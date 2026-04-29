use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ExpectedState;
use crate::error::Error;
use crate::hosts::handlers::ConnectionMethod;
use crate::hosts::managed_host::ManagedHost;
use crate::hosts::managed_host::ManagedHostBuilder;
use crate::secrets::SecretProvider;
use crate::state::compliance::HostStatus;
use crate::state::compliance::ManagedHostStatus;

#[allow(unused)]
use tracing::{Level, debug, error, info, span, trace, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct InventoryBuilder {
    name: Option<String>,
    hosts: Vec<ManagedHostBuilder>,
    default_connection_method: Option<ConnectionMethod>,
    global_vars: Option<HashMap<String, String>>,
}

impl InventoryBuilder {
    pub fn from_raw_yaml(raw_yaml: &str) -> Result<Self, Error> {
        match yaml_serde::from_str::<Self>(raw_yaml) {
            Ok(inventory_builder) => {
                debug!("Successfully parsed YAML inventory");
                Ok(inventory_builder)
            }
            Err(error_detail) => {
                error!("Failed to parse YAML inventory: {:?}", error_detail);
                Err(Error::FailureToParseContent(format!("{:?}", error_detail)))
            }
        }
    }

    pub fn from_raw_json(raw_json: &str) -> Result<Self, Error> {
        match serde_json::from_str::<Self>(raw_json) {
            Ok(inventory_builder) => {
                debug!("Successfully parsed JSON inventory");
                Ok(inventory_builder)
            }
            Err(error_detail) => {
                error!("Failed to parse JSON inventory: {:?}", error_detail);
                Err(Error::FailureToParseContent(format!("{:?}", error_detail)))
            }
        }
    }

    pub fn build(self) -> Result<Inventory, Error> {
        let mut final_hosts: HashMap<String, ManagedHostBuilder> = HashMap::new();
        let number_of_hosts = self.hosts.len();
        let inventory_name = self.name.unwrap_or(format!("{} hosts", number_of_hosts));

        let span = span!(Level::INFO, "inventory_building", name = inventory_name);
        let _enter = span.enter();

        for mut host in self.hosts {
            // Vars merging and overloading
            if let Some(global_vars) = &self.global_vars {
                let mut final_host_vars: HashMap<String, String> = global_vars.clone();

                if let Some(host_vars) = &host.host_vars {
                    final_host_vars.extend(host_vars.clone());
                }

                host.set_host_vars(Some(final_host_vars));
            }

            // ConnectionMethod overloading
            if let None = host.host_connection_method {
                match &self.default_connection_method {
                    Some(connection_method) => {
                        host.set_connection_method(connection_method.clone());
                    }
                    None => {
                        // In this branch, neither host ConnectionMethod nor global ConnectionMethod are set. We don't know how to connect to this host. Abord
                        let error_msg = format!(
                            "No HostConnectionMethod or GlobalConnectionMethod set. At least one of them must be set.",
                        );
                        error!(name = host.id, "{}", error_msg);
                        return Err(Error::WrongInitialization(error_msg));
                    }
                }
            }

            // When saving ManageHostBuilder for final result, check unicity of hosts by their id
            if let Some(old_managed_host_builder) = final_hosts.insert(host.id.to_string(), host) {
                error!(name = old_managed_host_builder.id, "duplicate host id");
                return Err(Error::WrongInitialization(format!(
                    "duplicate host id : {}",
                    old_managed_host_builder.id
                )));
            }
        }

        info!(target: "inventory","Inventory built with {} host(s)", final_hosts.len());
        Ok(Inventory::from(inventory_name, final_hosts))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    name: String,
    hosts: HashMap<String, ManagedHostBuilder>,
}

impl Inventory {
    pub fn from(name: String, hosts: HashMap<String, ManagedHostBuilder>) -> Self {
        Self { name, hosts }
    }

    pub fn init_connections(
        &mut self,
        secret_provider: &Option<SecretProvider>,
    ) -> Result<LivingInventory, Error> {
        let span = span!(Level::INFO, "inventory_connections", name = self.name);
        let _enter = span.enter();

        let mut managed_hosts: HashMap<String, ManagedHost> = HashMap::new();

        for (host_id, managed_host_builder) in self.hosts.clone() {
            // Try to build a ManagedHost out of a ManagedHostBuilder (implies fetching secrets when needed)
            match managed_host_builder.build(secret_provider) {
                Ok(mut managed_host) => {
                    let host_span = span!(Level::DEBUG, "host_connection", host_id);
                    let _host_enter = host_span.enter();

                    match managed_host.connect() {
                        Ok(()) => {
                            debug!(host_id, "Successfully connected to host");
                            managed_hosts.insert(host_id, managed_host);
                        }
                        Err(connection_error) => {
                            error!(
                                host_id,
                                "Failed to connect to host : {:?}", connection_error
                            );
                            return Err(connection_error);
                        }
                    }
                }
                Err(detail) => {
                    error!(host_id, "Failed to build host: {:?}", detail);
                    return Err(detail);
                }
            }
        }

        info!(target: "inventory","Successfully connected to {} host(s)", managed_hosts.len());
        Ok(LivingInventory::from(self.name.clone(), managed_hosts))
    }
}

pub struct LivingInventory {
    name: String,
    hosts: HashMap<String, ManagedHost>,
}

impl LivingInventory {
    pub fn from(name: String, hosts: HashMap<String, ManagedHost>) -> Self {
        Self { name, hosts }
    }

    pub fn add_var(&mut self, key: String, value: String) {
        let span = span!(Level::DEBUG, "living_inventory_add_var");
        let _enter = span.enter();

        debug!(key, value, "Adding variable");

        let _ = self.hosts.par_iter_mut().map(|(host_id, managed_host)| {
            trace!(host_id, key, value, "Adding variable to host");
            managed_host.add_var(key.clone(), value.clone())
        });

        info!(key, "Added variable to all hosts");
    }

    pub fn collect_properties(&mut self) -> Result<(), Error> {
        let span = span!(Level::INFO, "living_inventory_collect_properties");
        let _enter = span.enter();

        info!(
            "Starting property collection for {} hosts",
            self.hosts.len()
        );

        for result in self
            .hosts
            .par_iter_mut()
            .map(|(host_id, managed_host)| {
                let host_span = span!(Level::DEBUG, "collect_properties_host", host_id);
                let _host_enter = host_span.enter();

                debug!("Collecting properties");
                managed_host.collect_properties()
            })
            .collect::<Vec<Result<(), Error>>>()
        {
            if let Err(details) = result {
                error!("Failed to collect properties: {:?}", details);
                return Err(details);
            }
        }

        info!("Successfully collected properties from all hosts");
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), Error> {
        let span = span!(Level::INFO, "inventory_disconnect");
        let _enter = span.enter();

        info!("Disconnecting from {} hosts", self.hosts.len());

        for result in self
            .hosts
            .par_iter_mut()
            .map(|(host_id, managed_host)| {
                let host_span = span!(Level::DEBUG, "disconnect_host", host_id);
                let _host_enter = host_span.enter();

                debug!("Disconnecting from host {}", host_id);
                managed_host.disconnect()
            })
            .collect::<Vec<Result<(), Error>>>()
        {
            if let Err(details) = result {
                error!("Failed to disconnect host: {:?}", details);
                return Err(details);
            }
        }

        info!("Successfully disconnected from all hosts");
        Ok(())
    }

    pub fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<HashMap<String, ManagedHostStatus>, Error> {
        let span = span!(Level::INFO, "inventory");
        let _enter = span.enter();

        info!("Assessing compliance for {} hosts", self.hosts.len());

        let results: Result<Vec<_>, _> = self
            .hosts
            .par_iter_mut()
            .map(|(host_id, managed_host)| {
                let host_span = span!(Level::DEBUG, "host", host_id);
                let _host_enter = host_span.enter();

                debug!(name = host_id, "Assessing compliance");
                match managed_host.assess_compliance(expected_state, optional_secret_provider) {
                    Ok(managed_host_status) => {
                        debug!("Compliance assessment complete");
                        Ok((host_id.to_string(), managed_host_status))
                    }
                    Err(details) => {
                        error!("Failed to assess compliance : {:?}", details);
                        Err(details)
                    }
                }
            })
            .collect();

        let results = results?;
        let results_map: HashMap<String, ManagedHostStatus> = results.into_iter().collect();

        info!(
            "Completed compliance assessment for {} hosts",
            results_map.len()
        );
        Ok(results_map)
    }

    pub fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<HashMap<String, ManagedHostStatus>, Error> {
        let job_span = span!(Level::INFO, "job", inv = self.name, goal = "enforcement");
        let _enter = job_span.enter();

        debug!("Starting");

        let results: Result<Vec<_>, _> = self
            .hosts
            .par_iter_mut()
            .map(|(host_id, managed_host)| {
                let host_span = span!(parent: &job_span, Level::INFO, "host", id = host_id);
                let _host_enter = host_span.enter();

                info!(target: "run",
                    "Starting to enforce compliance (described by {} attribute(s))",
                    expected_state.attributes.len()
                );
                match managed_host.reach_compliance(expected_state, optional_secret_provider) {
                    Ok(managed_host_status) => {
                        match managed_host_status.state {
                            HostStatus::AlreadyCompliant => {
                                info!(target: "run","Already compliant");
                            }
                            HostStatus::NotCompliant => {
                                warn!("Not compliant");
                            }
                            HostStatus::ReachComplianceSuccess => {
                                info!(target: "run","Compliance reached")
                            }
                            HostStatus::ReachComplianceFailed => {
                                warn!("Failed to reach compliance")
                            }
                        }
                        Ok((host_id.to_string(), managed_host_status))
                    }
                    Err(details) => {
                        warn!("Failed to reach compliance");
                        Err(details)
                    }
                }
            })
            .collect();

        let results = results?;
        let results_map: HashMap<String, ManagedHostStatus> = results.into_iter().collect();

        info!(target: "run","All hosts handled");
        Ok(results_map)
    }
}
