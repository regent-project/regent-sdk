use nanoid::nanoid;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::ExpectedState;
use crate::error::RegentError;
use crate::hosts::handlers::ConnectionMethod;
use crate::hosts::managed_host::ManagedHost;
use crate::hosts::managed_host::ManagedHostBuilder;
use crate::secrets::SecretProvider;
use crate::secrets::SecretProvidersPool;
use crate::state::compliance::HostStatus;
use crate::state::compliance::ManagedHostStatus;

#[allow(unused)]
use tracing::{Level, debug, error, info, span, trace, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
struct InventoryBuilder {
    name: Option<String>,
    hosts: Vec<ManagedHostBuilder>,
    default_connection_method: Option<ConnectionMethod>,
    global_vars: Option<HashMap<String, String>>,
}

impl InventoryBuilder {
    pub fn from_raw_yaml(raw_yaml: &str) -> Result<Inventory, RegentError> {
        match yaml_serde::from_str::<Self>(raw_yaml) {
            Ok(inventory_builder) => {
                debug!("Successfully parsed YAML inventory");
                inventory_builder.build()
            }
            Err(details) => {
                error!("Failed to parse YAML inventory: {:?}", details);
                Err(RegentError::FailureToParseContent(format!("{:?}", details)))
            }
        }
    }

    pub fn from_raw_json(raw_json: &str) -> Result<Inventory, RegentError> {
        match serde_json::from_str::<Self>(raw_json) {
            Ok(inventory_builder) => {
                debug!("Successfully parsed JSON inventory");
                inventory_builder.build()
            }
            Err(details) => {
                error!("Failed to parse JSON inventory: {:?}", details);
                Err(RegentError::FailureToParseContent(format!("{:?}", details)))
            }
        }
    }

    pub fn build(self) -> Result<Inventory, RegentError> {
        let mut final_hosts: HashMap<String, ManagedHostBuilder> = HashMap::new();
        let inventory_name = match self.name {
            Some(name_value) => name_value,
            None => nanoid!(
                12,
                &[
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
                ]
            ),
        };

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
                        return Err(RegentError::WrongInitialization(error_msg));
                    }
                }
            }

            // When saving ManageHostBuilder for final result, check unicity of hosts by their id
            if let Some(old_managed_host_builder) = final_hosts.insert(host.id.to_string(), host) {
                error!(name = old_managed_host_builder.id, "duplicate host id");
                return Err(RegentError::WrongInitialization(format!(
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
    hosts: HashMap<String, ManagedHostBuilder>, // HostId -> ManagedHostBuilder
}

impl Inventory {
    pub fn from(name: String, hosts: HashMap<String, ManagedHostBuilder>) -> Self {
        Self { name, hosts }
    }

    pub fn from_raw_yaml(raw_yaml: &str) -> Result<Inventory, RegentError> {
        InventoryBuilder::from_raw_yaml(raw_yaml)
    }

    pub fn from_raw_json(raw_json: &str) -> Result<Inventory, RegentError> {
        InventoryBuilder::from_raw_json(raw_json)
    }

    pub async fn init(
        &mut self,
        optional_secret_provider: Option<SecretProvidersPool>,
    ) -> Result<LivingInventory, RegentError> {
        let span = span!(Level::INFO, "inventory_init", name = self.name);
        let _enter = span.enter();

        let mut managed_hosts: HashMap<String, ManagedHost> = HashMap::new();

        for (host_id, managed_host_builder) in self.hosts.clone() {
            // Try to build a ManagedHost out of a ManagedHostBuilder (implies fetching secrets when needed)
            match managed_host_builder
                .build(optional_secret_provider.clone())
                .await
            {
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
    hosts: HashMap<String, Arc<Mutex<ManagedHost>>>, // HostId -> Arc<Mutex<ManagedHost>>
}

impl LivingInventory {
    pub fn from(name: String, hosts: HashMap<String, ManagedHost>) -> Self {
        let mut new_hosts: HashMap<String, Arc<Mutex<ManagedHost>>> = HashMap::new();
        for (host_id, managed_host) in hosts {
            new_hosts.insert(host_id, Arc::new(Mutex::new(managed_host)));
        }
        Self {
            name,
            hosts: new_hosts,
        }
    }

    pub async fn add_var(&mut self, key: String, value: String) {
        let span = span!(Level::DEBUG, "living_inventory_add_var");
        let _enter = span.enter();

        debug!(key, value, "Adding variable");

        let _ = self.hosts.par_iter_mut().map(|(host_id, managed_host)| {
            trace!(host_id, key, value, "Adding variable to host");
            async {
                let mut host = managed_host.lock().await;
                host.add_var(key.clone(), value.clone())
            }
        });

        info!(key, "Added variable to all hosts");
    }

    pub async fn collect_properties(&mut self) -> Result<(), RegentError> {
        let span = span!(Level::INFO, "living_inventory_collect_properties");
        let _enter = span.enter();
        info!(
            "Starting property collection for {} hosts",
            self.hosts.len()
        );
        let mut join_set = JoinSet::new();
        for (host_id, managed_host) in self.hosts.clone() {
            join_set.spawn(async move {
                let host_span = span!(Level::DEBUG, "collect_properties_host", host_id);
                let _host_enter = host_span.enter();

                debug!("Collecting properties");
                match managed_host.lock().await.collect_properties() {
                    Ok(()) => {
                        info!("Host properties collected");
                    }
                    Err(details) => {
                        error!("Failed to collect properties: {:?}", details);
                    }
                }
            });
        }

        join_set.join_all().await;

        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), RegentError> {
        let span = span!(Level::INFO, "inventory_disconnect");
        let _enter = span.enter();

        info!("Disconnecting from {} hosts", self.hosts.len());

        let mut join_set = JoinSet::new();

        for (host_id, managed_host) in self.hosts.clone() {
            join_set.spawn(async move {
                let host_span = span!(Level::DEBUG, "disconnect_host", host_id);
                let _host_enter = host_span.enter();

                debug!("Disconnecting from host {}", host_id);
                match managed_host.lock().await.disconnect() {
                    Ok(()) => {
                        info!("Host properties collected");
                    }
                    Err(details) => {
                        error!("Failed to disconnect host: {:?}", details);
                    }
                }
            });
        }

        join_set.join_all().await;

        Ok(())
    }

    pub async fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<HashMap<String, ManagedHostStatus>, RegentError> {
        let job_span = span!(Level::INFO, "job", id = self.name, goal = "assess");
        let _enter = job_span.enter();

        info!("Assessing compliance for {} hosts", self.hosts.len());

        let mut join_set = JoinSet::new();
        let results: Arc<Mutex<Vec<(String, ManagedHostStatus)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // TODO : make this run concurrently by spawning tasks
        for (host_id, managed_host) in self.hosts.clone() {
            join_set.spawn({
                let expected_state_clone = expected_state.clone();
                let results_clone = results.clone();
                async move {
                    let host_span = span!(Level::DEBUG, "host", host_id);
                    let _host_enter = host_span.enter();

                    debug!(name = host_id, "Assessing compliance");
                    match managed_host
                        .lock()
                        .await
                        .assess_compliance(&expected_state_clone)
                        .await
                    {
                        Ok(managed_host_status) => {
                            debug!("Compliance assessment complete");
                            results_clone
                                .lock()
                                .await
                                .push((host_id.to_string(), managed_host_status));
                        }
                        Err(details) => {
                            error!("Failed to assess compliance : {:?}", details);
                        }
                    }
                }
            });
        }

        join_set.join_all().await;

        let results_map: HashMap<String, ManagedHostStatus> =
            results.lock().await.clone().into_iter().collect();

        info!(
            "Completed compliance assessment for {} hosts",
            results_map.len()
        );

        Ok(results_map)
    }

    pub async fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<HashMap<String, ManagedHostStatus>, RegentError> {
        let job_span = span!(Level::INFO, "job", id = self.name, goal = "enforce");
        let _enter = job_span.enter();

        debug!("Starting");

        let mut join_set = JoinSet::new();
        let results: Arc<Mutex<Vec<(String, ManagedHostStatus)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // TODO : make this run concurrently by spawning tasks
        for (host_id, managed_host) in self.hosts.clone() {
            join_set.spawn({
                let expected_state_clone = expected_state.clone();
                let results_clone = results.clone();
                let job_span_clone = job_span.clone();
                async move {
                    let host_span =
                        span!(parent: &job_span_clone, Level::INFO, "host", id = host_id);
                    let _host_enter = host_span.enter();

                    info!(target: "run",
                        "Starting to enforce compliance (described by {} attribute(s))",
                        expected_state_clone.attributes.len()
                    );
                    match managed_host
                        .lock()
                        .await
                        .reach_compliance(&expected_state_clone)
                        .await
                    {
                        Ok(managed_host_status) => {
                            match managed_host_status.state {
                                HostStatus::AlreadyCompliant => {
                                    info!(target: "run","Already compliant");
                                }
                                HostStatus::NotCompliant => {
                                    warn!("Not compliant");
                                }
                                HostStatus::ReachComplianceSuccess => {
                                    info!(target: "run","Compliance reached");
                                }
                                HostStatus::ReachComplianceFailed => {
                                    warn!("Failed to reach compliance");
                                }
                            }
                            results_clone
                                .lock()
                                .await
                                .push((host_id.to_string(), managed_host_status));
                        }
                        Err(details) => {
                            warn!("Failed to reach compliance : {}", details);
                        }
                    }
                }
            });
        }

        join_set.join_all().await;
        let results_map: HashMap<String, ManagedHostStatus> =
            results.lock().await.clone().into_iter().collect();

        info!(target: "run","All hosts handled");
        Ok(results_map)
    }
}
