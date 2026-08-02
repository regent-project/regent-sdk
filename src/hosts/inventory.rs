use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

        let span = span!(
            Level::INFO,
            "inventory_building",
            inventory = inventory_name
        );
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
        let span = span!(Level::INFO, "inventory_init", inventory = self.name);
        let _enter = span.enter();

        let mut set = JoinSet::new();

        for (host_id, managed_host_builder) in self.hosts.clone() {
            let optional_secret_provider_clone = optional_secret_provider.clone();
            set.spawn(async move {
                // Try to build a ManagedHost out of a ManagedHostBuilder (implies fetching secrets when needed)
                match managed_host_builder
                    .build(optional_secret_provider_clone)
                    .await
                {
                    Ok(mut managed_host) => {
                        let host_span = span!(Level::DEBUG, "host_connection", host_id);
                        let _host_enter = host_span.enter();

                        match managed_host.connect().await {
                            Ok(()) => {
                                debug!(host_id, "Successfully connected to host");
                                Ok(managed_host)
                            }
                            Err(connection_error) => {
                                error!(
                                    host_id,
                                    "Failed to connect to host : {:?}", connection_error
                                );
                                Err((managed_host.id().to_string(), connection_error))
                            }
                        }
                    }
                    Err(detail) => {
                        error!(host_id, "Failed to build host: {:?}", detail);
                        Err((host_id, detail))
                    }
                }
            });
        }

        let mut managed_hosts: HashMap<String, ManagedHost> = HashMap::new();
        let results = set.join_all().await;
        let mut failures = Vec::new();

        for result in results {
            match result {
                Ok(managed_host) => {
                    managed_hosts.insert(managed_host.id().to_string(), managed_host);
                }
                Err((host_id, error_details)) => {
                    failures.push(format!("{}: {}", host_id, error_details));
                    // TODO : add an "allowed-failure" mode here : some hosts init failed but we can go on with the ones who worked
                }
            }
        }

        if failures.is_empty() {
            info!(target: "inventory","Successfully connected to {} host(s)", managed_hosts.len());
            Ok(LivingInventory::from(self.name.clone(), managed_hosts))
        } else {
            Err(RegentError::ProblemWithHostConnection(format!(
                "Following hosts encountered problems while trying to init: {}",
                failures.join(", ")
            )))
        }
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

    // TODO : is it worth it to make this parallel through tokio tasks ?
    pub fn add_var(&mut self, key: String, value: String) {
        let span = span!(Level::DEBUG, "living_inventory_add_var");
        let _enter = span.enter();

        debug!(key, value, "Adding variable");

        let _ = self.hosts.iter_mut().map(|(host_id, managed_host)| {
            trace!(host_id, key, value, "Adding variable to host");
            managed_host.add_var(key.clone(), value.clone())
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

        let mut set = JoinSet::new();

        for (host_id, managed_host) in self.hosts.iter_mut() {
            let host_id = host_id.clone();
            let mut managed_host = managed_host.clone();
            set.spawn(async move {
                let host_span = span!(Level::DEBUG, "collect_properties_host", host_id);
                let _host_enter = host_span.enter();

                debug!("Collecting properties");
                (host_id, managed_host.collect_properties().await)
            });
        }

        let results = set.join_all().await;

        let failures: Vec<(String, RegentError)> = results
            .iter()
            .filter(|(_host_id, result)| result.is_err())
            .map(|(host_id, result)| (host_id.to_string(), result.clone().unwrap_err()))
            .collect();

        if failures.is_empty() {
            info!("Successfully collected properties from all hosts");
            Ok(())
        } else {
            error!("Failed to collect properties for {:?}", failures);
            return Err(RegentError::AnyOtherError(format!(
                "Failure to collect properties for {:?}",
                failures
            )));
        }
    }

    pub async fn disconnect(&mut self) -> Result<(), RegentError> {
        let span = span!(Level::INFO, "inventory_disconnect");
        let _enter = span.enter();

        info!("Disconnecting from {} hosts", self.hosts.len());

        // Take ownership of hosts to avoid borrowing issues
        let hosts = std::mem::take(&mut self.hosts);

        let mut set = JoinSet::new();

        for (host_id, mut managed_host) in hosts {
            // for (host_id, mut managed_host) in hosts.drain() {
            set.spawn(async move {
                let host_span = span!(Level::DEBUG, "disconnect_host", host_id);
                let _host_enter = host_span.enter();

                debug!("Disconnecting from host {}", host_id);
                match managed_host.disconnect().await {
                    Ok(()) => Ok(managed_host),
                    Err(error_details) => Err((managed_host, error_details)),
                }
            });
        }

        let results = set.join_all().await;

        let mut failures = Vec::new();

        for result in results {
            match result {
                Ok(managed_host) => {
                    self.hosts
                        .insert(managed_host.id().to_string(), managed_host);
                }
                Err((managed_host, error_details)) => {
                    failures.push(format!("{}: {}", managed_host.id(), error_details));
                    self.hosts
                        .insert(managed_host.id().to_string(), managed_host);
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(RegentError::ProblemWithHostConnection(format!(
                "Following hosts encountered problems while trying to disconnect: {}",
                failures.join(", ")
            )))
        }
    }

    pub async fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<HashMap<String, ManagedHostStatus>, RegentError> {
        let job_span = span!(Level::INFO, "job", inventory = self.name, goal = "assess");
        let _enter = job_span.enter();

        info!("Assessing compliance for {} hosts", self.hosts.len());

        // Take ownership of hosts to avoid borrowing issues
        let hosts = std::mem::take(&mut self.hosts);

        let mut set = JoinSet::new();

        for (host_id, mut managed_host) in hosts {
            let expected_state_clone = expected_state.clone();
            set.spawn(async move {
                let host_span = span!(Level::DEBUG, "host", host_id);
                let _host_enter = host_span.enter();

                debug!(name = host_id, "Assessing compliance");
                match managed_host.assess_compliance(&expected_state_clone).await {
                    Ok(managed_host_status) => {
                        debug!("Compliance assessment complete");
                        Ok((host_id.to_string(), managed_host_status))
                    }
                    Err(details) => {
                        error!("Failed to assess compliance : {:?}", details);
                        Err((host_id, details))
                    }
                }
            });
        }

        let results = set.join_all().await;
        let mut results_map = HashMap::new();
        let mut failures = Vec::new();

        for result in results {
            match result {
                Ok((host_id, managed_host_status)) => {
                    results_map.insert(host_id, managed_host_status);
                }
                Err((host_id, error_details)) => {
                    failures.push(format!("{}: {}", host_id, error_details));
                }
            }
        }

        if failures.is_empty() {
            info!(
                "Completed compliance assessment for {} hosts",
                results_map.len()
            );
            Ok(results_map)
        } else {
            Err(RegentError::ProblemWithHostConnection(format!(
                "Following hosts encountered problems while trying to assess compliance: {}",
                failures.join(", ")
            )))
        }
    }

    pub async fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<HashMap<String, ManagedHostStatus>, RegentError> {
        let job_span = span!(Level::INFO, "job", inventory = self.name, goal = "enforce");
        let _enter = job_span.enter();

        info!("Enforcing compliance for {} hosts", self.hosts.len());

        // Take ownership of hosts to avoid borrowing issues
        let hosts = std::mem::take(&mut self.hosts);

        let mut set = JoinSet::new();

        for (host_id, mut managed_host) in hosts {
            let expected_state_clone = expected_state.clone();
            set.spawn(async move {
                let host_span = span!(parent: None, Level::INFO, "host", id = host_id);
                let _host_enter = host_span.enter();

                info!(target: "run",
                    "Starting to enforce compliance (described by {} attribute(s))",
                    expected_state_clone.attributes.len()
                );
                match managed_host.reach_compliance(&expected_state_clone).await {
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
                                warn!("Failed to reach compliance");
                            }
                        }
                        Ok((managed_host, managed_host_status))
                    }
                    Err(details) => {
                        warn!("Failed to reach compliance");
                        Err((managed_host, details))
                    }
                }
            });
        }

        let results = set.join_all().await;
        let mut results_map = HashMap::new();
        let mut failures = Vec::new();

        for result in results {
            match result {
                Ok((managed_host, managed_host_status)) => {
                    let host_id = managed_host.id().to_string();
                    self.hosts.insert(host_id.clone(), managed_host);
                    results_map.insert(host_id, managed_host_status);
                }
                Err((managed_host, error_details)) => {
                    let host_id = managed_host.id().to_string();
                    failures.push(format!("{}: {}", host_id, error_details));
                    self.hosts.insert(host_id, managed_host);
                }
            }
        }

        if failures.is_empty() {
            info!(target: "run","All hosts handled");
            Ok(results_map)
        } else {
            Err(RegentError::ProblemWithHostConnection(format!(
                "Following hosts encountered problems while trying to reach compliance: {}",
                failures.join(", ")
            )))
        }
    }
}
