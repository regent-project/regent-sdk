use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ExpectedState;
use crate::error::Error;
use crate::hosts::handlers::ConnectionMethod;
use crate::hosts::managed_host::ManagedHost;
use crate::hosts::managed_host::ManagedHostBuilder;
use crate::secrets::Secret;
use crate::secrets::SecretProvider;
use crate::state::compliance::ManagedHostStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct InventoryBuilder {
    hosts: Vec<ManagedHostBuilder>,
    default_connection_method: Option<ConnectionMethod>,
    global_vars: Option<HashMap<String, String>>,
}

impl InventoryBuilder {
    pub fn from_raw_yaml(raw_yaml: &str) -> Result<Self, Error> {
        match yaml_serde::from_str::<Self>(raw_yaml) {
            Ok(inventory_builder) => Ok(inventory_builder),
            Err(error_detail) => Err(Error::FailureToParseContent(format!("{:?}", error_detail))),
        }
    }

    pub fn from_raw_json(raw_json: &str) -> Result<Self, Error> {
        match serde_json::from_str::<Self>(raw_json) {
            Ok(inventory_builder) => Ok(inventory_builder),
            Err(error_detail) => Err(Error::FailureToParseContent(format!("{:?}", error_detail))),
        }
    }

    pub fn build(self) -> Result<Inventory, Error> {
        let mut final_hosts: HashMap<String, ManagedHostBuilder> = HashMap::new();

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
                        return Err(Error::WrongInitialization(format!(
                            "Host {} has no HostConnectionMethod set and GlobalConnectionMethod is not set either. At least one of them must be set.",
                            host.id
                        )));
                    }
                }
            }

            // When saving ManageHostBuilder for final result, check unicity of hosts by their id
            if let Some(old_managed_host_builder) = final_hosts.insert(host.id.to_string(), host) {
                return Err(Error::WrongInitialization(format!(
                    "duplicate host id : {}",
                    old_managed_host_builder.id
                )));
            }
        }

        Ok(Inventory::from(final_hosts))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    hosts: HashMap<String, ManagedHostBuilder>,
}

impl Inventory {
    pub fn from(hosts: HashMap<String, ManagedHostBuilder>) -> Self {
        Self { hosts }
    }

    pub fn init(
        &mut self,
        secret_provider: &Option<SecretProvider>,
    ) -> Result<LivingInventory, Error> {
        let mut managed_hosts: HashMap<String, ManagedHost> = HashMap::new();

        for (_host_id, managed_host_builder) in self.hosts.clone() {
            // Try to build a ManagedHost out of a ManagedHostBuilder (implies fetching secrets when needed)
            match managed_host_builder.build(secret_provider) {
                Ok(mut managed_host) => match managed_host.connect() {
                    Ok(()) => {
                        managed_hosts.insert(managed_host.id().to_string(), managed_host);
                    }
                    Err(connection_error) => {
                        return Err(connection_error);
                    }
                },
                Err(detail) => {
                    return Err(detail);
                }
            }
        }

        Ok(LivingInventory::from(managed_hosts))
    }
}

pub struct LivingInventory {
    hosts: HashMap<String, ManagedHost>,
}

impl LivingInventory {
    pub fn from(hosts: HashMap<String, ManagedHost>) -> Self {
        Self { hosts }
    }

    pub fn add_var(&mut self, key: String, value: String) {
        let _ = self
            .hosts
            .par_iter_mut()
            .map(|(_managed_host_id, managed_host)| {
                managed_host.add_var(key.clone(), value.clone())
            });
    }

    pub fn collect_properties(&mut self) -> Result<(), Error> {
        for result in self
            .hosts
            .par_iter_mut()
            .map(|(_managed_host_id, managed_host)| managed_host.collect_properties())
            .collect::<Vec<Result<(), Error>>>()
        {
            if let Err(details) = result {
                return Err(details);
            }
        }

        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), Error> {
        for result in self
            .hosts
            .par_iter_mut()
            .map(|(_managed_host_id, managed_host)| managed_host.disconnect())
            .collect::<Vec<Result<(), Error>>>()
        {
            if let Err(details) = result {
                return Err(details);
            }
        }

        Ok(())
    }

    pub fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<HashMap<String, ManagedHostStatus>, Error> {
        let mut secrets: HashMap<String, Secret<String>> = HashMap::new();

        if let Some(secrets_references) = &expected_state.secrets_references {
            match optional_secret_provider {
                Some(secret_provider) => {
                    for (secret_alias, secret_reference) in secrets_references {
                        match secret_provider.get_secret_raw(secret_reference) {
                            Ok(secret) => {
                                secrets.insert(
                                    secret_alias.to_string(),
                                    Secret::from(
                                        secret_reference,
                                        secret
                                            .inner()
                                            .chars()
                                            .filter(|c| c.is_ascii())
                                            .collect::<String>()
                                            .trim()
                                            .to_string(),
                                    ),
                                );
                            }
                            Err(error_detail) => {
                                return Err(Error::FailedToGetSecret(format!(
                                    "{:?}",
                                    error_detail
                                )));
                            }
                        }
                    }
                }
                None => {
                    return Err(Error::WrongInitialization(
                        "Secrets are referenced but no SecretProvider to retrieve them from"
                            .to_string(),
                    ));
                }
            }
        }

        self.hosts
            .par_iter_mut()
            .map(|(managed_host_id, managed_host)| {
                managed_host.provision_secrets(&secrets);

                match managed_host.assess_compliance(expected_state, optional_secret_provider) {
                    Ok(managed_host_status) => {
                        Ok((managed_host_id.to_string(), managed_host_status))
                    }
                    Err(details) => Err(details),
                }
            })
            .collect()
    }

    pub fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<HashMap<String, ManagedHostStatus>, Error> {
        let mut secrets: HashMap<String, Secret<String>> = HashMap::new();

        if let Some(secrets_references) = &expected_state.secrets_references {
            match optional_secret_provider {
                Some(secret_provider) => {
                    for (secret_alias, secret_reference) in secrets_references {
                        match secret_provider.get_secret_raw(secret_reference) {
                            Ok(secret) => {
                                secrets.insert(
                                    secret_alias.to_string(),
                                    Secret::from(
                                        secret_reference,
                                        secret
                                            .inner()
                                            .chars()
                                            .filter(|c| c.is_ascii())
                                            .collect::<String>()
                                            .trim()
                                            .to_string(),
                                    ),
                                );
                            }
                            Err(error_detail) => {
                                return Err(Error::FailedToGetSecret(format!(
                                    "{:?}",
                                    error_detail
                                )));
                            }
                        }
                    }
                }
                None => {
                    return Err(Error::WrongInitialization(
                        "Secrets are referenced but no SecretProvider to retrieve them from"
                            .to_string(),
                    ));
                }
            }
        }

        self.hosts
            .par_iter_mut()
            .map(|(managed_host_id, managed_host)| {
                managed_host.provision_secrets(&secrets);

                match managed_host.reach_compliance(expected_state, optional_secret_provider) {
                    Ok(managed_host_status) => {
                        Ok((managed_host_id.to_string(), managed_host_status))
                    }
                    Err(details) => Err(details),
                }
            })
            .collect()
    }
}
