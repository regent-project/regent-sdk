use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ExpectedState;
use crate::error::Error;
use crate::hosts::handlers::ConnectionMethod;
use crate::hosts::managed_host::ManagedHost;
use crate::hosts::managed_host::ManagedHostBuilder;
use crate::secrets::SecretProvider;
use crate::state::compliance::ManagedHostStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InventoryBuilder {
    hosts: Vec<ManagedHostBuilder>,
    connection_method: Option<ConnectionMethod>,
    // vars: Option<HashMap<String, String>>,
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

    pub fn build(self, secret_provider: &Option<SecretProvider>) -> Result<Inventory, Error> {
        let mut hosts: HashMap<String, ManagedHost> = HashMap::new();

        for mut host in self.hosts {
            if let None = host.connection_method {
                if let Some(connection_method) = &self.connection_method {
                    host.set_connection_method(connection_method.clone());
                }
            }

            match host.build(secret_provider) {
                Ok(managed_host) => {
                    if let Some(old_managed_host) =
                        hosts.insert(managed_host.id().to_string(), managed_host)
                    {
                        return Err(Error::WrongInitialization(format!(
                            "duplicate host id : {}",
                            old_managed_host.id()
                        )));
                    }
                }
                Err(detail) => {
                    return Err(detail);
                }
            }
        }

        Ok(Inventory::from(hosts))
    }
}

pub struct Inventory {
    hosts: HashMap<String, ManagedHost>,
}

impl Inventory {
    pub fn from(hosts: HashMap<String, ManagedHost>) -> Self {
        Inventory { hosts }
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

    pub fn connect(&mut self) -> Result<(), Error> {
        for result in self
            .hosts
            .par_iter_mut()
            .map(|(_managed_host_id, managed_host)| managed_host.connect())
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
    ) -> Result<HashMap<String, ManagedHostStatus>, Error> {
        self.hosts
            .par_iter_mut()
            .map(|(managed_host_id, managed_host)| {
                match managed_host.assess_compliance(expected_state) {
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
    ) -> Result<HashMap<String, ManagedHostStatus>, Error> {
        self.hosts
            .par_iter_mut()
            .map(|(managed_host_id, managed_host)| {
                match managed_host.reach_compliance(expected_state) {
                    Ok(managed_host_status) => {
                        Ok((managed_host_id.to_string(), managed_host_status))
                    }
                    Err(details) => Err(details),
                }
            })
            .collect()
    }
}
