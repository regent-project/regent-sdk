use serde::{Serialize, Deserialize};

use crate::error::Error;
use crate::secrets::SecretProvider;
use crate::hosts::managed_host::ManagedHost;
use crate::hosts::managed_host::ManagedHostBuilder;


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InventoryBuilder {
    hosts: Vec<ManagedHostBuilder>
}

impl InventoryBuilder {
    pub fn build(self, secret_provider: &Option<SecretProvider>) -> Result<Inventory, Error> {
        let mut hosts: Vec<ManagedHost> = Vec::new();

        for host in self.hosts {
            match host.build(secret_provider) {
                Ok(managed_host) => {
                    hosts.push(managed_host);
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
    hosts: Vec<ManagedHost>
}

impl Inventory {
    pub fn from(hosts: Vec<ManagedHost>) -> Self {
        Inventory { hosts }
    }
}
