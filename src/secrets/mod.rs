use std::str::FromStr;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{error::Error, secrets::environment_variables::EnvVarSecretProvider};

pub mod environment_variables;
// pub mod files;
// pub mod aws_secrets_manager;
// pub mod gcp_secret_manager;
// pub mod delinea_secret_server;
// pub mod hashicorp_vault;
// pub mod infisical;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretsManagementSolution {
    Files,
    EnvironmentVariable(EnvVarSecretProvider),
    AwsSecretsManager,
    GcpSecretManager,
    DelineaSecretServer,
    HashicorpVault
}

// Each SecretsManagementSolution variant's nested type must implement this trait
pub trait SecretProvider {
    fn connect() -> Result<(), Error>;
    fn get_secret<T: FromStr>(secret_reference: String) -> Result<Secret<T>, Error>;
}


// Wrapper type which holds secrets content and helps to avoid leaking secrets (usual or debug logging in general...)
pub struct Secret<T> {
    inner: T
}

impl<T> Secret<T> {
    pub fn from(inner: T) -> Self {
        Self {
            inner
        }
    }
}