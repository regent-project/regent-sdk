pub mod local;
pub mod remote;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::error::Error;
use crate::secrets::local::environment_variables::EnvVarSecretProvider;
use crate::secrets::local::files::FilesSecretProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretsManagementSolution {
    Files(FilesSecretProvider),
    EnvironmentVariable(EnvVarSecretProvider),
    // AwsSecretsManager,
    // GcpSecretManager,
    // DelineaSecretServer,
    // HashicorpVault,
}

impl SecretsManagementSolution {
    pub fn get_secret<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, Error> {
        match self {
            SecretsManagementSolution::Files(secret_provider) => {
                secret_provider.get_secret(secret_reference)
            }

            SecretsManagementSolution::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret(secret_reference)
            } // SecretsManagementSolution::AwsSecretsManager => {}
              // SecretsManagementSolution::GcpSecretManager => {}
              // SecretsManagementSolution::DelineaSecretServer => {}
              // SecretsManagementSolution::HashicorpVault => {}
        }
    }
}

// Each SecretsManagementSolution variant's nested type must implement this trait
pub trait SecretProvider {
    fn connect() -> Result<(), Error>;
    fn get_secret<T: DeserializeOwned>(&self, secret_reference: &str) -> Result<Secret<T>, Error>;
}

// Wrapper type which holds secrets content and helps to avoid leaking secrets (usual or debug logging in general...)
pub struct Secret<T> {
    inner: T,
}

impl<T> Secret<T> {
    pub fn from(inner: T) -> Self {
        Self { inner }
    }

    pub fn inner(self) -> T {
        self.inner
    }
}
