pub mod local;
pub mod remote;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::error::Error;
use crate::secrets::local::environment_variables::EnvVarSecretProvider;
use crate::secrets::local::files::FilesSecretProvider;

#[derive(Clone)]
pub enum SecretProvider {
    Files(FilesSecretProvider),
    EnvironmentVariable(EnvVarSecretProvider),
    // AwsSecretsManager,
    // GcpSecretManager,
    // DelineaSecretServer,
    // HashicorpVault,
}

impl SecretProvider {
    pub fn files() -> Self {
        Self::Files(FilesSecretProvider::new())
    }

    pub fn env_var() -> Self {
        Self::EnvironmentVariable(EnvVarSecretProvider::new())
    }

    pub fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, Error> {
        match self {
            SecretProvider::Files(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference)
            }
            SecretProvider::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference)
            } // SecretProvider::AwsSecretsManager => {}
              // SecretProvider::GcpSecretManager => {}
              // SecretProvider::DelineaSecretServer => {}
              // SecretProvider::HashicorpVault => {}
        }
    }

    pub fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, Error> {
        match self {
            SecretProvider::Files(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference)
            }
            SecretProvider::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference)
            } // SecretProvider::AwsSecretsManager => {}
              // SecretProvider::GcpSecretManager => {}
              // SecretProvider::DelineaSecretServer => {}
              // SecretProvider::HashicorpVault => {}
        }
    }
}

// Each SecretProvider variant's nested type must implement this trait
pub trait SecretProvidingSolution {
    fn connect() -> Result<(), Error>;
    fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, Error>;
    fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, Error>;
}

// Wrapper type which holds secrets content and helps to avoid leaking secrets (usual or debug logging in general...)
#[derive(Clone)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    sec_ref: String,
}

impl SecretReference {
    pub fn from(sec_ref: &str) -> Self {
        Self {
            sec_ref: sec_ref.to_string(),
        }
    }

    pub fn sec_ref(&self) -> &str {
        &self.sec_ref
    }
}
