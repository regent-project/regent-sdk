pub mod local;
pub mod remote;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::error::RegentError;
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
    ) -> Result<Secret<T>, RegentError> {
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

    pub fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError> {
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
    fn connect() -> Result<(), RegentError>;
    fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;
    fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError>;
}

// Wrapper type which holds secrets content and helps to avoid leaking secrets (usual or debug logging in general...)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Secret<T> {
    sec_ref: String,
    inner: T,
}

impl<T> Debug for Secret<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("sec_ref", &self.sec_ref)
            .field("inner", &format_args!("<redacted>"))
            .finish()
    }
}

impl<T> Secret<T> {
    pub fn from(sec_ref: &str, inner: T) -> Self {
        Self {
            sec_ref: sec_ref.to_string(),
            inner,
        }
    }

    pub fn inner(self) -> T {
        self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
