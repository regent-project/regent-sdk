pub mod local;
pub mod remote;

#[cfg(feature = "aws-secretsmanager")]
use aws_config::SdkConfig as AwsConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::error::RegentError;
use crate::secrets::local::environment_variables::EnvVarSecretProvider;
use crate::secrets::local::files::FilesSecretProvider;
#[cfg(feature = "aws-secretsmanager")]
use crate::secrets::remote::aws_secrets_manager::AwsSecretsManagerProvider;
use crate::secrets::remote::gcp_secret_manager::GcpSecretProvider;

#[derive(Clone)]
pub enum SecretProvider {
    Files(FilesSecretProvider),
    EnvironmentVariable(EnvVarSecretProvider),
    #[cfg(feature = "aws-secretsmanager")]
    AwsSecretsManager(AwsSecretsManagerProvider),
    #[cfg(feature = "gcp-secretmanager")]
    GcpSecretManager(GcpSecretProvider),
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

    #[cfg(feature = "aws-secretsmanager")]
    pub fn aws_secretsmanager(aws_config: AwsConfig) -> Self {
        Self::AwsSecretsManager(AwsSecretsManagerProvider::from(aws_config))
    }

    #[cfg(feature = "gcp-secretmanager")]
    pub async fn gcp_secretmanager() -> Result<Self, RegentError> {
        match GcpSecretProvider::new().await {
            Ok(gcp_secret_provider) => Ok(Self::GcpSecretManager(gcp_secret_provider)),
            Err(details) => Err(RegentError::ProblemWithSecretsProvider(format!(
                "Failed to create a GCP SecretManager client : {}",
                details
            ))),
        }
    }

    pub async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError> {
        match self {
            SecretProvider::Files(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            }
            SecretProvider::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            }
            #[cfg(feature = "aws-secretsmanager")]
            SecretProvider::AwsSecretsManager(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            }
            #[cfg(feature = "gcp-secretmanager")]
            SecretProvider::GcpSecretManager(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            } // SecretProvider::DelineaSecretServer => {}
              // SecretProvider::HashicorpVault => {}
        }
    }

    pub async fn get_secret_raw(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<String>, RegentError> {
        match self {
            SecretProvider::Files(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            }
            SecretProvider::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            }
            #[cfg(feature = "aws-secretsmanager")]
            SecretProvider::AwsSecretsManager(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            }
            #[cfg(feature = "gcp-secretmanager")]
            SecretProvider::GcpSecretManager(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            } // SecretProvider::DelineaSecretServer => {}
              // SecretProvider::HashicorpVault => {}
        }
    }
}

// Each SecretProvider variant's nested type must implement this trait
pub trait SecretProvidingSolution {
    async fn connect(&mut self) -> Result<(), RegentError>;
    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;
    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError>;
}

pub trait AsyncSecretProvidingSolution {
    async fn connect(&mut self) -> Result<(), RegentError>;
    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;
    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError>;
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
