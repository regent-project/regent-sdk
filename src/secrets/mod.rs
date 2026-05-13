pub mod local;
pub mod remote;

#[cfg(feature = "aws-secretsmanager")]
use aws_config::SdkConfig as AwsConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

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
    provider: Option<String>,
}

impl SecretReference {
    pub fn from(sec_ref: &str, provider: Option<String>) -> Self {
        Self {
            sec_ref: sec_ref.to_string(),
            provider,
        }
    }

    pub fn sec_ref(&self) -> &str {
        &self.sec_ref
    }

    pub fn provider(&self) -> &Option<String> {
        &self.provider
    }
}

pub struct SecretProvidersPoolBuilder {
    providers: HashMap<String, SecretProvider>,
    default_provider: Option<String>,
}

impl SecretProvidersPoolBuilder {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: None,
        }
    }

    pub fn add_provider(mut self, name: &str, provider: SecretProvider) -> Self {
        if let Some(_old_secret_provider) = self.providers.insert(name.to_string(), provider) {
            warn!(
                "You just overrided a secret provider in the pool, also identified by the name {}",
                name
            );
        }
        self
    }

    pub fn add_default_provider(mut self, name: &str, provider: SecretProvider) -> Self {
        if let Some(_old_secret_provider) = self.providers.insert(name.to_string(), provider) {
            warn!(
                "You just overrided a secret provider in the pool, also identified by the name {}",
                name
            );
        }
        self.default_provider = Some(name.to_string());
        self
    }

    pub fn set_default(mut self, name: String) -> Self {
        self.default_provider = Some(name);
        self
    }

    pub fn build(self) -> Result<SecretProvidersPool, RegentError> {
        match self.default_provider {
            Some(default_provider_name) => match self.providers.get(&default_provider_name) {
                Some(_secrets_provider) => Ok(SecretProvidersPool {
                    providers: self.providers,
                    default_provider: default_provider_name,
                }),
                None => {
                    error!(
                        "Default secrets provider ({}) is not set",
                        default_provider_name
                    );
                    return Err(RegentError::SecretsIssue(format!(
                        "Default secrets provider ({}) is not set",
                        default_provider_name
                    )));
                }
            },
            None => {
                error!("No default secrets provider set");
                return Err(RegentError::SecretsIssue(
                    "No default secrets provider set".to_string(),
                ));
            }
        }
    }
}

#[derive(Clone)]
pub struct SecretProvidersPool {
    providers: HashMap<String, SecretProvider>,
    default_provider: String,
}

impl SecretProvidersPool {
    pub fn from(name: &str, secret_provider: SecretProvider) -> Self {
        let mut providers: HashMap<String, SecretProvider> = HashMap::new();
        providers.insert(name.to_string(), secret_provider);
        Self {
            providers,
            default_provider: name.to_string(),
        }
    }

    pub async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &SecretReference,
    ) -> Result<Secret<T>, RegentError> {
        let provider = match secret_reference.provider() {
            Some(user_defined_provider) => user_defined_provider,
            None => &self.default_provider,
        };

        match self.providers.get(provider) {
            Some(secret_provider) => {
                secret_provider
                    .get_secret_typed(secret_reference.sec_ref())
                    .await
            }
            None => {
                error!(
                    "Default secrets provider {} not found. Was the SecretProvidersPoolBuilder type used to build this SecretProvidersPool ?",
                    self.default_provider
                );
                return Err(RegentError::SecretsIssue(format!(
                    "Default secrets provider {} not found. Was the SecretProvidersPoolBuilder type used to build this SecretProvidersPool ?",
                    self.default_provider
                )));
            }
        }
    }

    pub async fn get_secret_raw(
        &self,
        secret_reference: &SecretReference,
    ) -> Result<Secret<String>, RegentError> {
        let provider = match secret_reference.provider() {
            Some(user_defined_provider) => user_defined_provider,
            None => &self.default_provider,
        };

        match self.providers.get(provider) {
            Some(secret_provider) => {
                secret_provider
                    .get_secret_raw(secret_reference.sec_ref())
                    .await
            }
            None => {
                error!(
                    "Default secrets provider {} not found. Was the SecretProvidersPoolBuilder type used to build this SecretProvidersPool ?",
                    self.default_provider
                );
                return Err(RegentError::SecretsIssue(format!(
                    "Default secrets provider {} not found. Was the SecretProvidersPoolBuilder type used to build this SecretProvidersPool ?",
                    self.default_provider
                )));
            }
        }
    }
}
