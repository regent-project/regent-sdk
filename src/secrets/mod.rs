//! Secret management
//!
//! This module provides comprehensive secret management capabilities for Regent SDK.
//! It supports multiple secret providers including local files, environment variables,
//! and cloud-based secret managers (AWS, GCP).
//!
//! ## Features
//!
//! - **Multiple Providers**: Files, environment variables, AWS Secrets Manager, GCP Secret Manager
//! - **Secret Pool**: Manage multiple providers with a unified interface
//! - **Typed Secrets**: Retrieve secrets as specific types (string, structs, etc.)
//! - **Builder Pattern**: Easy configuration of secret provider pools
//!
//! ## Quick Start
//!
//! ```no_run
//! use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
//!
//! // Create a pool with file-based secrets
//! let pool = SecretProvidersPoolBuilder::new()
//!     .add_default_provider("files", SecretProvider::files())
//!     .build()
//!     .unwrap();
//!
//! // Or use environment variables
//! let pool = SecretProvidersPool::from("env", SecretProvider::env_var());
//! ```

pub mod local;
pub mod remote;

#[cfg(feature = "aws-secretsmanager")]
use aws_config::SdkConfig as AwsConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::error::RegentError;
use crate::secrets::local::environment_variables::EnvVarSecretProvider;
use crate::secrets::local::files::FilesSecretProvider;
#[cfg(feature = "aws-secretsmanager")]
use crate::secrets::remote::aws_secrets_manager::AwsSecretsManagerProvider;
#[cfg(feature = "gcp-secretmanager")]
use crate::secrets::remote::gcp_secret_manager::GcpSecretProvider;

/// A cache for storing resolved secrets to ensure idempotency.
///
/// This cache stores secrets that have been retrieved from providers, ensuring
/// that the same secret value is used throughout a compliance operation,
/// even if the underlying secret is rotated during the operation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SecretCache {
    /// Map from secret reference to cached secret value
    cache: Arc<Mutex<HashMap<String, String>>>,
}

impl SecretCache {
    /// Create a new, empty secret cache.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Insert a secret into the cache.
    ///
    /// # Arguments
    /// * `secret_ref` - The secret reference string (including provider if specified)
    /// * `value` - The resolved secret value
    pub async fn insert(&self, secret_ref: String, value: String) {
        let mut cache = self.cache.lock().await;
        cache.insert(secret_ref, value);
    }

    /// Get a secret from the cache.
    ///
    /// # Arguments
    /// * `secret_ref` - The secret reference string (including provider if specified)
    ///
    /// # Returns
    /// * `Some(String)` if the secret is in the cache
    /// * `None` if the secret is not cached
    pub async fn get(&self, secret_ref: &str) -> Option<String> {
        let cache = self.cache.lock().await;
        cache.get(secret_ref).cloned()
    }

    /// Check if a secret is in the cache.
    ///
    /// # Arguments
    /// * `secret_ref` - The secret reference string (including provider if specified)
    ///
    /// # Returns
    /// * `true` if the secret is cached
    /// * `false` otherwise
    pub async fn contains(&self, secret_ref: &str) -> bool {
        let cache = self.cache.lock().await;
        cache.contains_key(secret_ref)
    }
}

/// Enum representing different types of secret providers.
///
/// Each variant wraps a specific secret provider implementation.
///
/// # Variants
///
/// - `Files`: Secret provider that reads from files
/// - `EnvironmentVariable`: Secret provider that reads from environment variables
/// - `AwsSecretsManager`: AWS Secrets Manager provider (requires `aws-secretsmanager` feature)
/// - `GcpSecretManager`: Google Cloud Secret Manager provider (requires `gcp-secretmanager` feature)
///
/// # Example
///
/// ```no_run
/// use regent_sdk::secrets::SecretProvider;
///
/// // Create a file-based provider
/// let provider = SecretProvider::files();
///
/// // Create an environment variable provider
/// let provider = SecretProvider::env_var();
///
/// // Create an AWS provider (requires feature flag)
/// // let provider = SecretProvider::aws_secretsmanager(aws_config);
/// ```
#[derive(Clone)]
pub enum SecretProvider {
    /// Secret provider that retrieves secrets from files on disk.
    Files(FilesSecretProvider),
    /// Secret provider that retrieves secrets from environment variables.
    EnvironmentVariable(EnvVarSecretProvider),
    /// AWS Secrets Manager provider.
    ///
    /// Requires the `aws-secretsmanager` feature to be enabled.
    #[cfg(feature = "aws-secretsmanager")]
    AwsSecretsManager(AwsSecretsManagerProvider),
    /// Google Cloud Secret Manager provider.
    ///
    /// Requires the `gcp-secretmanager` feature to be enabled.
    #[cfg(feature = "gcp-secretmanager")]
    GcpSecretManager(GcpSecretProvider),
    // DelineaSecretServer,
    // HashicorpVault,
}

impl SecretProvider {
    /// Create a file-based secret provider.
    ///
    /// Secrets are retrieved from files on the filesystem.
    /// The secret reference should be the file path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::SecretProvider;
    ///
    /// let provider = SecretProvider::files();
    /// // Secret reference: "/path/to/secret/file"
    /// ```
    pub fn files() -> Self {
        Self::Files(FilesSecretProvider::new())
    }

    /// Create an environment variable-based secret provider.
    ///
    /// Secrets are retrieved from environment variables.
    /// The secret reference should be the environment variable name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::SecretProvider;
    ///
    /// let provider = SecretProvider::env_var();
    /// // Secret reference: "MY_ENV_VAR"
    /// ```
    pub fn env_var() -> Self {
        Self::EnvironmentVariable(EnvVarSecretProvider::new())
    }

    /// Create an AWS Secrets Manager provider.
    ///
    /// Requires the `aws-secretsmanager` feature to be enabled.
    ///
    /// # Arguments
    ///
    /// * `aws_config` - AWS SDK configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::SecretProvider;
    /// use aws_config::SdkConfig;
    ///
    /// let aws_config = SdkConfig::default();
    /// let provider = SecretProvider::aws_secretsmanager(aws_config);
    /// ```
    #[cfg(feature = "aws-secretsmanager")]
    pub fn aws_secretsmanager(aws_config: AwsConfig) -> Self {
        Self::AwsSecretsManager(AwsSecretsManagerProvider::from(aws_config))
    }

    /// Create a Google Cloud Secret Manager provider.
    ///
    /// Requires the `gcp-secretmanager` feature to be enabled.
    ///
    /// # Returns
    ///
    /// A new GCP Secret Manager provider or an error if initialization fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::SecretProvider;
    ///
    /// let provider = SecretProvider::gcp_secretmanager().await.unwrap();
    /// ```
    #[cfg(feature = "gcp-secretmanager")]
    pub async fn gcp_secretmanager() -> Result<Self, RegentError> {
        match GcpSecretProvider::new().await {
            Ok(gcp_secret_provider) => Ok(Self::GcpSecretManager(gcp_secret_provider)),
            Err(details) => Err(RegentError::SecretsIssue(format!(
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

/// Trait for synchronous secret providers.
///
/// Implement this trait for secret providers that can operate synchronously.
///
/// # Requirements
///
/// Implementers must provide methods for connecting to the secret backend
/// and retrieving secrets in both typed and raw string formats.
pub trait SecretProvidingSolution {
    /// Connect to the secret provider backend.
    ///
    /// # Returns
    ///
    /// `Ok(())` if connection was successful, or a [`RegentError`] if it failed.
    async fn connect(&mut self) -> Result<(), RegentError>;

    /// Retrieve a secret as a specific type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the secret into (must implement `DeserializeOwned`)
    ///
    /// # Arguments
    ///
    /// * `secret_reference` - The reference/identifier for the secret
    ///
    /// # Returns
    ///
    /// The secret wrapped in a [`Secret`] container, or a [`RegentError`] if retrieval failed.
    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;

    /// Retrieve a secret as a raw string.
    ///
    /// # Arguments
    ///
    /// * `secret_reference` - The reference/identifier for the secret
    ///
    /// # Returns
    ///
    /// The secret as a string wrapped in a [`Secret`] container, or a [`RegentError`] if retrieval failed.
    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError>;
}

/// Trait for asynchronous secret providers.
///
/// Similar to [`SecretProvidingSolution`] but for providers that require async operations.
///
/// # Requirements
///
/// Implementers must provide methods for connecting to the secret backend
/// and retrieving secrets in both typed and raw string formats.
pub trait AsyncSecretProvidingSolution {
    /// Connect to the secret provider backend.
    ///
    /// # Returns
    ///
    /// `Ok(())` if connection was successful, or a [`RegentError`] if it failed.
    async fn connect(&mut self) -> Result<(), RegentError>;

    /// Retrieve a secret as a specific type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the secret into (must implement `DeserializeOwned`)
    ///
    /// # Arguments
    ///
    /// * `secret_reference` - The reference/identifier for the secret
    ///
    /// # Returns
    ///
    /// The secret wrapped in a [`Secret`] container, or a [`RegentError`] if retrieval failed.
    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;

    /// Retrieve a secret as a raw string.
    ///
    /// # Arguments
    ///
    /// * `secret_reference` - The reference/identifier for the secret
    ///
    /// # Returns
    ///
    /// The secret as a string wrapped in a [`Secret`] container, or a [`RegentError`] if retrieval failed.
    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError>;
}

/// A wrapper type that holds secret content and prevents accidental leaking.
///
/// This type wraps secret values and implements a custom `Debug` formatter that
/// redacts the actual secret content, preventing accidental exposure in logs.
///
/// # Type Parameters
///
/// * `T` - The type of the secret value
///
/// # Example
///
/// ```no_run
/// use regent_sdk::secrets::Secret;
///
/// let password = Secret::from("db_password", "super_secret_123".to_string());
///
/// // The secret content is redacted in Debug output
/// println!("{:?}", password); // Prints: Secret { sec_ref: "db_password", inner: <redacted> }
///
/// // Access the inner value when needed
/// let actual_password = password.inner();
/// ```
// Wrapper type which holds secrets content and helps to avoid leaking secrets (usual or debug logging in general...)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Secret<T> {
    /// Reference identifier for this secret (used for auditing and debugging).
    sec_ref: String,
    /// The actual secret value.
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
    /// Create a new secret wrapper.
    ///
    /// # Arguments
    ///
    /// * `sec_ref` - A reference identifier for this secret (used for auditing)
    /// * `inner` - The actual secret value
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::Secret;
    ///
    /// let secret = Secret::from("api_key", "sk-1234567890");
    /// ```
    pub fn from(sec_ref: &str, inner: T) -> Self {
        Self {
            sec_ref: sec_ref.to_string(),
            inner,
        }
    }

    /// Consume the secret wrapper and return the inner value.
    ///
    /// **Warning**: This exposes the secret value. Use with caution.
    ///
    /// # Returns
    ///
    /// The inner secret value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::Secret;
    ///
    /// let secret = Secret::from("password", "my_password");
    /// let password: String = secret.inner();
    /// ```
    pub fn inner(self) -> T {
        self.inner
    }
}

/// Reference to a secret in a secret provider.
///
/// This struct is used to identify secrets without containing the actual secret value.
/// It consists of a secret reference string and an optional provider name.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::secrets::SecretReference;
///
/// // Reference to a secret in the default provider
/// let ref1 = SecretReference::from("my_secret", None);
///
/// // Reference to a secret in a specific provider
/// let ref2 = SecretReference::from("my_secret", Some("aws".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    /// The reference/identifier for the secret (e.g., file path, env var name, secret name).
    sec_ref: String,
    /// Optional name of the secret provider to use.
    /// If `None`, the default provider will be used.
    provider: Option<String>,
}

impl SecretReference {
    /// Create a new secret reference.
    ///
    /// # Arguments
    ///
    /// * `sec_ref` - The reference/identifier for the secret
    /// * `provider` - Optional name of the secret provider
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::SecretReference;
    ///
    /// // Use default provider
    /// let ref1 = SecretReference::from("password", None);
    ///
    /// // Use specific provider
    /// let ref2 = SecretReference::from("api_key", Some("aws".to_string()));
    /// ```
    pub fn from(sec_ref: &str, provider: Option<String>) -> Self {
        Self {
            sec_ref: sec_ref.to_string(),
            provider,
        }
    }

    /// Get the secret reference string.
    ///
    /// # Returns
    ///
    /// A reference to the secret reference string.
    pub fn sec_ref(&self) -> &str {
        &self.sec_ref
    }

    /// Get the optional provider name.
    ///
    /// # Returns
    ///
    /// A reference to the optional provider name.
    pub fn provider(&self) -> &Option<String> {
        &self.provider
    }
}

/// Builder for creating [`SecretProvidersPool`] instances.
///
/// This builder allows you to configure multiple secret providers and set a default.
/// Use the builder pattern to add providers and then call [`build`] to create the pool.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
///
/// let pool = SecretProvidersPoolBuilder::new()
///     .add_provider("files", SecretProvider::files())
///     .add_default_provider("env", SecretProvider::env_var())
///     .build()
///     .unwrap();
/// ```
pub struct SecretProvidersPoolBuilder {
    providers: HashMap<String, SecretProvider>,
    default_provider: Option<String>,
}

impl SecretProvidersPoolBuilder {
    /// Create a new, empty secret providers pool builder.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::SecretProvidersPoolBuilder;
    ///
    /// let builder = SecretProvidersPoolBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: None,
        }
    }

    /// Add a secret provider to the pool.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique identifier for this provider
    /// * `provider` - The secret provider instance
    ///
    /// # Returns
    ///
    /// The builder, for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let builder = SecretProvidersPoolBuilder::new()
    ///     .add_provider("files", SecretProvider::files());
    /// ```
    pub fn add_provider(mut self, name: &str, provider: SecretProvider) -> Self {
        if let Some(_old_secret_provider) = self.providers.insert(name.to_string(), provider) {
            warn!(
                "You just overrided a secret provider in the pool, also identified by the name {}",
                name
            );
        }
        self
    }

    /// Add a secret provider and set it as the default.
    ///
    /// This is a convenience method that combines [`add_provider`] and [`set_default`].
    ///
    /// # Arguments
    ///
    /// * `name` - Unique identifier for this provider
    /// * `provider` - The secret provider instance
    ///
    /// # Returns
    ///
    /// The builder, for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let builder = SecretProvidersPoolBuilder::new()
    ///     .add_default_provider("files", SecretProvider::files());
    /// ```
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

    /// Set the default provider by name.
    ///
    /// The provider must have been previously added with [`add_provider`].
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the provider to set as default
    ///
    /// # Returns
    ///
    /// The builder, for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let builder = SecretProvidersPoolBuilder::new()
    ///     .add_provider("files", SecretProvider::files())
    ///     .add_provider("env", SecretProvider::env_var())
    ///     .set_default("files".to_string());
    /// ```
    pub fn set_default(mut self, name: String) -> Self {
        self.default_provider = Some(name);
        self
    }

    /// Build the secret providers pool.
    ///
    /// This consumes the builder and returns a new [`SecretProvidersPool`] if validation passes.
    ///
    /// # Returns
    ///
    /// - `Ok(SecretProvidersPool)` if the pool was successfully built
    /// - `Err(RegentError)` if validation failed (e.g., no default provider set, or default provider not found)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let pool = SecretProvidersPoolBuilder::new()
    ///     .add_default_provider("files", SecretProvider::files())
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<SecretProvidersPool, RegentError> {
        match self.default_provider {
            Some(default_provider_name) => match self.providers.get(&default_provider_name) {
                Some(_secrets_provider) => Ok(SecretProvidersPool {
                    providers: self.providers,
                    default_provider: default_provider_name,
                    secret_cache: None,
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

/// A pool of multiple secret providers with a unified interface.
///
/// This struct manages multiple [`SecretProvider`] instances and provides a single
/// interface for retrieving secrets. When a secret is requested, the pool uses
/// either the provider specified in the secret reference or the default provider.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::secrets::{SecretProvider, SecretProvidersPool, SecretReference};
///
/// // Create a pool with a single provider
/// let pool = SecretProvidersPool::from("files", SecretProvider::files());
///
/// // Retrieve a secret
/// let secret_ref = SecretReference::from("/path/to/secret", None);
/// let secret = pool.get_secret_raw(&secret_ref).await.unwrap();
/// ```
#[derive(Clone)]
pub struct SecretProvidersPool {
    /// Map of provider names to provider instances.
    providers: HashMap<String, SecretProvider>,
    /// Name of the default provider to use when none is specified.
    default_provider: String,
    /// Optional cache for storing resolved secrets to ensure idempotency.
    /// When `Some`, secrets are cached after first retrieval and subsequent
    /// requests for the same secret will return the cached value.
    secret_cache: Option<SecretCache>,
}

impl SecretProvidersPool {
    /// Create a new secret providers pool with a single provider.
    ///
    /// This is a convenience constructor for pools with only one provider,
    /// which will automatically be set as the default.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the provider
    /// * `secret_provider` - The secret provider instance
    ///
    /// # Returns
    ///
    /// A new [`SecretProvidersPool`] with the specified provider as the default.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
    ///
    /// let pool = SecretProvidersPool::from("files", SecretProvider::files());
    /// ```
    pub fn from(name: &str, secret_provider: SecretProvider) -> Self {
        let mut providers: HashMap<String, SecretProvider> = HashMap::new();
        providers.insert(name.to_string(), secret_provider);
        Self {
            providers,
            default_provider: name.to_string(),
            secret_cache: None,
        }
    }

    /// Enable secret caching for this pool.
    ///
    /// When caching is enabled, secrets are stored after first retrieval and
    /// subsequent requests for the same secret will return the cached value.
    /// This ensures idempotency by preventing secret rotation from affecting
    /// compliance operations that are in progress.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
    ///
    /// let mut pool = SecretProvidersPool::from("files", SecretProvider::files());
    /// pool.enable_caching();
    /// ```
    pub fn enable_caching(&mut self) {
        self.secret_cache = Some(SecretCache::new());
    }

    /// Disable secret caching for this pool.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
    ///
    /// let mut pool = SecretProvidersPool::from("files", SecretProvider::files());
    /// pool.disable_caching();
    /// ```
    pub fn disable_caching(&mut self) {
        self.secret_cache = None;
    }

    /// Check if caching is enabled for this pool.
    ///
    /// # Returns
    /// * `true` if caching is enabled
    /// * `false` otherwise
    pub fn is_caching_enabled(&self) -> bool {
        self.secret_cache.is_some()
    }

    /// Create a cache key from a secret reference.
    ///
    /// This creates a unique key that combines the provider name and secret reference
    /// to ensure proper caching across different providers.
    pub fn create_cache_key(&self, secret_reference: &SecretReference) -> String {
        let provider = match secret_reference.provider() {
            Some(user_defined_provider) => user_defined_provider.clone(),
            None => self.default_provider.clone(),
        };
        format!("{}:{}", provider, secret_reference.sec_ref())
    }

    /// Retrieve a secret as a specific type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the secret into (must implement `DeserializeOwned`)
    ///
    /// # Arguments
    ///
    /// * `secret_reference` - Reference to the secret to retrieve
    ///
    /// # Returns
    ///
    /// The secret wrapped in a [`Secret`] container, or a [`RegentError`] if retrieval failed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvidersPool, SecretReference};
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct ApiCredentials {
    ///     key: String,
    ///     secret: String,
    /// }
    ///
    /// let pool = SecretProvidersPool::from("files", SecretProvider::files());
    /// let secret_ref = SecretReference::from("api_creds.json", None);
    /// let creds: Secret<ApiCredentials> = pool.get_secret_typed(&secret_ref).await.unwrap();
    /// ```
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

    /// Retrieve a secret as a raw string.
    ///
    /// # Arguments
    ///
    /// * `secret_reference` - Reference to the secret to retrieve
    ///
    /// # Returns
    ///
    /// The secret as a string wrapped in a [`Secret`] container, or a [`RegentError`] if retrieval failed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvidersPool, SecretReference};
    ///
    /// let pool = SecretProvidersPool::from("files", SecretProvider::files());
    /// let secret_ref = SecretReference::from("/path/to/password.txt", None);
    /// let password = pool.get_secret_raw(&secret_ref).await.unwrap();
    /// let password_str: String = password.inner();
    /// ```
    pub async fn get_secret_raw(
        &self,
        secret_reference: &SecretReference,
    ) -> Result<Secret<String>, RegentError> {
        let cache_key = self.create_cache_key(secret_reference);

        // Check if the secret is in cache
        if let Some(cache) = &self.secret_cache {
            if let Some(cached_value) = cache.get(&cache_key).await {
                debug!("Secret cache hit for: {}", cache_key);
                return Ok(Secret::from(secret_reference.sec_ref(), cached_value));
            }
        }

        // Secret not in cache, fetch from provider
        let provider = match secret_reference.provider() {
            Some(user_defined_provider) => user_defined_provider,
            None => &self.default_provider,
        };

        let secret_result = match self.providers.get(provider) {
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
        };

        // Store in cache if caching is enabled
        if let Some(cache) = &self.secret_cache {
            if let Ok(secret) = &secret_result {
                let secret_value = secret.clone().inner();
                cache.insert(cache_key.clone(), secret_value).await;
                debug!("Secret cached for: {}", cache_key);
            }
        }

        secret_result
    }
}
