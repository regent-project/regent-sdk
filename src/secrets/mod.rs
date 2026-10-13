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
//! use regent_sdk::secrets::{SecretProvider, SecretProvidersPool, SecretProvidersPoolBuilder, SecretReference};
//!
//! // Create a pool with file-based secrets
//! let files = SecretProvider::files("files");
//! let pool = SecretProvidersPoolBuilder::new()
//!     .with_default_provider(&files)
//!     .build()
//!     .unwrap();
//!
//! // Refer to a secret of this provider
//! let ssh_key = SecretReference::from_provider("/path/to/key", &files);
//!
//! // Or use environment variables
//! let pool = SecretProvidersPool::with_default_provider(&SecretProvider::env_var("env"));
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
/// that the same secret value is used throughout a run,
/// even if the underlying secret is rotated during the operation.
#[derive(Debug, Clone)]
pub struct SecretCache {
    cache: Arc<Mutex<HashMap<String, String>>>,
}

impl SecretCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, secret_ref: String, value: String) {
        let mut cache = self.cache.lock().await;
        cache.insert(secret_ref, value);
    }

    pub async fn get(&self, secret_ref: &str) -> Option<String> {
        let cache = self.cache.lock().await;
        cache.get(secret_ref).cloned()
    }

    pub async fn contains(&self, secret_ref: &str) -> bool {
        let cache = self.cache.lock().await;
        cache.contains_key(secret_ref)
    }
}

/// A named secret provider. The name identifies the provider in a [`SecretProvidersPool`]: it is the `Provider` of the
/// [`SecretReference`]s pointing to its secrets. This wrapper type allows to map the "YAML API" with the rust code, meaning
/// an artbitrary user-defined name with an actual rust item.
#[derive(Clone)]
pub struct SecretProvider {
    name: String,
    backend: SecretBackend,
}

#[derive(Clone)]
enum SecretBackend {
    /// Secret provider that retrieves secrets from files on disk.
    Files(FilesSecretProvider),
    /// Secret provider that retrieves secrets from environment variables.
    EnvironmentVariable(EnvVarSecretProvider),
    /// AWS Secrets Manager provider.
    /// Requires the `aws-secretsmanager` feature to be enabled.
    #[cfg(feature = "aws-secretsmanager")]
    AwsSecretsManager(AwsSecretsManagerProvider),
    /// Google Cloud Secret Manager provider.
    /// Requires the `gcp-secretmanager` feature to be enabled.
    #[cfg(feature = "gcp-secretmanager")]
    GcpSecretManager(GcpSecretProvider),
    // DelineaSecretServer,
    // HashicorpVault,
}

impl SecretProvider {
    /// Secrets are retrieved from files on the filesystem.
    /// The secret reference must be the file path.
    pub fn files(name: &str) -> Self {
        Self::new(name, SecretBackend::Files(FilesSecretProvider::new()))
    }

    /// Secrets are retrieved from environment variables.
    /// The secret reference must be the environment variable name.
    pub fn env_var(name: &str) -> Self {
        Self::new(
            name,
            SecretBackend::EnvironmentVariable(EnvVarSecretProvider::new()),
        )
    }

    /// Create an AWS Secrets Manager provider.
    ///
    /// The secret reference must be the ARN of the secret.
    /// Requires the `aws-secretsmanager` feature to be enabled.
    #[cfg(feature = "aws-secretsmanager")]
    pub fn aws_secretsmanager(name: &str, aws_config: AwsConfig) -> Self {
        Self::new(
            name,
            SecretBackend::AwsSecretsManager(AwsSecretsManagerProvider::from(aws_config)),
        )
    }

    /// Create a Google Cloud Secret Manager provider.
    ///
    /// The secret reference must be the Ressource Name of the secret.
    /// Requires the `gcp-secretmanager` feature to be enabled.
    #[cfg(feature = "gcp-secretmanager")]
    pub async fn gcp_secretmanager(name: &str) -> Result<Self, RegentError> {
        match GcpSecretProvider::new().await {
            Ok(gcp_secret_provider) => Ok(Self::new(
                name,
                SecretBackend::GcpSecretManager(gcp_secret_provider),
            )),
            Err(details) => Err(RegentError::SecretsIssue(format!(
                "Failed to create a GCP SecretManager client : {}",
                details
            ))),
        }
    }

    fn new(name: &str, backend: SecretBackend) -> Self {
        Self {
            name: name.to_string(),
            backend,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError> {
        match &self.backend {
            SecretBackend::Files(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            }
            SecretBackend::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            }
            #[cfg(feature = "aws-secretsmanager")]
            SecretBackend::AwsSecretsManager(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            }
            #[cfg(feature = "gcp-secretmanager")]
            SecretBackend::GcpSecretManager(secret_provider) => {
                secret_provider.get_secret_typed(secret_reference).await
            } // SecretBackend::DelineaSecretServer => {}
              // SecretBackend::HashicorpVault => {}
        }
    }

    pub async fn get_secret_raw(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<String>, RegentError> {
        match &self.backend {
            SecretBackend::Files(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            }
            SecretBackend::EnvironmentVariable(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            }
            #[cfg(feature = "aws-secretsmanager")]
            SecretBackend::AwsSecretsManager(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            }
            #[cfg(feature = "gcp-secretmanager")]
            SecretBackend::GcpSecretManager(secret_provider) => {
                secret_provider.get_secret_raw(secret_reference).await
            } // SecretBackend::DelineaSecretServer => {}
              // SecretBackend::HashicorpVault => {}
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
    async fn connect(&mut self) -> Result<(), RegentError>;

    /// Retrieve a secret as a specific type.
    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;

    /// Retrieve a secret as a raw string.
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
    async fn connect(&mut self) -> Result<(), RegentError>;

    /// Retrieve a secret as a specific type.
    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError>;

    /// Retrieve a secret as a raw string.
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

    /// Create a reference to a secret of the given provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretReference};
    ///
    /// let env = SecretProvider::env_var("env");
    /// let api_key = SecretReference::from_provider("API_KEY", &env);
    /// ```
    pub fn from_provider(sec_ref: &str, provider: &SecretProvider) -> Self {
        Self::from(sec_ref, Some(provider.name.clone()))
    }

    /// Get the secret reference string.
    pub fn sec_ref(&self) -> &str {
        &self.sec_ref
    }

    /// Get the optional provider name.
    pub fn provider(&self) -> &Option<String> {
        &self.provider
    }
}

/// Builder for creating [`SecretProvidersPool`] instances.
///
/// This builder allows you to configure multiple secret providers and set a default.
/// Use the builder pattern to add providers and then call [`SecretProvidersPoolBuilder::build()`] to create the pool.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
///
/// let pool = SecretProvidersPoolBuilder::new()
///     .add_provider(&SecretProvider::files("files"))
///     .with_default_provider(&SecretProvider::env_var("env"))
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
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let builder = SecretProvidersPoolBuilder::new()
    ///     .add_provider(&SecretProvider::files("files"));
    /// ```
    pub fn add_provider(mut self, provider: &SecretProvider) -> Self {
        if let Some(_old_secret_provider) = self
            .providers
            .insert(provider.name.clone(), provider.clone())
        {
            warn!(
                "You just overrided a secret provider in the pool, also identified by the name {}",
                provider.name
            );
        }
        self
    }

    /// Add a secret provider and set it as the default.
    ///
    /// This is a convenience method that combines `add_provider` and `set_default`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let builder = SecretProvidersPoolBuilder::new()
    ///     .with_default_provider(&SecretProvider::files("files"));
    /// ```
    pub fn with_default_provider(self, provider: &SecretProvider) -> Self {
        let mut builder = self.add_provider(provider);
        builder.default_provider = Some(provider.name.clone());
        builder
    }

    /// Set the default provider.
    ///
    /// The provider must have been previously added with `add_provider`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let files = SecretProvider::files("files");
    /// let builder = SecretProvidersPoolBuilder::new()
    ///     .add_provider(&files)
    ///     .add_provider(&SecretProvider::env_var("env"))
    ///     .set_default(&files);
    /// ```
    pub fn set_default(mut self, provider: &SecretProvider) -> Self {
        self.default_provider = Some(provider.name.clone());
        self
    }

    /// Build the secret providers pool.
    ///
    /// This consumes the builder and returns a new [`SecretProvidersPool`] if validation passes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let pool = SecretProvidersPoolBuilder::new()
    ///     .with_default_provider(&SecretProvider::files("files"))
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
/// let pool = SecretProvidersPool::with_default_provider(&SecretProvider::files("files"));
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
    /// Create a pool holding a single provider, used as the default provider.
    ///
    /// To hold several providers, use [`SecretProvidersPoolBuilder`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
    ///
    /// let pool = SecretProvidersPool::with_default_provider(&SecretProvider::files("files"));
    /// ```
    pub fn with_default_provider(secret_provider: &SecretProvider) -> Self {
        let mut providers: HashMap<String, SecretProvider> = HashMap::new();
        providers.insert(secret_provider.name.clone(), secret_provider.clone());
        Self {
            providers,
            default_provider: secret_provider.name.clone(),
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
    /// let mut pool = SecretProvidersPool::with_default_provider(&SecretProvider::files("files"));
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
    /// let mut pool = SecretProvidersPool::with_default_provider(&SecretProvider::files("files"));
    /// pool.disable_caching();
    /// ```
    pub fn disable_caching(&mut self) {
        self.secret_cache = None;
    }

    /// Check if caching is enabled for this pool.
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
    /// let pool = SecretProvidersPool::with_default_provider(&SecretProvider::files("files"));
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
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::secrets::{SecretProvidersPool, SecretReference};
    ///
    /// let pool = SecretProvidersPool::with_default_provider(&SecretProvider::files("files"));
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
