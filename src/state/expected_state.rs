//! Expected state definition
//!
//! This module provides the [`ExpectedState`] type, which is the root container
//! for infrastructure definitions in Regent SDK.

use crate::secrets::SecretProvidersPool;
use crate::{RegentError, secrets::SecretReference, state::attribute::Attribute};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

/// The root container for infrastructure definitions.
///
/// `ExpectedState` represents the desired state of one or more systems. It contains
/// a list of [`Attribute`] instances, each defining a specific resource or configuration.
///
/// # Serialization
///
/// `ExpectedState` can be serialized and deserialized as JSON or YAML:
///
/// ```no_run
/// use regent_sdk::state::ExpectedState;
/// use regents_sdk::Attribute;
///
/// let expected_state = ExpectedState::new()
///     .with_attribute(Attribute::service(/* ... */))
///     .build();
///
/// // Serialize to YAML
/// let yaml = serde_yaml::to_string(&expected_state).unwrap();
///
/// // Deserialize from YAML
/// let expected_state: ExpectedState = serde_yaml::from_str(&yaml).unwrap();
/// ```
///
/// # Example
///
/// ```no_run
/// use regent_sdk::state::ExpectedState;
/// use regent_sdk::Attribute;
/// use regent_sdk::attribute::system::service::{ServiceBlockExpectedState, ServiceExpectedState};
/// use regent_sdk::Privilege;
///
/// // Create individual attribute
/// let nginx_service = ServiceBlockExpectedState::builder("nginx")
///     .with_state(ServiceExpectedState::Started)
///     .build()
///     .unwrap();
///
/// // Create expected state
/// let expected_state = ExpectedState::new()
///     .with_attribute(Attribute::service(nginx_service, Privilege::WithSudo, None))
///     .with_attribute(Attribute::user(/* ... */))
///     .build();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ExpectedState {
    /// List of attributes that define the expected state.
    ///
    /// Each attribute represents a resource or configuration that should exist
    /// on the target system in a specific state.
    pub attributes: Vec<Attribute>,
}

impl ExpectedState {
    /// Create a new, empty expected state.
    ///
    /// # Returns
    ///
    /// A new [`ExpectedState`] with no attributes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::state::ExpectedState;
    ///
    /// let expected_state = ExpectedState::new();
    /// assert!(expected_state.attributes.is_empty());
    /// ```
    pub fn new() -> ExpectedState {
        ExpectedState {
            attributes: Vec::new(),
        }
    }

    /// Add an attribute to the expected state.
    ///
    /// This method uses the builder pattern, allowing for fluent configuration.
    ///
    /// # Arguments
    ///
    /// * `attribute` - The attribute to add
    ///
    /// # Returns
    ///
    /// The same [`ExpectedState`] with the attribute added.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::state::ExpectedState;
    /// use regent_sdk::Attribute;
    ///
    /// let expected_state = ExpectedState::new()
    ///     .with_attribute(Attribute::service(/* ... */))
    ///     .with_attribute(Attribute::user(/* ... */))
    ///     .build();
    /// ```
    pub fn with_attribute(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    /// Parse an expected state from raw YAML content.
    ///
    /// This method deserializes YAML and validates all attributes.
    ///
    /// # Arguments
    ///
    /// * `raw_yaml_content` - The YAML string to parse
    ///
    /// # Returns
    ///
    /// - `Ok(ExpectedState)` if parsing and validation succeeded
    /// - `Err(RegentError)` if parsing failed or any attribute validation failed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::state::ExpectedState;
    ///
    /// let yaml = r#"
    /// Attributes:
    ///   - Service:
    ///       Name: nginx
    ///       State: Started
    /// "#;
    ///
    /// let expected_state = ExpectedState::from_raw_yaml(yaml).unwrap();
    /// ```
    pub fn from_raw_yaml(raw_yaml_content: &str) -> Result<Self, RegentError> {
        match yaml_serde::from_str::<ExpectedState>(raw_yaml_content) {
            Ok(expected_state) => {
                for attribute in &expected_state.attributes {
                    if let Err(details) = attribute.check() {
                        return Err(details);
                    }
                }
                Ok(expected_state)
            }
            Err(detailss) => Err(RegentError::FailureToParseContent(format!("{}", detailss))),
        }
    }

    /// Build the expected state.
    ///
    /// This method creates a new [`ExpectedState`] with a copy of the current attributes.
    /// It's primarily useful for finalizing a builder-style configuration.
    ///
    /// # Returns
    ///
    /// A new [`ExpectedState`] instance.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::state::ExpectedState;
    /// use regent_sdk::Attribute;
    ///
    /// let expected_state = ExpectedState::new()
    ///     .with_attribute(Attribute::service(/* ... */))
    ///     .build();
    /// ```
    pub fn build(&self) -> ExpectedState {
        ExpectedState {
            attributes: self.attributes.clone(),
        }
    }
}

/// A parameter that can be either a clear value or a secret reference.
///
/// This enum allows attributes to accept parameters that are either provided
/// directly or retrieved from a secret provider.
///
/// # Type Parameters
///
/// * `T` - The type of the clear value
///
/// # Variants
///
/// - `Clear`: A direct value (not secret)
/// - `Secret`: A reference to a secret in a secret provider
///
/// # Example
///
/// ```no_run
/// use regent_sdk::state::expected_state::Parameter;
/// use regent_sdk::secrets::SecretReference;
///
/// // Clear parameter
/// let param1: Parameter<String> = Parameter::Clear("hello".to_string());
///
/// // Secret parameter
/// let param2: Parameter<String> = Parameter::Secret(
///     SecretReference::from("my_secret", Some("files".to_string()))
/// );
/// ```
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Parameter<T> {
    /// A direct, non-secret value.
    Clear(T),
    /// A reference to a secret in a secret provider.
    Secret(SecretReference),
}

impl<T> Debug for Parameter<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Parameter::Clear(content) => {
                write!(f, "{:?}", content)
            }
            Parameter::Secret(content) => {
                write!(f, "{:?}", content)
            }
        }
    }
}

impl<T> Display for Parameter<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Parameter::Clear(content) => {
                write!(f, "{}", content)
            }
            Parameter::Secret(content) => {
                write!(f, "{:?}", content)
            }
        }
    }
}

impl Parameter<String> {
    /// Resolve a string parameter, retrieving from secret provider if needed.
    ///
    /// If the parameter is a clear value, returns it directly.
    /// If the parameter is a secret reference, retrieves the secret from the provider.
    ///
    /// # Arguments
    ///
    /// * `optional_secret_provider` - Optional secret providers pool
    ///
    /// # Returns
    ///
    /// - `Ok(String)` with the resolved value
    /// - `Err(RegentError)` if secret retrieval failed or no provider was available
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::state::expected_state::Parameter;
    /// use regent_sdk::secrets::{SecretProvidersPool, SecretProvider};
    ///
    /// let param = Parameter::Clear("hello".to_string());
    /// let value = param.inner_raw(&None).await.unwrap();
    /// assert_eq!(value, "hello");
    /// ```
    pub async fn inner_raw(
        self,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<String, RegentError> {
        match self {
            Parameter::Clear(content) => Ok(content),
            Parameter::Secret(secret_reference) => match optional_secret_provider {
                Some(secret_providers_pool) => {
                    match secret_providers_pool
                        .get_secret_raw(&secret_reference)
                        .await
                    {
                        Ok(secret) => Ok(secret.inner()),
                        Err(details) => {
                            return Err(RegentError::FailedToGetSecret(format!("{:?}", details)));
                        }
                    }
                }
                None => {
                    return Err(RegentError::WrongInitialization(
                        "Secrets are referenced but no SecretProvider to retrieve them from"
                            .to_string(),
                    ));
                }
            },
        }
    }
}

impl<T: DeserializeOwned> Parameter<T> {
    /// Resolve a parameter, retrieving from secret provider if needed.
    ///
    /// If the parameter is a clear value, returns it directly.
    /// If the parameter is a secret reference, retrieves and deserializes the secret.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the secret into (must implement `DeserializeOwned`)
    ///
    /// # Arguments
    ///
    /// * `optional_secret_provider` - Optional secret providers pool
    ///
    /// # Returns
    ///
    /// - `Ok(T)` with the resolved and deserialized value
    /// - `Err(RegentError)` if secret retrieval or deserialization failed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::state::expected_state::Parameter;
    /// use regents_sdk::secrets::{SecretProvidersPool, SecretProvider};
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Config {
    ///     api_key: String,
    /// }
    ///
    /// // Assuming we have a provider
    /// let param: Parameter<Config> = Parameter::Secret(/* ... */);
    /// let config: Config = param.inner(&Some(pool)).await.unwrap();
    /// ```
    pub async fn inner(
        self,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<T, RegentError> {
        match self {
            Parameter::Clear(content) => Ok(content),
            Parameter::Secret(secret_reference) => match optional_secret_provider {
                Some(secret_providers_pool) => {
                    match secret_providers_pool
                        .get_secret_typed::<T>(&secret_reference)
                        .await
                    {
                        Ok(secret) => Ok(secret.inner()),
                        Err(details) => {
                            return Err(RegentError::FailedToGetSecret(format!("{:?}", details)));
                        }
                    }
                }
                None => {
                    return Err(RegentError::WrongInitialization(
                        "Secrets are referenced but no SecretProvider to retrieve them from"
                            .to_string(),
                    ));
                }
            },
        }
    }
}
