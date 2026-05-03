use crate::secrets::SecretProvider;
use crate::{RegentError, secrets::SecretReference, state::attribute::Attribute};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ExpectedState {
    pub attributes: Vec<Attribute>,
}

impl ExpectedState {
    pub fn new() -> ExpectedState {
        ExpectedState {
            attributes: Vec::new(),
        }
    }

    pub fn with_attribute(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }

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

    pub fn build(&self) -> ExpectedState {
        ExpectedState {
            attributes: self.attributes.clone(),
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Parameter<T> {
    Clear(T),
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
    pub fn inner_raw(
        self,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<String, RegentError> {
        match self {
            Parameter::Clear(content) => Ok(content),
            Parameter::Secret(secret_reference) => match optional_secret_provider {
                Some(secret_provider) => {
                    match secret_provider.get_secret_raw(secret_reference.sec_ref()) {
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
    pub fn inner(
        self,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<T, RegentError> {
        match self {
            Parameter::Clear(content) => Ok(content),
            Parameter::Secret(secret_reference) => match optional_secret_provider {
                Some(secret_provider) => {
                    match secret_provider.get_secret_typed::<T>(secret_reference.sec_ref()) {
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
