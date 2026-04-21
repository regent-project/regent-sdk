use crate::secrets::SecretProvider;
use crate::{Error, secrets::SecretReference, state::attribute::Attribute};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Display};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ExpectedState {
    pub secrets_references: Option<HashMap<String, String>>,
    pub attributes: Vec<Attribute>,
}

impl ExpectedState {
    pub fn new() -> ExpectedState {
        ExpectedState {
            secrets_references: None,
            attributes: Vec::new(),
        }
    }

    pub fn with_attribute(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    pub fn from_raw_yaml(raw_yaml_content: &str) -> Result<Self, Error> {
        match yaml_serde::from_str::<ExpectedState>(raw_yaml_content) {
            Ok(expected_state) => Ok(expected_state),
            Err(error_details) => Err(Error::FailureToParseContent(format!("{}", error_details))),
        }
    }

    pub fn build(&self) -> ExpectedState {
        ExpectedState {
            secrets_references: self.secrets_references.clone(),
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
    ) -> Result<String, Error> {
        match self {
            Parameter::Clear(content) => Ok(content),
            Parameter::Secret(secret_reference) => match optional_secret_provider {
                Some(secret_provider) => {
                    match secret_provider.get_secret_raw(secret_reference.sec_ref()) {
                        Ok(secret) => Ok(secret.inner()),
                        Err(error_detail) => {
                            return Err(Error::FailedToGetSecret(format!("{:?}", error_detail)));
                        }
                    }
                }
                None => {
                    return Err(Error::WrongInitialization(
                        "Secrets are referenced but no SecretProvider to retrieve them from"
                            .to_string(),
                    ));
                }
            },
        }
    }
}

impl<T: DeserializeOwned> Parameter<T> {
    pub fn inner(self, optional_secret_provider: &Option<SecretProvider>) -> Result<T, Error> {
        match self {
            Parameter::Clear(content) => Ok(content),
            Parameter::Secret(secret_reference) => match optional_secret_provider {
                Some(secret_provider) => {
                    match secret_provider.get_secret_typed::<T>(secret_reference.sec_ref()) {
                        Ok(secret) => Ok(secret.inner()),
                        Err(error_detail) => {
                            return Err(Error::FailedToGetSecret(format!("{:?}", error_detail)));
                        }
                    }
                }
                None => {
                    return Err(Error::WrongInitialization(
                        "Secrets are referenced but no SecretProvider to retrieve them from"
                            .to_string(),
                    ));
                }
            },
        }
    }
}
