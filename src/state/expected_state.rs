use std::collections::HashMap;

use crate::{Error, state::attribute::Attribute};
use serde::{Deserialize, Serialize};

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
