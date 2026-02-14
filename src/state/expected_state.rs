use crate::state::attribute::Attribute;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
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

    pub fn build(&self) -> ExpectedState {
        ExpectedState {
            attributes: self.attributes.clone(),
        }
    }
}
