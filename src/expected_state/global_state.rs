use crate::task::moduleblock::ModuleBlockExpectedState as Attribute;

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

pub enum DryRunMode {
    Sequential,
    Parallel,
}

pub enum CompliancyStatus {
    Compliant,
    NotCompliant, // TODO : add details about why it's not compliant
}
