use crate::error::Error;
use crate::managed_host::InternalApiCallOutcome;
use crate::managed_host::{AssessCompliance, ReachCompliance};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugBlockExpectedState {
    msg: String,
    // var: Option<String>, // TODO
}

// impl Check for DebugBlockExpectedState {
//     fn check(&self) -> Result<(), Error> {
//         Ok(())
//     }
// }

impl<Handler: HostHandler> AssessCompliance<Handler> for DebugBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error> {
        return Ok(AttributeComplianceAssessment::NonCompliant(Vec::from([
            Remediation::None(self.msg.clone()),
        ])));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DebugApiCall {}

impl DebugApiCall {
    pub fn display(&self) -> String {
        "Debug module".into()
    }

}

impl<Handler: HostHandler> ReachCompliance<Handler> for DebugApiCall {
    
    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        Ok(InternalApiCallOutcome::Success)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_debug_module_block_from_yaml_str() {
        let attribute = "---
msg: some content
    ";

        let attribute: DebugBlockExpectedState = serde_yaml::from_str(attribute).unwrap();

        assert_eq!(attribute.msg, "some content".to_string());
    }
}
