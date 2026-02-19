use crate::error::Error;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingBlockExpectedState {}

// impl Check for PingBlockExpectedState {
//     fn check(&self) -> Result<(), Error> {
//         Ok(())
//     }
// }

impl<Handler: HostHandler> AssessCompliance<Handler> for PingBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error> {
        let cmd = String::from("id");
        let cmd_result = host_handler.run_command(cmd.as_str(), &privilege)?;

        if cmd_result.return_code == 0 {
            return Ok(AttributeComplianceAssessment::Compliant);
        } else {
            return Err(Error::FailedDryRunEvaluation(
                "Host unreachable".to_string(),
            ));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingApiCall {
    privilege: Privilege,
}

impl PingApiCall {
    pub fn display(&self) -> String {
        return format!("Check SSH connectivity with remote host");
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for PingApiCall {
    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        Ok(InternalApiCallOutcome::Success)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_ping_module_block_from_yaml_str() {
        // This is weird to deserialize an empty content. Options may come later for the ping module (timeout for example)
        let raw_attributes = "---
    ";

        let attribute: PingBlockExpectedState = serde_yaml::from_str(raw_attributes).unwrap();
    }
}
