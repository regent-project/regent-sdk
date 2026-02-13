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
pub struct CommandBlockExpectedState {
    cmd: String,
}

// impl Check for CommandBlockExpectedState {
//     fn check(&self) -> Result<(), Error> {
//         Ok(())
//     }
// }

impl<Handler: HostHandler> AssessCompliance<Handler> for CommandBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error> {
        let mut remediations: Vec<Remediation> = Vec::new();

        let privilege = privilege.clone();

        remediations.push(Remediation::Command(CommandApiCall {
            cmd: self.cmd.clone(),
            privilege,
        }));

        return Ok(AttributeComplianceAssessment::NonCompliant(remediations));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandApiCall {
    pub cmd: String,
    privilege: Privilege,
}

impl<Handler: HostHandler> ReachCompliance<Handler> for CommandApiCall {
    // fn display(&self) -> String {
    //     return format!("Run command : {}", self.cmd);
    // }

    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        let cmd_result = host_handler
            .run_command(self.cmd.as_str(), &self.privilege)
            .unwrap();

        // TODO : add command output saving
        if cmd_result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success)
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC : {}, STDOUT : {}, STDERR : {}",
                cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_service_module_block_from_yaml_str() {
        let raw_attributes = "---
- cmd: ls -ltrh";

        let attributes: Vec<CommandBlockExpectedState> =
            serde_yaml::from_str(raw_attributes).unwrap();
    }
}
