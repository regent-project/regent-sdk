use crate::error::Error;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvider;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
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
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvider>,
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
    fn call(
        &self,
        _host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<InternalApiCallOutcome, Error> {
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

        let _attribute: PingBlockExpectedState = yaml_serde::from_str(raw_attributes).unwrap();
    }
}
