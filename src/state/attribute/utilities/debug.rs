use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvider;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DebugBlockExpectedState {
    msg: String,
    // var: Option<String>, // TODO
}

impl Check for DebugBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DebugBlockExpectedState {
    async fn assess_compliance(
        &self,
        _host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
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
    async fn call(
        &self,
        _host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        Ok(InternalApiCallOutcome::Success(None))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_debug_module_block_from_yaml_str() {
        let attribute = "---
Msg: some content
    ";

        let attribute: DebugBlockExpectedState = yaml_serde::from_str(attribute).unwrap();

        assert_eq!(attribute.msg, "some content".to_string());
    }
}
