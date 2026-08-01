//! Debug message attribute
//!
//! This module provides the `DebugBlockExpectedState` type for outputting debug messages
//! during compliance assessment. Useful for troubleshooting and logging.
//!
//! **Compatible OS:** All (cross-platform)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::utilities::debug::DebugBlockExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Output a debug message
//! let debug_msg = DebugBlockExpectedState::builder("Checking system configuration")
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::debug(debug_msg, Privilege::None, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !Debug
//!       Msg: "Checking system configuration"
//!       Privilege: !None
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for a debug message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DebugBlockExpectedState {
    /// Debug message to output during compliance assessment
    msg: String,
    // var: Option<String>, // TODO
}

impl Timeout for DebugBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}

impl Check for DebugBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(&self, _host_properties: &HostProperties) -> Result<(), RegentError> {
        // Debug messages are cross-platform compatible
        Ok(())
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DebugBlockExpectedState {
    async fn assess_compliance(
        &self,
        _host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify host compatibility (always passes for debug)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }
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

impl Timeout for DebugApiCall {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}

impl Check for DebugApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(&self, _host_properties: &HostProperties) -> Result<(), RegentError> {
        // Debug messages are cross-platform compatible
        Ok(())
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for DebugApiCall {
    async fn call(
        &self,
        _host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify host compatibility (always passes for debug)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

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
