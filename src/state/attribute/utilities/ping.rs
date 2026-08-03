//! Host connectivity check (ping) attribute
//!
//! This module provides the `PingBlockExpectedState` type for checking basic connectivity
//! to a managed host. This is essentially a no-op attribute that verifies the host is reachable.
//!
//! **Compatible OS:** All (cross-platform)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::utilities::ping::PingBlockExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Check host connectivity
//! let ping = PingBlockExpectedState::builder()
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::ping(ping, Privilege::None, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !Ping
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
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for a host connectivity check
///
/// This attribute checks if the host is reachable by running a simple `id` command.
/// It does not require any additional parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct PingBlockExpectedState {}

impl Check for PingBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        // Ping is cross-platform compatible
        Ok(())
    }
}

impl Timeout for PingBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for PingBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify host compatibility (always passes for ping)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }
        // Ping is a connectivity check that should not affect compliance state
        // The actual connectivity validation should be handled at the connection level
        let cmd = String::from("id");
        let _cmd_result = host_handler.run_command(cmd.as_str(), &privilege).await?;
        
        // Always return Compliant - ping is a pre-requisite check, not a compliance attribute
        return Ok(AttributeComplianceAssessment::Compliant);
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

impl Check for PingApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        // Ping is cross-platform compatible
        Ok(())
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for PingApiCall {
    async fn call(
        &self,
        _host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify host compatibility (always passes for ping)
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
    fn parsing_ping_module_block_from_yaml_str() {
        // This is weird to deserialize an empty content. Options may come later for the ping module (timeout for example)
        let raw_attributes = "---
    ";

        let _attribute: PingBlockExpectedState = yaml_serde::from_str(raw_attributes).unwrap();
    }
}
