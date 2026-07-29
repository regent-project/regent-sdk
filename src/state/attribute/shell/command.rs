//! Shell command execution attribute
//!
//! This module provides the `CommandBlockExpectedState` type for executing arbitrary
//! shell commands on managed hosts.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::shell::command::CommandBlockExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Execute a simple command
//! let echo = CommandBlockExpectedState::builder("echo 'Hello, World!'")
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::command(echo, Privilege::None, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !Command
//!       Cmd: "echo 'Hello, World!'"
//!       Privilege: !None
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::secrets::{SecretProvidersPool, SecretReference};
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::expected_state::Parameter;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for a shell command to execute
///
/// The command will be executed each time compliance is assessed. Use this for
/// idempotent commands or one-time setup tasks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct CommandBlockExpectedState {
    /// Command to execute. Can be a clear text string or a secret reference.
    cmd: Parameter<String>,
}

impl Timeout for CommandBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

impl CommandBlockExpectedState {
    pub fn builder(cmd: &str) -> CommandBlockExpectedState {
        CommandBlockExpectedState {
            cmd: Parameter::Clear(cmd.to_string()),
        }
    }

    pub fn builder_secret(sec_ref: SecretReference) -> CommandBlockExpectedState {
        CommandBlockExpectedState {
            cmd: Parameter::Secret(sec_ref),
        }
    }

    pub fn build(&self) -> Result<CommandBlockExpectedState, RegentError> {
        if let Err(details) = self.check() {
            return Err(details);
        }
        Ok(self.clone())
    }
}

impl Check for CommandBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for CommandBlockExpectedState {
    async fn assess_compliance(
        &self,
        _host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
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
    pub cmd: Parameter<String>,
    privilege: Privilege,
}

impl CommandApiCall {
    pub fn display(&self) -> String {
        return format!("Run command : {}", self.cmd);
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for CommandApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let cmd_result = host_handler
            .run_command(
                &self
                    .cmd
                    .clone()
                    .inner_raw(optional_secret_provider)
                    .await
                    .unwrap(),
                &self.privilege,
            )
            .await
            .unwrap();

        if cmd_result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success(Some(cmd_result.stdout)))
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
- Cmd: ls -ltrh";

        let _attributes: Vec<CommandBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();
    }
}
