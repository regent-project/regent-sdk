//! Service management attribute
//!
//! This module provides the `ServiceBlockExpectedState` type for managing system services
//! using systemctl.
//!
//! **Compatible OS:** Linux (all distributions with systemd)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::service::{ServiceBlockExpectedState, ServiceExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Ensure httpd service is running and enabled
//! let httpd = ServiceBlockExpectedState::builder("httpd")
//!     .with_state(ServiceExpectedState::Started)
//!     .with_enabled(true)
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::service(httpd, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !Service
//!       Name: httpd
//!       State: !Started
//!       Enabled: true
//!       Privilege: !WithSudo
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Desired run-state of the service
///
/// - `Started`  / `Stopped`  — idempotent: only act if the service is not already in the target state.
/// - `Restarted`/ `Reloaded` — unconditional: always emit the corresponding systemctl command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceExpectedState {
    /// Service should be running
    Started,
    /// Service should be stopped
    Stopped,
    /// Service should be restarted (unconditional action)
    Restarted,
    /// Service should be reloaded (unconditional action)
    Reloaded,
}

/// Configuration for a system service
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceBlockExpectedState {
    /// Service name
    name: String,
    /// Desired run-state. At least one of State or Enabled must be set.
    state: Option<ServiceExpectedState>,
    /// Whether the service should be enabled (start on boot). true = enabled, false = disabled.
    enabled: Option<bool>,
}

impl Timeout for ServiceBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

impl ServiceBlockExpectedState {
    pub fn builder(service_name: &str) -> ServiceBlockExpectedState {
        ServiceBlockExpectedState {
            name: service_name.to_string(),
            state: None,
            enabled: None,
        }
    }

    pub fn with_state(&mut self, state: ServiceExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_enabled(&mut self, enabled: bool) -> &mut Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn build(&self) -> Result<ServiceBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for ServiceBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.state.is_none() && self.enabled.is_none() {
            return Err(RegentError::IncoherentExpectedState(
                "At least one of State or Enabled must be set.".to_string(),
            ));
        }
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        use crate::hosts::properties::InitSystem;
        match host_properties.os_kind() {
            OsKind::Linux(linux_specifics) => match linux_specifics.init_system {
                InitSystem::Systemd => Ok(()),
                InitSystem::Unknown => Err(RegentError::IncompatibleHost(
                    "systemctl requires systemd but init system could not be detected".to_string(),
                )),
            },
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but systemctl is only supported on Linux with systemd",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for ServiceBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        if !host_handler
            .is_this_command_available("systemctl", privilege)
            .await
            .unwrap()
        {
            return Err(RegentError::FailedDryRunEvaluation(
                "systemctl is not available on this host".to_string(),
            ));
        }

        let mut remediations: Vec<Remediation> = Vec::new();

        // ── run-state ─────────────────────────────────────────────────────────
        match &self.state {
            Some(ServiceExpectedState::Started) => {
                let active = service_is_active(host_handler, &self.name)
                    .await
                    .map_err(|e| RegentError::FailedDryRunEvaluation(e))?;
                if !active {
                    remediations.push(Remediation::Service(ServiceApiCall::from(
                        ServiceModuleInternalApiCall::Start(self.name.clone()),
                        privilege.clone(),
                    )));
                }
            }
            Some(ServiceExpectedState::Stopped) => {
                let active = service_is_active(host_handler, &self.name)
                    .await
                    .map_err(|e| RegentError::FailedDryRunEvaluation(e))?;
                if active {
                    remediations.push(Remediation::Service(ServiceApiCall::from(
                        ServiceModuleInternalApiCall::Stop(self.name.clone()),
                        privilege.clone(),
                    )));
                }
            }
            Some(ServiceExpectedState::Restarted) => {
                // Unconditional — always restart.
                remediations.push(Remediation::Service(ServiceApiCall::from(
                    ServiceModuleInternalApiCall::Restart(self.name.clone()),
                    privilege.clone(),
                )));
            }
            Some(ServiceExpectedState::Reloaded) => {
                // Unconditional — always reload.
                remediations.push(Remediation::Service(ServiceApiCall::from(
                    ServiceModuleInternalApiCall::Reload(self.name.clone()),
                    privilege.clone(),
                )));
            }
            None => {}
        }

        // ── boot-enable state ─────────────────────────────────────────────────
        match self.enabled {
            Some(true) => {
                let is_enabled = service_is_enabled(host_handler, &self.name)
                    .await
                    .map_err(|e| RegentError::FailedDryRunEvaluation(e))?;
                if !is_enabled {
                    remediations.push(Remediation::Service(ServiceApiCall::from(
                        ServiceModuleInternalApiCall::Enable(self.name.clone()),
                        privilege.clone(),
                    )));
                }
            }
            Some(false) => {
                let is_enabled = service_is_enabled(host_handler, &self.name)
                    .await
                    .map_err(|e| RegentError::FailedDryRunEvaluation(e))?;
                if is_enabled {
                    remediations.push(Remediation::Service(ServiceApiCall::from(
                        ServiceModuleInternalApiCall::Disable(self.name.clone()),
                        privilege.clone(),
                    )));
                }
            }
            None => {}
        }

        if remediations.is_empty() {
            Ok(AttributeComplianceAssessment::Compliant)
        } else {
            Ok(AttributeComplianceAssessment::NonCompliant(remediations))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceModuleInternalApiCall {
    Start(String),
    Stop(String),
    Restart(String),
    Reload(String),
    Enable(String),
    Disable(String),
}

impl std::fmt::Display for ServiceModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceModuleInternalApiCall::Start(s) => write!(f, "start {}", s),
            ServiceModuleInternalApiCall::Stop(s) => write!(f, "stop {}", s),
            ServiceModuleInternalApiCall::Restart(s) => write!(f, "restart {}", s),
            ServiceModuleInternalApiCall::Reload(s) => write!(f, "reload {}", s),
            ServiceModuleInternalApiCall::Enable(s) => write!(f, "enable {}", s),
            ServiceModuleInternalApiCall::Disable(s) => write!(f, "disable {}", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceApiCall {
    pub api_call: ServiceModuleInternalApiCall,
    privilege: Privilege,
}

impl ServiceApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            ServiceModuleInternalApiCall::Start(s) => format!("Start service {}", s),
            ServiceModuleInternalApiCall::Stop(s) => format!("Stop service {}", s),
            ServiceModuleInternalApiCall::Restart(s) => format!("Restart service {}", s),
            ServiceModuleInternalApiCall::Reload(s) => format!("Reload service {}", s),
            ServiceModuleInternalApiCall::Enable(s) => format!("Enable service {}", s),
            ServiceModuleInternalApiCall::Disable(s) => format!("Disable service {}", s),
        }
    }

    fn from(api_call: ServiceModuleInternalApiCall, privilege: Privilege) -> ServiceApiCall {
        ServiceApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for ServiceApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        use crate::hosts::properties::InitSystem;
        match host_properties.os_kind() {
            OsKind::Linux(linux_specifics) => match linux_specifics.init_system {
                InitSystem::Systemd => Ok(()),
                InitSystem::Unknown => Err(RegentError::IncompatibleHost(
                    "systemctl requires systemd but init system could not be detected".to_string(),
                )),
            },
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but systemctl is only supported on Linux with systemd",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for ServiceApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let cmd = match &self.api_call {
            ServiceModuleInternalApiCall::Start(s) => format!("systemctl start {}", s),
            ServiceModuleInternalApiCall::Stop(s) => format!("systemctl stop {}", s),
            ServiceModuleInternalApiCall::Restart(s) => format!("systemctl restart {}", s),
            ServiceModuleInternalApiCall::Reload(s) => format!("systemctl reload {}", s),
            ServiceModuleInternalApiCall::Enable(s) => format!("systemctl enable {}", s),
            ServiceModuleInternalApiCall::Disable(s) => format!("systemctl disable {}", s),
        };

        let result = host_handler
            .run_command(&cmd, &self.privilege)
            .await
            .unwrap();

        if result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success(None))
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC: {}, STDOUT: {}, STDERR: {}",
                result.return_code, result.stdout, result.stderr
            )))
        }
    }
}

async fn service_is_active<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &str,
) -> Result<bool, String> {
    match host_handler
        .run_command(&format!("systemctl is-active {}", name), &Privilege::None)
        .await
    {
        Ok(r) => match r.return_code {
            0 => Ok(true),
            3 => Ok(false),
            4 => Err(format!("Service not found: {}", name)),
            _ => Ok(false), // "failed" or other transient states → not active
        },
        Err(e) => Err(format!("Unable to check active state of {}: {:?}", name, e)),
    }
}

async fn service_is_enabled<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &str,
) -> Result<bool, String> {
    match host_handler
        .run_command(&format!("systemctl is-enabled {}", name), &Privilege::None)
        .await
    {
        Ok(r) => match r.return_code {
            0 => Ok(true),
            1 | 3 => Ok(false),
            4 => Err(format!("Service not found: {}", name)),
            _ => Ok(false),
        },
        Err(e) => Err(format!(
            "Unable to check enabled state of {}: {:?}",
            name, e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_service_module_block_from_yaml_str() {
        let raw = "---
- Name: nginx
  State: !Started
  Enabled: true

- Name: nginx
  State: !Stopped
  Enabled: false

- Name: nginx
  State: !Restarted

- Name: nginx
  State: !Reloaded

- Name: nginx
  Enabled: true
        ";
        let _: Vec<ServiceBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }

    #[test]
    fn check_rejects_empty_state_and_enabled() {
        let result = ServiceBlockExpectedState::builder("nginx").build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_state_only() {
        let result = ServiceBlockExpectedState::builder("nginx")
            .with_state(ServiceExpectedState::Started)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_enabled_only() {
        let result = ServiceBlockExpectedState::builder("nginx")
            .with_enabled(true)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_restarted_with_enabled() {
        let result = ServiceBlockExpectedState::builder("nginx")
            .with_state(ServiceExpectedState::Restarted)
            .with_enabled(false)
            .build();
        assert!(result.is_ok());
    }
}
