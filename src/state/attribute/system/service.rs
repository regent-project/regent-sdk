//! Service management attribute
//!
//! This module provides the `ServiceExpectedState` type for managing system services.
//!
//! **Compatible OS:**
//! - Linux (all distributions with systemd) - uses `systemctl`
//! - Windows (when `windows` feature is enabled) - uses `sc.exe` and `net` commands
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::service::{ServiceExpectedState, ServiceExpectedStatus, ServiceAction};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Ensure httpd service is running and enabled
//! let httpd = ServiceExpectedState::state(
//!     "httpd",
//!     ServiceExpectedStatus::Started,
//!     true
//! );
//!
//! // Just manage service state (running/stopped)
//! let nginx = ServiceExpectedState::state("nginx", ServiceExpectedStatus::Started, false);
//!
//! // Just manage whether service is enabled at boot
//! let mysql = ServiceExpectedState::enabled("mysql", true);
//!
//! // Manage unconditional action (restart)
//! let redis = ServiceExpectedState::restarted("redis");
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
//!   - Name: Httpd must be running and enabled
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: httpd
//!       State: Started
//!       Enabled: true
//! ```
//!
//! For state-only configuration:
//!
//! ```yaml
//! Attributes:
//!   - Name: Nginx must be stopped
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: nginx
//!       State: Stopped
//! ```
//!
//! For enabled-only configuration:
//!
//! ```yaml
//! Attributes:
//!   - Name: MySQL must be disabled at boot
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: mysql
//!       Enabled: false
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, InitSystem, LinuxFlavor, LinuxSpecifics, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Desired run-state of the service
///
/// - `Started`  / `Stopped`  — idempotent: only act if the service is not already in the target state.
///
/// # Serialization
///
/// This enum is serialized/deserialized in PascalCase:
/// - `Started` → `"Started"`
/// - `Stopped` → `"Stopped"`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceExpectedStatus {
    /// Service should be running
    Started,
    /// Service should be stopped
    Stopped,
}

/// Desired action to run on the service
///
/// - `Restarted`/ `Reloaded` — unconditional: always emit the corresponding systemctl command.
///
/// # Serialization
///
/// This enum is serialized/deserialized in PascalCase:
/// - `Restarted` → `"Restarted"`
/// - `Reloaded` → `"Reloaded"`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceAction {
    /// Service should be restarted (unconditional action)
    Restarted,
    /// Service should be reloaded (unconditional action)
    Reloaded,
}

/// Configuration for a system service
///
/// This enum represents the desired state for a system service, supporting configurations:
/// - `State`: Manage the service's running state (started/stopped) and/or boot enablement
/// - `Action`: Manage unconditional actions (restart/reload)
///
/// # YAML Representation
///
/// ## State with enabled:
/// ```yaml
/// Name: httpd
/// State: Started
/// Enabled: true
/// ```
///
/// ## State only:
/// ```yaml
/// Name: nginx
/// State: Started
/// ```
///
/// ## Enabled only:
/// ```yaml
/// Name: mysql
/// Enabled: true
/// ```
///
/// ## Action only:
/// ```yaml
/// Name: nginx
/// Action: Restarted
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all_fields = "PascalCase")]
#[serde(untagged)]
pub enum ServiceExpectedState {
    /// Manage the service's running state and/or boot enablement
    ///
    /// Note: The `enabled` field is only present in this variant to respect the semantics
    /// that enabled state is managed alongside running state.
    State {
        /// Name of the service
        name: String,
        /// Desired running state of the service (optional - can be omitted for enabled-only config)
        #[serde(default)]
        state: Option<ServiceExpectedStatus>,
        /// Whether the service should be enabled at boot
        enabled: bool,
    },
    /// Manage unconditional actions (restart/reload)
    Action {
        /// Name of the service
        name: String,
        /// Action to perform on the service
        action: ServiceAction,
    },
}

impl Timeout for ServiceExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

impl ServiceExpectedState {
    /// Create a state configuration with running state and boot enablement
    pub fn state(name: &str, state: ServiceExpectedStatus, enabled: bool) -> ServiceExpectedState {
        ServiceExpectedState::State {
            name: name.to_string(),
            state: Some(state),
            enabled,
        }
    }

    /// Create an enabled-only configuration (no state management, only enablement)
    pub fn started_and_enabled(name: &str) -> ServiceExpectedState {
        ServiceExpectedState::State {
            name: name.to_string(),
            state: Some(ServiceExpectedStatus::Started),
            enabled: true,
        }
    }

    /// Create an enabled-only configuration (no state management, only enablement)
    pub fn enabled(name: &str, enabled: bool) -> ServiceExpectedState {
        ServiceExpectedState::State {
            name: name.to_string(),
            state: None,
            enabled,
        }
    }

    /// Create a restarted action configuration
    pub fn restarted(name: &str) -> ServiceExpectedState {
        ServiceExpectedState::Action {
            name: name.to_string(),
            action: ServiceAction::Restarted,
        }
    }

    /// Create a reloaded action configuration
    pub fn reloaded(name: &str) -> ServiceExpectedState {
        ServiceExpectedState::Action {
            name: name.to_string(),
            action: ServiceAction::Reloaded,
        }
    }
}

impl Check for ServiceExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // if self.state.is_none() && self.enabled.is_none() {
        //     return Err(RegentError::IncoherentExpectedState(
        //         "At least one of State or Enabled must be set.".to_string(),
        //     ));
        // }
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
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but service management is only supported on Linux with systemd or Windows (with windows feature)",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for ServiceExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        // Determine the effective OS kind - assume Linux if HostProperties is None
        let os_kind = host_properties
            .as_ref()
            .map(|props| props.os_kind())
            .unwrap_or(&OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Debian,
                init_system: InitSystem::Systemd,
            }));

        // Check OS-dependent prerequisites
        match os_kind {
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => {
                // Check if sc.exe is available on Windows
                let command_available = host_handler
                    .is_this_command_available("sc", privilege)
                    .await
                    .unwrap_or(false);

                if !command_available {
                    return Err(RegentError::FailedDryRunEvaluation(
                        "Service management commands (sc) are not available on this Windows host"
                            .to_string(),
                    ));
                }
            }
            OsKind::Linux(_) => {
                // Check if systemctl is available on Linux
                let command_available = host_handler
                    .is_this_command_available("systemctl", privilege)
                    .await
                    .unwrap_or(false);

                if !command_available {
                    return Err(RegentError::FailedDryRunEvaluation(
                        "Service management commands (systemctl) are not available on this Linux host".to_string(),
                    ));
                }
            }
            OsKind::FreeBsd(_) | OsKind::MacOs(_) | OsKind::Unknown => {}
        }

        // Match on OS kind to determine service checking behavior
        let mut remediations: Vec<Remediation> = Vec::new();

        match &self {
            Self::State {
                name,
                state,
                enabled,
            } => {
                // TODO : factorize this
                // Handle state (started/stopped) with optional enabled
                match os_kind {
                    #[cfg(feature = "windows")]
                    OsKind::Windows(_) => {
                        // Handle state if present
                        if let Some(expected_state) = state {
                            match windows_service_is_active(host_handler, &name).await {
                                Ok(current_service_activity) => {
                                    match (current_service_activity, expected_state) {
                                        (
                                            ServiceActivityStatus::Active,
                                            ServiceExpectedStatus::Started,
                                        )
                                        | (
                                            ServiceActivityStatus::Inactive,
                                            ServiceExpectedStatus::Stopped,
                                        ) => {
                                            // Service already in expected state, nothing to do
                                        }
                                        (
                                            ServiceActivityStatus::Active,
                                            ServiceExpectedStatus::Stopped,
                                        ) => {
                                            remediations.push(Remediation::Service(
                                                ServiceApiCall::from(
                                                    ServiceModuleInternalApiCall::Stop(
                                                        name.clone(),
                                                    ),
                                                    privilege.clone(),
                                                ),
                                            ));
                                        }
                                        (
                                            ServiceActivityStatus::Inactive,
                                            ServiceExpectedStatus::Started,
                                        ) => {
                                            remediations.push(Remediation::Service(
                                                ServiceApiCall::from(
                                                    ServiceModuleInternalApiCall::Start(
                                                        name.clone(),
                                                    ),
                                                    privilege.clone(),
                                                ),
                                            ));
                                        }
                                        (
                                            ServiceActivityStatus::ServiceNotFound,
                                            _expected_state,
                                        ) => {
                                            return Ok(
                                                AttributeComplianceAssessment::NonCompliantFatal(
                                                    format!("service not found"),
                                                ),
                                            );
                                        }
                                        (
                                            ServiceActivityStatus::UnsupportedCase(details),
                                            _expected_state,
                                        ) => {
                                            return Ok(
                                                AttributeComplianceAssessment::NonCompliantFatal(
                                                    format!("{details}"),
                                                ),
                                            );
                                        }
                                    }
                                }
                                Err(error_details) => {
                                    return Err(RegentError::FailedTaskDryRun(format!(
                                        "Unable to check service activity : {error_details}"
                                    )));
                                }
                            }
                        }

                        // Handle enabled
                        match windows_service_is_enabled(host_handler, &name).await {
                            Ok(current_service_enabling) => {
                                match (current_service_enabling, *enabled) {
                                    (ServiceEnablingStatus::Enabled, true)
                                    | (ServiceEnablingStatus::Disabled, false) => {
                                        // Service already in expected state, nothing to do
                                    }
                                    (ServiceEnablingStatus::Enabled, false) => {
                                        remediations.push(Remediation::Service(
                                            ServiceApiCall::from(
                                                ServiceModuleInternalApiCall::Disable(name.clone()),
                                                privilege.clone(),
                                            ),
                                        ));
                                        remediations.push(Remediation::Service(
                                            ServiceApiCall::from(
                                                ServiceModuleInternalApiCall::Enable(name.clone()),
                                                privilege.clone(),
                                            ),
                                        ));
                                    }
                                    (ServiceEnablingStatus::Disabled, true) => {
                                        remediations.push(Remediation::Service(
                                            ServiceApiCall::from(
                                                ServiceModuleInternalApiCall::Enable(name.clone()),
                                                privilege.clone(),
                                            ),
                                        ));
                                    }
                                    (ServiceEnablingStatus::ServiceNotFound, _expected_state) => {
                                        return Ok(
                                            AttributeComplianceAssessment::NonCompliantFatal(
                                                format!("service not found"),
                                            ),
                                        );
                                    }
                                    (
                                        ServiceEnablingStatus::UnsupportedCase(details),
                                        _expected_state,
                                    ) => {
                                        return Ok(
                                            AttributeComplianceAssessment::NonCompliantFatal(
                                                format!("{details}"),
                                            ),
                                        );
                                    }
                                }
                            }
                            Err(error_details) => {
                                return Err(RegentError::FailedTaskDryRun(format!(
                                    "Unable to check service activity : {error_details}"
                                )));
                            }
                        }
                    }
                    OsKind::Linux(_) => {
                        // Handle state if present
                        if let Some(expected_state) = state {
                            match service_is_active(host_handler, &name).await {
                                Ok(current_service_activity) => {
                                    match (current_service_activity, expected_state) {
                                        (
                                            ServiceActivityStatus::Active,
                                            ServiceExpectedStatus::Started,
                                        )
                                        | (
                                            ServiceActivityStatus::Inactive,
                                            ServiceExpectedStatus::Stopped,
                                        ) => {
                                            // Service already in expected state, nothing to do
                                        }
                                        (
                                            ServiceActivityStatus::Active,
                                            ServiceExpectedStatus::Stopped,
                                        ) => {
                                            remediations.push(Remediation::Service(
                                                ServiceApiCall::from(
                                                    ServiceModuleInternalApiCall::Stop(
                                                        name.clone(),
                                                    ),
                                                    privilege.clone(),
                                                ),
                                            ));
                                        }
                                        (
                                            ServiceActivityStatus::Inactive,
                                            ServiceExpectedStatus::Started,
                                        ) => {
                                            remediations.push(Remediation::Service(
                                                ServiceApiCall::from(
                                                    ServiceModuleInternalApiCall::Start(
                                                        name.clone(),
                                                    ),
                                                    privilege.clone(),
                                                ),
                                            ));
                                        }
                                        (
                                            ServiceActivityStatus::ServiceNotFound,
                                            _expected_state,
                                        ) => {
                                            return Ok(
                                                AttributeComplianceAssessment::NonCompliantFatal(
                                                    format!("service not found"),
                                                ),
                                            );
                                        }
                                        (
                                            ServiceActivityStatus::UnsupportedCase(details),
                                            _expected_state,
                                        ) => {
                                            return Ok(
                                                AttributeComplianceAssessment::NonCompliantFatal(
                                                    format!("{details}"),
                                                ),
                                            );
                                        }
                                    }
                                }
                                Err(error_details) => {
                                    return Err(RegentError::FailedTaskDryRun(format!(
                                        "Unable to check service activity : {error_details}"
                                    )));
                                }
                            }
                        }

                        // Handle enabled
                        match service_is_enabled(host_handler, &name).await {
                            Ok(current_service_enabling) => {
                                match (current_service_enabling, *enabled) {
                                    (ServiceEnablingStatus::Enabled, true)
                                    | (ServiceEnablingStatus::Disabled, false) => {
                                        // Service already in expected state, nothing to do
                                    }
                                    (ServiceEnablingStatus::Enabled, false) => {
                                        remediations.push(Remediation::Service(
                                            ServiceApiCall::from(
                                                ServiceModuleInternalApiCall::Disable(name.clone()),
                                                privilege.clone(),
                                            ),
                                        ));
                                        remediations.push(Remediation::Service(
                                            ServiceApiCall::from(
                                                ServiceModuleInternalApiCall::Enable(name.clone()),
                                                privilege.clone(),
                                            ),
                                        ));
                                    }
                                    (ServiceEnablingStatus::Disabled, true) => {
                                        remediations.push(Remediation::Service(
                                            ServiceApiCall::from(
                                                ServiceModuleInternalApiCall::Enable(name.clone()),
                                                privilege.clone(),
                                            ),
                                        ));
                                    }
                                    (ServiceEnablingStatus::ServiceNotFound, _expected_state) => {
                                        return Ok(
                                            AttributeComplianceAssessment::NonCompliantFatal(
                                                format!("service not found"),
                                            ),
                                        );
                                    }
                                    (
                                        ServiceEnablingStatus::UnsupportedCase(details),
                                        _expected_state,
                                    ) => {
                                        return Ok(
                                            AttributeComplianceAssessment::NonCompliantFatal(
                                                format!("{details}"),
                                            ),
                                        );
                                    }
                                }
                            }
                            Err(error_details) => {
                                return Err(RegentError::FailedTaskDryRun(format!(
                                    "Unable to check service activity : {error_details}"
                                )));
                            }
                        }
                    }
                    OsKind::FreeBsd(_) | OsKind::MacOs(_) | OsKind::Unknown => {
                        return Err(RegentError::FailedDryRunEvaluation(format!(
                            "Service management is not supported on {:?}",
                            os_kind
                        )));
                    }
                }
            }
            Self::Action { name, action } => {
                // Handle unconditional actions (restart/reload)
                match os_kind {
                    #[cfg(feature = "windows")]
                    OsKind::Windows(_) => {
                        match &action {
                            ServiceAction::Restarted => {
                                // Unconditional — always restart.
                                remediations.push(Remediation::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Restart(name.clone()),
                                    privilege.clone(),
                                )));
                            }
                            ServiceAction::Reloaded => {
                                // Unconditional — always reload.
                                remediations.push(Remediation::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Reload(name.clone()),
                                    privilege.clone(),
                                )));
                            }
                        }
                    }
                    OsKind::Linux(_) => {
                        match &action {
                            ServiceAction::Restarted => {
                                // Unconditional — always restart.
                                remediations.push(Remediation::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Restart(name.clone()),
                                    privilege.clone(),
                                )));
                            }
                            ServiceAction::Reloaded => {
                                // Unconditional — always reload.
                                remediations.push(Remediation::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Reload(name.clone()),
                                    privilege.clone(),
                                )));
                            }
                        }
                    }
                    OsKind::FreeBsd(_) | OsKind::MacOs(_) | OsKind::Unknown => {
                        return Err(RegentError::FailedDryRunEvaluation(format!(
                            "Service management is not supported on {:?}",
                            os_kind
                        )));
                    }
                }
            }
        }

        if remediations.is_empty() {
            Ok(AttributeComplianceAssessment::Compliant)
        } else {
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(remediations)?,
            ))
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
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but service management is only supported on Linux with systemd or Windows (with windows feature)",
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
        // Early check: verify we're on a compatible host
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        // Determine the effective OS kind - assume Linux if HostProperties is None
        let os_kind = host_properties
            .as_ref()
            .map(|props| props.os_kind())
            .unwrap_or(&OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Debian,
                init_system: InitSystem::Systemd,
            }));

        // Match on OS kind to execute the appropriate command
        match os_kind {
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => {
                // Build Windows command
                let cmd = match &self.api_call {
                    ServiceModuleInternalApiCall::Start(s) => format!("net start {}", s),
                    ServiceModuleInternalApiCall::Stop(s) => format!("net stop {}", s),
                    ServiceModuleInternalApiCall::Restart(s) => {
                        // Windows doesn't have a direct restart command, we stop then start
                        format!("net stop {} && net start {}", s, s)
                    }
                    ServiceModuleInternalApiCall::Reload(s) => {
                        // Windows doesn't have a direct reload command
                        // This might not be supported for all services
                        format!("sc control {} 128", s) // Sends a reload parameter, but not all services support this
                    }
                    ServiceModuleInternalApiCall::Enable(s) => {
                        format!("sc config {} start= auto", s)
                    }
                    ServiceModuleInternalApiCall::Disable(s) => {
                        format!("sc config {} start= disabled", s)
                    }
                };

                // Execute Windows command
                let result = host_handler.run_windows_command(&cmd).await;

                match result {
                    Ok(result) => {
                        if result.return_code == 0 {
                            Ok(InternalApiCallOutcome::Success(None))
                        } else {
                            Ok(InternalApiCallOutcome::Failure(format!(
                                "RC: {}, STDOUT: {}, STDERR: {}",
                                result.return_code, result.stdout, result.stderr
                            )))
                        }
                    }
                    Err(e) => Ok(InternalApiCallOutcome::Failure(format!(
                        "Command execution failed: {:?}",
                        e
                    ))),
                }
            }
            OsKind::Linux(_) => {
                // Build Linux command
                let cmd = match &self.api_call {
                    ServiceModuleInternalApiCall::Start(s) => format!("systemctl start {}", s),
                    ServiceModuleInternalApiCall::Stop(s) => format!("systemctl stop {}", s),
                    ServiceModuleInternalApiCall::Restart(s) => format!("systemctl restart {}", s),
                    ServiceModuleInternalApiCall::Reload(s) => format!("systemctl reload {}", s),
                    ServiceModuleInternalApiCall::Enable(s) => format!("systemctl enable {}", s),
                    ServiceModuleInternalApiCall::Disable(s) => format!("systemctl disable {}", s),
                };

                // Execute Linux command
                let result = host_handler.run_command(&cmd, &self.privilege).await;

                match result {
                    Ok(result) => {
                        if result.return_code == 0 {
                            Ok(InternalApiCallOutcome::Success(None))
                        } else {
                            Ok(InternalApiCallOutcome::Failure(format!(
                                "RC: {}, STDOUT: {}, STDERR: {}",
                                result.return_code, result.stdout, result.stderr
                            )))
                        }
                    }
                    Err(e) => Ok(InternalApiCallOutcome::Failure(format!(
                        "Command execution failed: {:?}",
                        e
                    ))),
                }
            }
            OsKind::FreeBsd(_) | OsKind::MacOs(_) | OsKind::Unknown => {
                Err(RegentError::FailedDryRunEvaluation(format!(
                    "Service management is not supported on {:?}",
                    os_kind
                )))
            }
        }
    }
}

async fn service_is_active<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &str,
) -> Result<ServiceActivityStatus, String> {
    match host_handler
        .run_command(&format!("systemctl is-active {}", name), &Privilege::None)
        .await
    {
        Ok(r) => match r.return_code {
            0 => Ok(ServiceActivityStatus::Active),
            3 => Ok(ServiceActivityStatus::Inactive),
            4 => Ok(ServiceActivityStatus::ServiceNotFound),
            _ => Ok(ServiceActivityStatus::UnsupportedCase(format!("{:?}", r))),
        },
        Err(e) => Err(format!("Unable to check active state of {}: {:?}", name, e)),
    }
}

async fn service_is_enabled<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &str,
) -> Result<ServiceEnablingStatus, String> {
    match host_handler
        .run_command(&format!("systemctl is-enabled {}", name), &Privilege::None)
        .await
    {
        Ok(r) => match r.return_code {
            0 => Ok(ServiceEnablingStatus::Enabled),
            1 | 3 => Ok(ServiceEnablingStatus::Disabled),
            4 => Ok(ServiceEnablingStatus::ServiceNotFound),
            _ => Ok(ServiceEnablingStatus::UnsupportedCase(format!("{:?}", r))),
        },
        Err(e) => Err(format!(
            "Unable to check enabled state of {}: {:?}",
            name, e
        )),
    }
}

#[cfg(feature = "windows")]
async fn windows_service_is_active<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &str,
) -> Result<ServiceActivityStatus, String> {
    match host_handler
        .run_windows_command(&format!("sc query {}", name))
        .await
    {
        Ok(r) => {
            // sc query returns 0 for success, but we need to parse the output
            // The output contains "STATE" line which shows the service state
            if r.return_code != 0 {
                // Service might not exist or other error
                if r.stdout.contains("does not exist") || r.stderr.contains("does not exist") {
                    return Ok(ServiceActivityStatus::ServiceNotFound);
                } else {
                    return Ok(ServiceActivityStatus::UnsupportedCase(format!(
                        "Unable to check service enabling status (command issue): {:?}",
                        r
                    )));
                }
            }

            // Parse the output for service state
            // Looking for lines like: "STATE              : 4  RUNNING"
            let output = r.stdout.to_lowercase();
            if output.contains("running") {
                Ok(ServiceActivityStatus::Active)
            } else if output.contains("stopped") || output.contains("pending") {
                Ok(ServiceActivityStatus::Inactive)
            } else {
                Ok(ServiceActivityStatus::UnsupportedCase(format!(
                    "Unable to check service activity (output parsing issue): {:?}",
                    r
                )))
            }
        }
        Err(e) => Err(format!("Unable to check active state of {}: {:?}", name, e)),
    }
}

#[cfg(feature = "windows")]
async fn windows_service_is_enabled<Handler: HostHandler>(
    host_handler: &mut Handler,
    name: &str,
) -> Result<ServiceEnablingStatus, String> {
    match host_handler
        .run_windows_command(&format!("sc qc {}", name))
        .await
    {
        Ok(r) => {
            // sc qc (query configuration) returns information about the service
            // We need to look for the START_TYPE line
            if r.return_code != 0 {
                if r.stdout.contains("does not exist") || r.stderr.contains("does not exist") {
                    return Ok(ServiceEnablingStatus::ServiceNotFound);
                } else {
                    return Ok(ServiceEnablingStatus::UnsupportedCase(format!(
                        "Unable to check service enabling status (command issue): {:?}",
                        r
                    )));
                }
            }

            // Parse the output for start type
            // Looking for lines like: "START_TYPE       : 2   AUTO_START"
            let output = r.stdout.to_lowercase();
            if output.contains("auto_start") || output.contains("2") {
                Ok(ServiceEnablingStatus::Enabled)
            } else if output.contains("disabled") || output.contains("3") || output.contains("4") {
                Ok(ServiceEnablingStatus::Disabled)
            } else {
                Ok(ServiceEnablingStatus::UnsupportedCase(format!(
                    "Unable to check service enabling status (output parsing issue): {:?}",
                    r
                )))
            }
        }
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
  State: Started
  Enabled: true

- Name: nginx
  State: Stopped
  Enabled: false

- Name: nginx
  Action: Restarted

- Name: nginx
  Action: Reloaded

- Name: nginx
  Enabled: true
        ";
        let _: Vec<ServiceExpectedState> = yaml_serde::from_str(raw).unwrap();
    }
}

enum ServiceActivityStatus {
    Active,
    Inactive,
    ServiceNotFound,
    UnsupportedCase(String),
}

enum ServiceEnablingStatus {
    Enabled,
    Disabled,
    ServiceNotFound,
    UnsupportedCase(String),
}
