//! Hostname management attribute
//!
//! This module provides the `HostnameBlockExpectedState` type for setting and managing
//! the system hostname.
//!
//! **Compatible OS:**
//! - Linux, macOS, FreeBSD - uses hostnamectl or /etc/hostname
//! - Windows (when `windows` feature is enabled) - uses Windows hostname commands
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::hostname::{HostnameBlockExpectedState, HostnameMethod};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Set hostname using systemd method
//! let hostname = HostnameBlockExpectedState::builder("myserver.example.com")
//!     .with_method(HostnameMethod::Systemd)
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::hostname(hostname, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Hostname must be myserver.example.com
//!     Privilege: !WithSudo
//!     Detail: !Hostname
//!       Name: myserver.example.com
//!       Method: !Systemd
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, LinuxFlavor, LinuxSpecifics, OsKind, InitSystem};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Method for setting the hostname
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum HostnameMethod {
    /// Uses hostnamectl set-hostname (systemd, persistent across reboots)
    Systemd,
    /// Uses hostname command + writes /etc/hostname (non-systemd systems)
    Generic,
    #[cfg(feature = "windows")]
    /// Uses Windows hostname command (Windows only)
    Windows,
}

/// Configuration for managing the system hostname
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct HostnameBlockExpectedState {
    /// The desired hostname
    name: String,
    /// Method to use for setting the hostname (defaults to auto-detection)
    method: Option<HostnameMethod>,
}

impl Timeout for HostnameBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl HostnameBlockExpectedState {
    pub fn builder(hostname: &str) -> HostnameBlockExpectedState {
        HostnameBlockExpectedState {
            name: hostname.to_string(),
            method: None,
        }
    }

    pub fn with_method(&mut self, method: HostnameMethod) -> &mut Self {
        self.method = Some(method);
        self
    }

    pub fn build(&self) -> Result<HostnameBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for HostnameBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.name.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "Hostname cannot be empty.".to_string(),
            ));
        } else if let Err(details) = is_valid_hostname(&self.name) {
            return Err(RegentError::IncoherentExpectedState(details));
        }

        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) | OsKind::MacOs(_) | OsKind::FreeBsd(_) => Ok(()),
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but hostname management is only supported on Unix-like systems or Windows (with windows feature)",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for HostnameBlockExpectedState {
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

        // Get current hostname based on OS
        let current_hostname = match os_kind {
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => {
                match host_handler
                    .run_windows_command("hostname")
                    .await
                {
                    Ok(result) => {
                        if result.return_code != 0 {
                            return Err(RegentError::FailedDryRunEvaluation(
                                "Failed to get current hostname on Windows".to_string(),
                            ));
                        }
                        result.stdout.trim().to_string()
                    }
                    Err(e) => {
                        return Err(RegentError::FailedDryRunEvaluation(format!(
                            "Unable to get hostname on Windows: {:?}",
                            e
                        )));
                    }
                }
            }
            OsKind::Linux(_) | OsKind::MacOs(_) | OsKind::FreeBsd(_) => {
                match host_handler
                    .run_command("cat /etc/hostname", &Privilege::None)
                    .await
                {
                    Ok(result) => {
                        if result.return_code != 0 {
                            return Err(RegentError::FailedDryRunEvaluation(
                                "Failed to get current hostname".to_string(),
                            ));
                        }
                        result.stdout.trim().to_string()
                    }
                    Err(e) => {
                        return Err(RegentError::FailedDryRunEvaluation(format!(
                            "Unable to get hostname: {:?}",
                            e
                        )));
                    }
                }
            }
            OsKind::Unknown => {
                return Err(RegentError::FailedDryRunEvaluation(
                    "Cannot determine hostname on unknown OS".to_string(),
                ));
            }
        };

        if current_hostname == self.name {
            return Ok(AttributeComplianceAssessment::Compliant);
        }

        // Determine method based on OS and user preference
        let method = match os_kind {
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => {
                // On Windows, only Windows method makes sense
                self.method.clone().unwrap_or(HostnameMethod::Windows)
            }
            OsKind::Linux(_) => {
                // On Linux, use user preference or default to Systemd
                self.method.clone().unwrap_or(HostnameMethod::Systemd)
            }
            OsKind::MacOs(_) | OsKind::FreeBsd(_) => {
                // On macOS and FreeBSD, Generic method is more appropriate
                self.method.clone().unwrap_or(HostnameMethod::Generic)
            }
            OsKind::Unknown => {
                return Err(RegentError::FailedDryRunEvaluation(
                    "Cannot set hostname on unknown OS".to_string(),
                ));
            }
        };

        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(vec![
                Remediation::Hostname(HostnameApiCall::from(
                    HostnameModuleInternalApiCall::SetHostname {
                        name: self.name.clone(),
                        method,
                    },
                    privilege.clone(),
                )),
            ]).unwrap()
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum HostnameModuleInternalApiCall {
    SetHostname {
        name: String,
        method: HostnameMethod,
    },
}

impl std::fmt::Display for HostnameModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostnameModuleInternalApiCall::SetHostname { name, .. } => {
                write!(f, "set hostname to {}", name)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostnameApiCall {
    pub api_call: HostnameModuleInternalApiCall,
    privilege: Privilege,
}

impl HostnameApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            HostnameModuleInternalApiCall::SetHostname { name, .. } => {
                format!("Set hostname to {}", name)
            }
        }
    }

    fn from(api_call: HostnameModuleInternalApiCall, privilege: Privilege) -> HostnameApiCall {
        HostnameApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for HostnameApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) | OsKind::MacOs(_) | OsKind::FreeBsd(_) => Ok(()),
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but hostname management is only supported on Unix-like systems or Windows (with windows feature)",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for HostnameApiCall {
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

        // Match on OS kind to execute the appropriate hostname command
        match os_kind {
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => {
                // Extract hostname and method from the API call
                let (name, method) = match &self.api_call {
                    HostnameModuleInternalApiCall::SetHostname { name, method } => (name, method),
                };

                // Build Windows hostname command
                let cmd = match method {
                    HostnameMethod::Windows => format!("hostname {}", name),
                    // For Windows, we'll use the Windows method even if user specified systemd/generic
                    HostnameMethod::Systemd | HostnameMethod::Generic => format!("hostname {}", name),
                };

                // Execute Windows command
                let cmd_result = host_handler
                    .run_windows_command(&cmd)
                    .await;

                match cmd_result {
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
            OsKind::Linux(_) | OsKind::MacOs(_) | OsKind::FreeBsd(_) => {
                // Extract hostname and method from the API call
                let (name, method) = match &self.api_call {
                    HostnameModuleInternalApiCall::SetHostname { name, method } => (name, method),
                };

                // Build Unix hostname command
                let cmd = match method {
                    HostnameMethod::Systemd => format!("hostnamectl set-hostname {}", name),
                    HostnameMethod::Generic => {
                        format!("hostname {} && echo {} > /etc/hostname", name, name)
                    }
                    #[cfg(feature = "windows")]
                    HostnameMethod::Windows => {
                        // On Unix, use systemd as fallback for Windows method
                        format!("hostnamectl set-hostname {}", name)
                    }
                };

                // Execute Unix command
                let cmd_result = host_handler
                    .run_command(&cmd, &self.privilege)
                    .await;

                match cmd_result {
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
            OsKind::Unknown => {
                Err(RegentError::FailedDryRunEvaluation(
                    "Cannot set hostname on unknown OS".to_string(),
                ))
            }
        }
    }
}

// Checking RFC952 and RFC1123 compliance
fn is_valid_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty() {
        return Err("hostname is empty".to_string());
    }

    if hostname.len() > 253 {
        return Err("hostname too long (max 253 characters)".to_string());
    }

    if hostname.contains("--") {
        return Err("hostname forbidden to have --".to_string());
    }

    for element in hostname.split('.') {
        if element.is_empty() {
            return Err("one empty element between 2 points".to_string());
        } else if element.len() > 63 {
            return Err("element too long (max 63 characters)".to_string());
        }

        for (i, c) in element.chars().enumerate() {
            match c {
                'a'..='z' | '0'..='9' => (),
                '-' => {
                    if i == 0 {
                        return Err("element forbidden to start with -".to_string());
                    } else if i == element.len() - 1 {
                        return Err("element forbidden to end with -".to_string());
                    }
                }
                forbidden_character => {
                    return Err(format!("forbidden character : {forbidden_character}"));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_hostname_module_block_from_yaml_str() {
        let raw_attributes = "---
- Name: myserver.example.com

- Name: webserver
  Method: !Systemd

- Name: oldbox
  Method: !Generic
        ";

        let _attributes: Vec<HostnameBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();
    }

    #[test]
    fn check_rejects_empty_hostname() {
        let result = HostnameBlockExpectedState::builder("").build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_valid_hostname() {
        let result = HostnameBlockExpectedState::builder("myserver.example.com").build();
        assert!(result.is_ok());
    }

    #[test]
    fn is_valid_hostname_rejects_empty_hostname() {
        assert!(is_valid_hostname("").is_err());
    }

    #[test]
    fn is_valid_hostname_rejects_hostname_longer_than_253_chars() {
        let long_hostname = "a".repeat(254);
        assert!(is_valid_hostname(&long_hostname).is_err());
    }

    #[test]
    fn is_valid_hostname_rejects_hostname_with_consecutive_dashes() {
        assert!(is_valid_hostname("my--server").is_err());
    }

    #[test]
    fn is_valid_hostname_rejects_hostname_with_leading_or_trailing_dashes() {
        assert!(is_valid_hostname("-myserver").is_err());
        assert!(is_valid_hostname("myserver-").is_err());
    }

    #[test]
    fn is_valid_hostname_rejects_hostname_with_invalid_chars() {
        assert!(is_valid_hostname("my!server").is_err());
        assert!(is_valid_hostname("my@server").is_err());
    }

    #[test]
    fn is_valid_hostname_accepts_valid_hostname() {
        assert!(is_valid_hostname("myserver").is_ok());
        assert!(is_valid_hostname("myserver.example.com").is_ok());
    }

    #[test]
    fn is_valid_hostname_rejects_hostname_with_labels_longer_than_63_chars() {
        let long_label = format!("element-1.{}.element-2", "a".repeat(64));
        assert!(is_valid_hostname(&format!("{}.example.com", long_label)).is_err());
    }
}
