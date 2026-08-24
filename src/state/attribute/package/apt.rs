//! APT package management attribute
//!
//! This module provides the `AptExpectedState` type for managing Debian/Ubuntu packages
//! using the APT package manager.
//!
//! **Compatible OS:** Linux (Debian-based distributions: Debian, Ubuntu, etc.)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::apt::{AptExpectedState, PackageExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install a package
//! let apache = AptExpectedState::package_state("apache2", PackageExpectedState::Present);
//!
//! // Remove a package
//! let nginx = AptExpectedState::package_state("nginx", PackageExpectedState::Absent);
//!
//! // Trigger a full system upgrade
//! let upgrade = AptExpectedState::full_system_upgrade();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::apt(apache, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Apache2 package must be present
//!     Privilege: !WithSudo
//!     Detail: !Apt
//!       Package: apache2
//!       State: Present
//! ```
//!
//! For a full system upgrade:
//!
//! ```yaml
//! Attributes:
//!   - Name: All packages must be up to date
//!     Privilege: !WithSudo
//!     Detail: !Apt
//!       SystemUpToDate
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, LinuxFlavor, LinuxSpecifics, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AptModuleInternalApiCall {
    Install(String),
    Remove(String),
    Upgrade,
}

impl std::fmt::Display for AptModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AptModuleInternalApiCall::Install(package) => write!(f, "install {}", package),
            AptModuleInternalApiCall::Remove(package) => write!(f, "remove {}", package),
            AptModuleInternalApiCall::Upgrade => write!(f, "upgrade"),
        }
    }
}

/// Desired state of a package
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PackageExpectedState {
    /// Package should be installed
    Present,
    /// Package should be removed
    Absent,
}

/// Configuration for APT package management
///
/// This enum represents the desired state for APT package management on Debian/Ubuntu systems.
/// It supports two main operations:
/// - Managing individual packages (install/remove) via the `PackageState` variant
/// - Performing a full system upgrade via the `SystemUpToDate` variant
///
/// # YAML Representation
///
/// ## Package management:
/// ```yaml
/// Package: nginx
/// State: Present  # or Absent to remove
/// ```
///
/// ## Full system upgrade:
/// ```yaml
/// SystemUpToDate
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all_fields = "PascalCase")]
#[serde(deny_unknown_fields)]
pub enum AptExpectedState {
    /// Perform a full system upgrade (apt-get update && apt-get upgrade)
    SystemUpToDate,
    /// Manage a specific package's state
    #[serde(untagged)]
    PackageState {
        /// Name of the package to manage
        package: String,
        /// Desired state of the package
        state: PackageExpectedState,
    },
}

impl Timeout for AptExpectedState {
    fn default_timeout(&self) -> Duration {
        match self {
            Self::SystemUpToDate => Duration::from_secs(300),
            Self::PackageState {
                package: _,
                state: _,
            } => Duration::from_secs(60),
        }
    }
}

impl AptExpectedState {
    pub fn full_system_upgrade() -> AptExpectedState {
        AptExpectedState::SystemUpToDate
    }

    pub fn package_state(package: &str, state: PackageExpectedState) -> AptExpectedState {
        AptExpectedState::PackageState {
            package: package.to_string(),
            state,
        }
    }
}

impl Check for AptExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Debian,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but APT is only supported on Debian-based Linux distributions",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for AptExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Linux with Debian flavor)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let apt_available = match host_handler
            .is_this_command_available("apt-get", &Privilege::None)
            .await
        {
            Ok(availability) => availability,
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "{:?}",
                    details
                )));
            }
        };
        let dpkg_available = match host_handler
            .is_this_command_available("dpkg", &Privilege::None)
            .await
        {
            Ok(availability) => availability,
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "{:?}",
                    details
                )));
            }
        };

        if !apt_available || !dpkg_available {
            return Err(RegentError::FailedDryRunEvaluation(
                "APT not working on this host. Is this really a debian-flavored linux distribution ?"
                    .to_string(),
            ));
        }

        let mut remediations: Vec<Remediation> = Vec::new();

        match &self {
            Self::SystemUpToDate => {
                match host_handler
                    .run_command(
                        &format!("apt-get update -y && apt-get -s -u upgrade | grep -q \"^Inst\""),
                        &Privilege::None,
                    )
                    .await
                {
                    Ok(r) => match r.return_code {
                        0 => {
                            // updates are available
                            remediations.push(Remediation::Apt(AptApiCall::from(
                                AptModuleInternalApiCall::Upgrade,
                                privilege.clone(),
                            )));
                        }
                        1 => {
                            // No update available, nothing to do
                        }
                        _ => {
                            // Something else happened -> error
                            return Err(RegentError::FailedDryRunEvaluation(format!(
                                "Unable to check available updates: {:?}",
                                r
                            )));
                        }
                    },
                    Err(e) => {
                        return Err(RegentError::FailedDryRunEvaluation(format!(
                            "Unable to check available updates: {:?}",
                            e
                        )));
                    }
                }
            }
            Self::PackageState {
                package,
                state: expected_state,
            } => {
                let package_is_currently_installed =
                    is_package_installed(host_handler, package).await;

                match (package_is_currently_installed, expected_state) {
                    (true, PackageExpectedState::Present) => {} // Nothing to do
                    (true, PackageExpectedState::Absent) => {
                        // Package is present and needs to be removed
                        remediations.push(Remediation::Apt(AptApiCall::from(
                            AptModuleInternalApiCall::Remove(package.clone()),
                            privilege.clone(),
                        )));
                    }
                    (false, PackageExpectedState::Present) => {
                        // Package is absent and needs to be installed
                        remediations.push(Remediation::Apt(AptApiCall::from(
                            AptModuleInternalApiCall::Install(package.clone()),
                            privilege.clone(),
                        )));
                    }
                    (false, PackageExpectedState::Absent) => {} // Nothing to do
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
pub struct AptApiCall {
    pub api_call: AptModuleInternalApiCall,
    privilege: Privilege,
}

impl Check for AptApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Debian,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but APT is only supported on Debian-based Linux distributions",
                incompatible_os_kind
            ))),
        }
    }
}

impl AptApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            AptModuleInternalApiCall::Install(package_name) => {
                return format!("Install - {}", package_name);
            }
            AptModuleInternalApiCall::Remove(package_name) => {
                return format!("Remove - {}", package_name);
            }
            AptModuleInternalApiCall::Upgrade => {
                return String::from("Upgrade");
            }
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for AptApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Linux with Debian flavor)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let (cmd, privilege, package_name) = match &self.api_call {
            AptModuleInternalApiCall::Install(package_name) => (
                format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y {}",
                    package_name
                ),
                &self.privilege,
                Some(package_name.clone()),
            ),
            AptModuleInternalApiCall::Remove(package_name) => (
                format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y {}",
                    package_name
                ),
                &self.privilege,
                Some(package_name.clone()),
            ),
            AptModuleInternalApiCall::Upgrade => (
                "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y".to_string(),
                &self.privilege,
                None,
            ),
        };

        let cmd_result = host_handler
            .run_command(cmd.as_str(), privilege)
            .await
            .unwrap();

        if cmd_result.return_code == 0 {
            // Post-install verification: verify the package state matches the expected operation
            if let Some(pkg_name) = &package_name {
                let verification_result = match &self.api_call {
                    AptModuleInternalApiCall::Install(_) => {
                        // Verify the package is now installed
                        is_package_installed(host_handler, pkg_name).await
                    }
                    AptModuleInternalApiCall::Remove(_) => {
                        // Verify the package is now removed
                        !is_package_installed(host_handler, pkg_name).await
                    }
                    AptModuleInternalApiCall::Upgrade => {
                        // Upgrade is a system-wide operation, can't easily verify individual packages
                        // Just return success based on the command result
                        true
                    }
                };

                if verification_result {
                    Ok(InternalApiCallOutcome::Success(None))
                } else {
                    Ok(InternalApiCallOutcome::Failure(format!(
                        "Command succeeded but post-verification failed: package {} state does not match expected",
                        pkg_name
                    )))
                }
            } else {
                // For upgrade operations without specific package verification
                Ok(InternalApiCallOutcome::Success(None))
            }
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC : {}, STDOUT : {}, STDERR : {}",
                cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
            )))
        }
    }
}

impl AptApiCall {
    fn from(api_call: AptModuleInternalApiCall, privilege: Privilege) -> AptApiCall {
        AptApiCall {
            api_call,
            privilege,
        }
    }
}

async fn is_package_installed<Handler: HostHandler>(
    host_handler: &mut Handler,
    package: &str,
) -> bool {
    let test = host_handler
        .run_command(format!("dpkg -s {}", package).as_str(), &Privilege::None)
        .await
        .unwrap();

    if test.return_code == 0 { true } else { false }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_apt_module_block_from_yaml_str() {
        let raw_attributes = "---
- SystemUpToDate

- Package: apache2
  State: Present

- Package: apache2
  State: Absent
    ";

        let attributes: Vec<AptExpectedState> = yaml_serde::from_str(raw_attributes).unwrap();

        assert_eq!(attributes[0], AptExpectedState::SystemUpToDate);

        assert_eq!(
            attributes[1],
            AptExpectedState::PackageState {
                package: "apache2".to_string(),
                state: PackageExpectedState::Present
            }
        );

        assert_eq!(
            attributes[2],
            AptExpectedState::PackageState {
                package: "apache2".to_string(),
                state: PackageExpectedState::Absent
            }
        );
    }

    #[test]
    fn rejecting_incorrect_apt_module_block_from_yaml_str() {
        // Test that Package without State fails to deserialize
        let raw_attribute = "---
Package: apache2
    ";
        assert!(yaml_serde::from_str::<AptExpectedState>(raw_attribute).is_err());

        // Test that Package with empty State fails
        let raw_attribute = "---
Package:
State: Absent
    ";
        assert!(yaml_serde::from_str::<AptExpectedState>(raw_attribute).is_err());

        // Test that unknown keys are rejected
        let raw_attribute = "---
Package: apache2
State: Absent
unknown_key: unknown_value
    ";
        assert!(yaml_serde::from_str::<AptExpectedState>(raw_attribute).is_err());
    }
}
