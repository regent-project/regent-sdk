//! Pacman package management attribute
//!
//! This module provides the `PacmanExpectedState` type for managing Arch Linux packages
//! using the pacman package manager.
//!
//! **Compatible OS:** Linux (Arch-based distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::pacman::{PacmanExpectedState, PackageExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install a package
//! let pkg = PacmanExpectedState::package_state("nginx", PackageExpectedState::Present);
//!
//! // Remove a package
//! let pkg = PacmanExpectedState::package_state("nginx", PackageExpectedState::Absent);
//!
//! // Trigger a full system upgrade
//! let upgrade = PacmanExpectedState::system_upgrade();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::pacman(pkg, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Nginx package must be present
//!     Privilege: !WithSudo
//!     Detail: !Pacman
//!       Package: nginx
//!       State: Present
//! ```
//!
//! For a full system upgrade:
//!
//! ```yaml
//! Attributes:
//!   - Name: System must be up to date
//!     Privilege: !WithSudo
//!     Detail: !Pacman
//!       SystemUpgrade
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
pub enum PacmanModuleInternalApiCall {
    Install(String),
    Remove(String),
    Upgrade,
}

impl std::fmt::Display for PacmanModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacmanModuleInternalApiCall::Install(package) => write!(f, "install {}", package),
            PacmanModuleInternalApiCall::Remove(package) => write!(f, "remove {}", package),
            PacmanModuleInternalApiCall::Upgrade => write!(f, "upgrade"),
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

/// Configuration for Pacman package management
///
/// This enum represents the desired state for Pacman package management on Arch Linux systems.
/// It supports two main operations:
/// - Managing individual packages (install/remove) via the `PackageState` variant
/// - Performing a full system upgrade via the `SystemUpgrade` variant
///
/// # YAML Representation
///
/// ## Package management:
/// ```yaml
/// Package: nginx
/// State: Present  # or "Absent" to remove
/// ```
///
/// ## Full system upgrade:
/// ```yaml
/// SystemUpgrade
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all_fields = "PascalCase")]
#[serde(deny_unknown_fields)]
pub enum PacmanExpectedState {
    /// Perform a full system upgrade (pacman -Syu)
    SystemUpgrade,
    /// Manage a specific package's state
    #[serde(untagged)]
    PackageState {
        /// Name of the package to manage
        package: String,
        /// Desired state of the package
        state: PackageExpectedState,
    },
}

impl Timeout for PacmanExpectedState {
    fn default_timeout(&self) -> Duration {
        match self {
            Self::SystemUpgrade => Duration::from_secs(300),
            Self::PackageState {
                package: _,
                state: _,
            } => Duration::from_secs(60),
        }
    }
}

impl PacmanExpectedState {
    pub fn system_upgrade() -> PacmanExpectedState {
        PacmanExpectedState::SystemUpgrade
    }

    pub fn package_state(package: &str, state: PackageExpectedState) -> PacmanExpectedState {
        PacmanExpectedState::PackageState {
            package: package.to_string(),
            state,
        }
    }

    pub fn package_present(package: &str) -> PacmanExpectedState {
        PacmanExpectedState::PackageState {
            package: package.to_string(),
            state: PackageExpectedState::Present,
        }
    }
}

impl Check for PacmanExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Arch,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but Pacman is only supported on Arch Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for PacmanExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Arch Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        if !host_handler
            .is_this_command_available("pacman", &Privilege::None)
            .await
            .unwrap()
        {
            return Err(RegentError::FailedDryRunEvaluation(
                "Pacman not working on this host".to_string(),
            ));
        }

        let mut remediations: Vec<Remediation> = Vec::new();

        match &self {
            Self::SystemUpgrade => {
                // For system upgrade, we always add the upgrade remediation
                // In a more sophisticated implementation, we could check if upgrades are available
                remediations.push(Remediation::Pacman(PacmanApiCall::from(
                    PacmanModuleInternalApiCall::Upgrade,
                    privilege.clone(),
                )));
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
                        remediations.push(Remediation::Pacman(PacmanApiCall::from(
                            PacmanModuleInternalApiCall::Remove(package.clone()),
                            privilege.clone(),
                        )));
                    }
                    (false, PackageExpectedState::Present) => {
                        // Package is absent and needs to be installed
                        remediations.push(Remediation::Pacman(PacmanApiCall::from(
                            PacmanModuleInternalApiCall::Install(package.clone()),
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
pub struct PacmanApiCall {
    pub api_call: PacmanModuleInternalApiCall,
    privilege: Privilege,
}

impl Check for PacmanApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Arch,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but Pacman is only supported on Arch Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl PacmanApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            PacmanModuleInternalApiCall::Install(package_name) => {
                return format!("Install - {}", package_name);
            }
            PacmanModuleInternalApiCall::Remove(package_name) => {
                return format!("Remove - {}", package_name);
            }
            PacmanModuleInternalApiCall::Upgrade => {
                return String::from("Upgrade");
            }
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for PacmanApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Arch Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let (cmd, privilege, package_name) = match &self.api_call {
            PacmanModuleInternalApiCall::Install(package_name) => (
                format!("pacman --noconfirm -S {}", package_name),
                &self.privilege,
                Some(package_name.clone()),
            ),
            PacmanModuleInternalApiCall::Remove(package_name) => (
                format!("pacman --noconfirm -R {}", package_name),
                &self.privilege,
                Some(package_name.clone()),
            ),
            PacmanModuleInternalApiCall::Upgrade => {
                ("pacman -Syu".to_string(), &self.privilege, None)
            }
        };

        let cmd_result = host_handler
            .run_command(cmd.as_str(), privilege)
            .await
            .unwrap();

        if cmd_result.return_code == 0 {
            // Post-install verification: verify the package state matches the expected operation
            if let Some(pkg_name) = &package_name {
                let verification_result = match &self.api_call {
                    PacmanModuleInternalApiCall::Install(_) => {
                        // Verify the package is now installed
                        is_package_installed(host_handler, pkg_name).await
                    }
                    PacmanModuleInternalApiCall::Remove(_) => {
                        // Verify the package is now removed
                        !is_package_installed(host_handler, pkg_name).await
                    }
                    PacmanModuleInternalApiCall::Upgrade => {
                        // Upgrade is a system-wide operation, can't easily verify individual packages
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

impl PacmanApiCall {
    fn from(api_call: PacmanModuleInternalApiCall, privilege: Privilege) -> PacmanApiCall {
        PacmanApiCall {
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
        .run_command(
            format!("LC_ALL=en_US.UTF-8 pacman -Q -i {}", package).as_str(),
            &Privilege::None,
        )
        .await
        .unwrap();

    test.return_code == 0
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_pacman_module_block_from_yaml_str() {
        let raw_attributes = "---
- Package: apache
  State: Present

- Package: apache
  State: Absent

- SystemUpgrade
    ";

        let attributes: Vec<PacmanExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();

        assert_eq!(
            attributes[0],
            PacmanExpectedState::PackageState {
                package: "apache".to_string(),
                state: PackageExpectedState::Present
            }
        );

        assert_eq!(
            attributes[1],
            PacmanExpectedState::PackageState {
                package: "apache".to_string(),
                state: PackageExpectedState::Absent
            }
        );

        assert_eq!(attributes[2], PacmanExpectedState::SystemUpgrade);
    }

    #[test]
    fn rejecting_incorrect_pacman_module_block_from_yaml_str() {
        // Test that Package without State fails to deserialize
        let raw_attribute = "---
Package: apache
    ";
        assert!(yaml_serde::from_str::<PacmanExpectedState>(raw_attribute).is_err());

        // Test that Package with empty State fails
        let raw_attribute = "---
Package:
State: Absent
    ";
        assert!(yaml_serde::from_str::<PacmanExpectedState>(raw_attribute).is_err());

        // Test that unknown keys are rejected
        let raw_attribute = "---
Package: apache
State: Absent
unknown_key: unknown_value
    ";
        assert!(yaml_serde::from_str::<PacmanExpectedState>(raw_attribute).is_err());
    }
}
