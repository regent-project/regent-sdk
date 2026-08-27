//! YUM/DNF package management attribute
//!
//! This module provides the `YumDnfExpectedState` type for managing RHEL/CentOS/Fedora
//! packages using the YUM or DNF package manager.
//!
//! **Compatible OS:** Linux (Fedora, CentOS, RHEL-based distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::yumdnf::{YumDnfExpectedState, PackageExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install httpd package
//! let httpd = YumDnfExpectedState::package_state("httpd", PackageExpectedState::Present);
//!
//! // Remove a package
//! let nginx = YumDnfExpectedState::package_state("nginx", PackageExpectedState::Absent);
//!
//! // Trigger a full system upgrade
//! let upgrade = YumDnfExpectedState::full_system_upgrade();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::yumdnf(httpd, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Httpd package must be present
//!     Privilege: !WithSudo
//!     Detail: !YumDnf
//!       Package: httpd
//!       State: present
//! ```
//!
//! For a full system upgrade:
//!
//! ```yaml
//! Attributes:
//!   - Name: All packages must be up to date
//!     Privilege: !WithSudo
//!     Detail: !YumDnf
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
pub enum YumDnfModuleInternalApiCall {
    Install(String),
    Remove(String),
    Upgrade,
}

impl std::fmt::Display for YumDnfModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YumDnfModuleInternalApiCall::Install(package) => write!(f, "install {}", package),
            YumDnfModuleInternalApiCall::Remove(package) => write!(f, "remove {}", package),
            YumDnfModuleInternalApiCall::Upgrade => write!(f, "upgrade"),
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

/// Configuration for YUM/DNF package management
///
/// This enum represents the desired state for YUM/DNF package management on Fedora/CentOS/RHEL systems.
/// It supports two main operations:
/// - Managing individual packages (install/remove) via the `PackageState` variant
/// - Performing a full system upgrade via the `SystemUpToDate` variant
///
/// # YAML Representation
///
/// ## Package management:
/// ```yaml
/// Package: httpd
/// State: Present  # or "Absent" to remove
/// ```
///
/// ## Full system upgrade:
/// ```yaml
/// SystemUpToDate
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all_fields = "PascalCase")]
#[serde(deny_unknown_fields)]
pub enum YumDnfExpectedState {
    /// Perform a full system upgrade (dnf/yum update)
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

impl Timeout for YumDnfExpectedState {
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

impl YumDnfExpectedState {
    pub fn full_system_upgrade() -> YumDnfExpectedState {
        YumDnfExpectedState::SystemUpToDate
    }

    pub fn package_state(package: &str, state: PackageExpectedState) -> YumDnfExpectedState {
        YumDnfExpectedState::PackageState {
            package: package.to_string(),
            state,
        }
    }
}

impl Check for YumDnfExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Fedora,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but YUM/DNF is only supported on Fedora/CentOS/RHEL Linux",
                incompatible_os_kind
            ))),
        }
    }
}

#[allow(unused_assignments)] // 'package_manager' is never actually read, only borrowed
impl<Handler: HostHandler> AssessCompliance<Handler> for YumDnfExpectedState {
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

        let package_manager: RedHatFlavoredPackageManager;

        if host_handler
            .is_this_command_available("dnf", &Privilege::None)
            .await
            .unwrap()
        {
            package_manager = RedHatFlavoredPackageManager::Dnf;
        } else if host_handler
            .is_this_command_available("yum", &Privilege::None)
            .await
            .unwrap()
        {
            package_manager = RedHatFlavoredPackageManager::Yum;
        } else {
            return Err(RegentError::FailedDryRunEvaluation(
                "Neither YUM nor DNF work on this host".to_string(),
            ));
        }

        let mut remediations: Vec<Remediation> = Vec::new();

        match &self {
            Self::SystemUpToDate => {
                // For system upgrade, we need to check if updates are available
                // This is a simplified check - in practice, we'd run the appropriate command
                remediations.push(Remediation::YumDnf(YumDnfApiCall::from(
                    YumDnfModuleInternalApiCall::Upgrade,
                    package_manager,
                    privilege.clone(),
                )));
            }
            Self::PackageState {
                package,
                state: expected_state,
            } => {
                let package_is_currently_installed = is_package_installed(
                    host_handler,
                    &package_manager,
                    package.clone(),
                    privilege.clone(),
                )
                .await;

                match (package_is_currently_installed, expected_state) {
                    (true, PackageExpectedState::Present) => {} // Nothing to do
                    (true, PackageExpectedState::Absent) => {
                        // Package is present and needs to be removed
                        remediations.push(Remediation::YumDnf(YumDnfApiCall::from(
                            YumDnfModuleInternalApiCall::Remove(package.clone()),
                            package_manager.clone(),
                            privilege.clone(),
                        )));
                    }
                    (false, PackageExpectedState::Present) => {
                        // Package is absent and needs to be installed
                        remediations.push(Remediation::YumDnf(YumDnfApiCall::from(
                            YumDnfModuleInternalApiCall::Install(package.clone()),
                            package_manager.clone(),
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
enum RedHatFlavoredPackageManager {
    Yum,
    Dnf,
}

impl RedHatFlavoredPackageManager {
    fn command_name(&self) -> &str {
        match self {
            RedHatFlavoredPackageManager::Dnf => "dnf",
            RedHatFlavoredPackageManager::Yum => "yum",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct YumDnfApiCall {
    pub api_call: YumDnfModuleInternalApiCall,
    package_manager: RedHatFlavoredPackageManager,
    privilege: Privilege,
}

impl YumDnfApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            YumDnfModuleInternalApiCall::Install(package_name) => {
                return format!("Install - {}", package_name);
            }
            YumDnfModuleInternalApiCall::Remove(package_name) => {
                return format!("Remove - {}", package_name);
            }
            YumDnfModuleInternalApiCall::Upgrade => {
                return String::from("Upgrade");
            }
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for YumDnfApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let (cmd, privilege, package_name) = match &self.api_call {
            YumDnfModuleInternalApiCall::Install(package_name) => (
                format!(
                    "{} install -y {}",
                    self.package_manager.command_name(),
                    package_name
                ),
                &self.privilege,
                Some(package_name.clone()),
            ),
            YumDnfModuleInternalApiCall::Remove(package_name) => (
                format!(
                    "{} remove -y {}",
                    self.package_manager.command_name(),
                    package_name
                ),
                &self.privilege,
                Some(package_name.clone()),
            ),
            YumDnfModuleInternalApiCall::Upgrade => (
                format!(
                    "{} update -y --refresh",
                    self.package_manager.command_name()
                ),
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
                    YumDnfModuleInternalApiCall::Install(_) => {
                        // Verify the package is now installed
                        is_package_installed(
                            host_handler,
                            &self.package_manager,
                            pkg_name.clone(),
                            self.privilege.clone(),
                        )
                        .await
                    }
                    YumDnfModuleInternalApiCall::Remove(_) => {
                        // Verify the package is now removed
                        !is_package_installed(
                            host_handler,
                            &self.package_manager,
                            pkg_name.clone(),
                            self.privilege.clone(),
                        )
                        .await
                    }
                    YumDnfModuleInternalApiCall::Upgrade => {
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

impl YumDnfApiCall {
    fn from(
        api_call: YumDnfModuleInternalApiCall,
        package_manager: RedHatFlavoredPackageManager,
        privilege: Privilege,
    ) -> YumDnfApiCall {
        YumDnfApiCall {
            api_call,
            package_manager,
            privilege,
        }
    }
}

async fn is_package_installed<Handler: HostHandler>(
    host_handler: &mut Handler,
    package_manager: &RedHatFlavoredPackageManager,
    package_name: String,
    privilege: Privilege,
) -> bool {
    let test = host_handler
        .run_command(
            format!(
                "{} list installed {}",
                package_manager.command_name(),
                package_name
            )
            .as_str(),
            &privilege,
        )
        .await
        .unwrap();

    if test.return_code == 0 {
        return true;
    } else {
        return false;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_yumdnf_module_block_from_yaml_str() {
        let raw_attributes = "---
- Package: httpd
  State: Present

- Package: httpd
  State: Absent

- SystemUpToDate
    ";

        let attributes: Vec<YumDnfExpectedState> = yaml_serde::from_str(raw_attributes).unwrap();
        assert_eq!(
            attributes[0],
            YumDnfExpectedState::PackageState {
                package: "httpd".to_string(),
                state: PackageExpectedState::Present
            }
        );

        assert_eq!(
            attributes[1],
            YumDnfExpectedState::PackageState {
                package: "httpd".to_string(),
                state: PackageExpectedState::Absent
            }
        );

        assert_eq!(attributes[2], YumDnfExpectedState::SystemUpToDate);
    }

    #[test]
    fn rejecting_incorrect_yumdnf_module_block_from_yaml_str() {
        // Missing State field - should fail deserialization
        let raw_attribute = "---
Package: httpd
    ";
        assert!(yaml_serde::from_str::<YumDnfExpectedState>(raw_attribute).is_err());

        // Missing Package field - should fail deserialization
        let raw_attribute = "---
Package:
State: Absent
    ";
        assert!(yaml_serde::from_str::<YumDnfExpectedState>(raw_attribute).is_err());

        // Unknown key - should fail deserialization
        let raw_attribute = "---
Package: httpd
State: Absent
unknown_key: unknown_value
    ";
        assert!(yaml_serde::from_str::<YumDnfExpectedState>(raw_attribute).is_err());
    }
}
