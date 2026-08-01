//! YUM/DNF package management attribute
//!
//! This module provides the `YumDnfBlockExpectedState` type for managing RHEL/CentOS/Fedora
//! packages using the YUM or DNF package manager.
//!
//! **Compatible OS:** Linux (Fedora, CentOS, RHEL-based distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::yumdnf::{YumDnfBlockExpectedState, PackageExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install httpd package
//! let httpd = YumDnfBlockExpectedState::builder()
//!     .with_package_state("httpd", PackageExpectedState::Present)
//!     .build()
//!     .unwrap();
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
//!   - Detail: !YumDnf
//!       Package: httpd
//!       State: !Present
//!       Privilege: !WithSudo
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, LinuxFlavor, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
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
/// Use the builder to specify package state (Present/Absent) and optionally trigger
/// a system upgrade.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct YumDnfBlockExpectedState {
    /// Desired state of the package(s)
    state: Option<PackageExpectedState>,
    /// Package name to manage
    package: Option<String>,
    /// Whether to perform a full system upgrade
    upgrade: Option<bool>,
}

impl Timeout for YumDnfBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

impl YumDnfBlockExpectedState {
    pub fn builder() -> YumDnfBlockExpectedState {
        YumDnfBlockExpectedState {
            state: None,
            package: None,
            upgrade: None,
        }
    }

    pub fn with_system_upgrade(&mut self) -> &mut Self {
        self.upgrade = Some(true);
        self
    }

    pub fn with_package_state(
        &mut self,
        package_name: &str,
        package_state: PackageExpectedState,
    ) -> &mut Self {
        self.package = Some(package_name.to_string());
        self.state = Some(package_state);
        self
    }

    pub fn build(&self) -> Result<YumDnfBlockExpectedState, RegentError> {
        if let Err(details) = self.check() {
            return Err(details);
        }
        Ok(self.clone())
    }
}

impl Check for YumDnfBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if let (None, None, None) = (&self.state, &self.package, self.upgrade) {
            return Err(RegentError::IncoherentExpectedState(format!(
                "All parameters are unset. Please describe the expected state."
            )));
        }
        if let (None, Some(package_name)) = (&self.state, &self.package) {
            return Err(RegentError::IncoherentExpectedState(format!(
                "Missing 'state' parameter. What is the expected state of the package ({}) ?",
                package_name
            )));
        }
        if let (Some(package_expected_state), None) = (&self.state, &self.package) {
            return Err(RegentError::IncoherentExpectedState(format!(
                "Missing 'package' parameter. Which package should be {:?} ?",
                package_expected_state
            )));
        }
        Ok(())
    }

    fn check_host_compatibility(&self, host_properties: &HostProperties) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxFlavor::Fedora) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(
                format!("Host is {:?} but YUM/DNF is only supported on Fedora/CentOS/RHEL Linux", incompatible_os_kind)
            )),
        }
    }
}

#[allow(unused_assignments)] // 'package_manager' is never actually read, only borrowed
impl<Handler: HostHandler> AssessCompliance<Handler> for YumDnfBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,

        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
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

        match &self.state {
            None => {}
            Some(state) => {
                match state {
                    PackageExpectedState::Present => {
                        // Check is package is already installed or needs to be
                        if is_package_installed(
                            host_handler,
                            &package_manager,
                            self.package.clone().unwrap(),
                            privilege.clone(),
                        )
                        .await
                        {
                            remediations.push(Remediation::None(format!(
                                "{} already present",
                                self.package.clone().unwrap()
                            )));
                        } else {
                            // Package is absent and needs to be installed
                            remediations.push(Remediation::YumDnf(YumDnfApiCall::from(
                                YumDnfModuleInternalApiCall::Install(self.package.clone().unwrap()),
                                package_manager.clone(),
                                privilege.clone(),
                            )));
                        }
                    }
                    PackageExpectedState::Absent => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(
                            host_handler,
                            &package_manager,
                            self.package.clone().unwrap(),
                            privilege.clone(),
                        )
                        .await
                        {
                            // Package is present and needs to be removed
                            remediations.push(Remediation::YumDnf(YumDnfApiCall::from(
                                YumDnfModuleInternalApiCall::Remove(self.package.clone().unwrap()),
                                package_manager.clone(),
                                privilege.clone(),
                            )));
                        } else {
                            remediations.push(Remediation::None(format!(
                                "{} already absent",
                                self.package.clone().unwrap()
                            )));
                        }
                    }
                }
            }
        }
        // TODO : have this to do a "dnf check-update" only
        // If updates available -> ApiCall, if not, Matched
        if let Some(value) = self.upgrade {
            if value {
                remediations.push(Remediation::YumDnf(YumDnfApiCall::from(
                    YumDnfModuleInternalApiCall::Upgrade,
                    package_manager,
                    privilege.clone(),
                )));
            }
        }

        // If remediations are only None, it means a Match. If only one change is not a None, return the whole list.
        for remediation in remediations.iter() {
            match remediation {
                Remediation::None(_) => {}
                _ => {
                    return Ok(AttributeComplianceAssessment::NonCompliant(remediations));
                }
            }
        }
        return Ok(AttributeComplianceAssessment::Compliant);
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
        let (cmd, privilege) = match &self.api_call {
            YumDnfModuleInternalApiCall::Install(package_name) => (
                format!(
                    "{} install -y {}",
                    self.package_manager.command_name(),
                    package_name
                ),
                &self.privilege,
            ),
            YumDnfModuleInternalApiCall::Remove(package_name) => (
                format!(
                    "{} remove -y {}",
                    self.package_manager.command_name(),
                    package_name
                ),
                &self.privilege,
            ),
            YumDnfModuleInternalApiCall::Upgrade => (
                format!(
                    "{} update -y --refresh",
                    self.package_manager.command_name()
                ),
                &self.privilege,
            ),
        };

        let cmd_result = host_handler
            .run_command(cmd.as_str(), privilege)
            .await
            .unwrap();

        if cmd_result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success(None))
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
  State: !Present

- Package: httpd
  State: !Absent

- Upgrade: true
    ";

        let attributes: Vec<YumDnfBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();

        assert_eq!(attributes[0].package, Some("httpd".to_string()));
        assert_eq!(attributes[0].state, Some(PackageExpectedState::Present));
        assert_eq!(attributes[0].upgrade, None);

        assert_eq!(attributes[1].package, Some("httpd".to_string()));
        assert_eq!(attributes[1].state, Some(PackageExpectedState::Absent));
        assert_eq!(attributes[1].upgrade, None);

        assert_eq!(attributes[2].package, None);
        assert_eq!(attributes[2].state, None);
        assert_eq!(attributes[2].upgrade, Some(true));
    }

    #[test]
    fn rejecting_incorrect_yumdnf_module_block_from_yaml_str() {
        let raw_attribute = "---
Package: httpd
    ";
        let yaml_part = yaml_serde::from_str::<YumDnfBlockExpectedState>(raw_attribute);
        assert!(yaml_part.is_ok());
        assert!(yaml_part.unwrap().check().is_err());

        let raw_attribute = "---
Package:
State: !Absent
    ";
        let yaml_part = yaml_serde::from_str::<YumDnfBlockExpectedState>(raw_attribute);
        assert!(yaml_part.is_ok());
        assert!(yaml_part.unwrap().check().is_err());

        let raw_attribute = "---
Package: httpd
State: !Absent
unknown_key: unknown_value
    ";
        assert!(yaml_serde::from_str::<YumDnfBlockExpectedState>(raw_attribute).is_err());
    }
}
