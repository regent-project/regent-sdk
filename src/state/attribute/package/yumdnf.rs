use crate::error::Error;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YumDnfBlockExpectedState {
    state: Option<PackageExpectedState>,
    package: Option<String>,
    upgrade: Option<bool>,
}

// Chained methods to allow building an YumDnfBlockExpectedState as follows :
// let apt_block = YumDnfBlockExpectedState::builder()
//     .with_package_state("httpd", PackageExpectedState::Present)
//     .with_system_upgrade()
//     .build();
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

    pub fn build(&self) -> Result<YumDnfBlockExpectedState, Error> {
        // if let Err(error_detail) = self.check() {
        //     return Err(error_detail);
        // }
        Ok(self.clone())
    }
}

// impl Check for YumDnfBlockExpectedState {
//     fn check(&self) -> Result<(), Error> {
//         if let (None, None, None) = (&self.state, &self.package, self.upgrade) {
//             return Err(Error::IncoherentExpectedState(format!(
//                 "All parameters are unset. Please describe the expected state."
//             )));
//         }
//         if let (None, Some(package_name)) = (&self.state, &self.package) {
//             return Err(Error::IncoherentExpectedState(format!(
//                 "Missing 'state' parameter. What is the expected state of the package ({}) ?",
//                 package_name
//             )));
//         }
//         if let (Some(package_expected_state), None) = (&self.state, &self.package) {
//             return Err(Error::IncoherentExpectedState(format!(
//                 "Missing 'package' parameter. Which package should be {:?} ?",
//                 package_expected_state
//             )));
//         }
//         Ok(())
//     }
// }

#[allow(unused_assignments)] // 'package_manager' is never actually read, only borrowed
impl<Handler: HostHandler> AssessCompliance<Handler> for YumDnfBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error> {
        let package_manager: RedHatFlavoredPackageManager;

        if host_handler
            .is_this_command_available("dnf", &Privilege::None)
            .unwrap()
        {
            package_manager = RedHatFlavoredPackageManager::Dnf;
        } else if host_handler
            .is_this_command_available("yum", &Privilege::None)
            .unwrap()
        {
            package_manager = RedHatFlavoredPackageManager::Yum;
        } else {
            return Err(Error::FailedDryRunEvaluation(
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
                        ) {
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
                        ) {
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
    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
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

        let cmd_result = host_handler.run_command(cmd.as_str(), privilege).unwrap();

        if cmd_result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success)
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

fn is_package_installed<Handler: HostHandler>(
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
- package: httpd
  state: present

- package: httpd
  state: absent

- upgrade: true
    ";

        let attributes: Vec<YumDnfBlockExpectedState> =
            serde_yaml::from_str(raw_attributes).unwrap();

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
- 
    ";
        assert!(serde_yaml::from_str::<YumDnfBlockExpectedState>(raw_attribute).is_err());

        let raw_attribute = "---
- package: httpd
    ";
        assert!(serde_yaml::from_str::<YumDnfBlockExpectedState>(raw_attribute).is_err());

        let raw_attribute = "---
- package:
  state: absent
    ";
        assert!(serde_yaml::from_str::<YumDnfBlockExpectedState>(raw_attribute).is_err());

        let raw_attribute = "---
- package: httpd
  state: absent
  unknown_key: unknown_value
    ";
        assert!(serde_yaml::from_str::<YumDnfBlockExpectedState>(raw_attribute).is_err());
    }
}
