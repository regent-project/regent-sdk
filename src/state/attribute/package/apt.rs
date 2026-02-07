use crate::error::Error;
use crate::managed_host::InternalApiCallOutcome;
use crate::managed_host::{AssessCompliance, ReachCompliance};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AptBlockExpectedState {
    state: Option<PackageExpectedState>,
    package: Option<String>,
    upgrade: Option<bool>,
}

// Chained methods to allow building an AptBlockExpectedState as follows :
// let apt_block = AptBlockExpectedState::builder()
//     .with_package_state("apache2", PackageExpectedState::Present)
//     .with_system_upgrade()
//     .build();
impl AptBlockExpectedState {
    pub fn builder() -> AptBlockExpectedState {
        AptBlockExpectedState {
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

    pub fn build(&self) -> Result<AptBlockExpectedState, Error> {
        // if let Err(error_detail) = self.check() {
        //     return Err(error_detail);
        // }
        Ok(self.clone())
    }
}

// impl Check for AptBlockExpectedState {
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

impl<Handler: HostHandler> AssessCompliance<Handler> for AptBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<Option<Vec<Remediation>>, Error> {
        if !host_handler
            .is_this_command_available("apt-get", &Privilege::None)
            .unwrap()
            || !host_handler
                .is_this_command_available("dpkg", &Privilege::None)
                .unwrap()
        {
            return Err(Error::FailedDryRunEvaluation(
                "APT not working on this host".to_string(),
            ));
        }

        let mut remediations: Vec<Remediation> = Vec::new();

        match &self.state {
            None => {}
            Some(state) => {
                match state {
                    PackageExpectedState::Present => {
                        // Check is package is already installed or needs to be
                        if is_package_installed(host_handler, self.package.clone().unwrap()) {
                            remediations.push(Remediation::None(format!(
                                "{} already present",
                                self.package.clone().unwrap()
                            )));
                        } else {
                            // Package is absent and needs to be installed
                            remediations.push(Remediation::Apt(AptApiCall::from(
                                AptModuleInternalApiCall::Install(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        }
                    }
                    PackageExpectedState::Absent => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(host_handler, self.package.clone().unwrap()) {
                            // Package is present and needs to be removed
                            remediations.push(Remediation::Apt(AptApiCall::from(
                                AptModuleInternalApiCall::Remove(self.package.clone().unwrap()),
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

        // TODO: have this do an "apt update"
        // -> if no update available, state = Matched
        // -> if updates available, state = ApiCall -> action = "apt upgrade"
        if let Some(value) = self.upgrade {
            if value {
                remediations.push(Remediation::Apt(AptApiCall::from(
                    AptModuleInternalApiCall::Upgrade,
                    privilege.clone(),
                )));
            }
        }

        // If changes are only None, it means a Match. If only one change is not a None, return the whole list.
        for remediation in remediations.iter() {
            match remediation {
                Remediation::None(_) => {}
                _ => {
                    return Ok(Some(remediations));
                }
            }
        }
        return Ok(None);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AptApiCall {
    pub api_call: AptModuleInternalApiCall,
    privilege: Privilege,
}

impl<Handler: HostHandler> ReachCompliance<Handler> for AptApiCall {
    // fn display(&self) -> String {
    //     match &self.api_call {
    //         AptModuleInternalApiCall::Install(package_name) => {
    //             return format!("Install - {}", package_name);
    //         }
    //         AptModuleInternalApiCall::Remove(package_name) => {
    //             return format!("Remove - {}", package_name);
    //         }
    //         AptModuleInternalApiCall::Upgrade => {
    //             return String::from("Upgrade");
    //         }
    //     }
    // }

    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        let (cmd, privilege) = match &self.api_call {
            AptModuleInternalApiCall::Install(package_name) => (
                format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y {}",
                    package_name
                ),
                &self.privilege,
            ),
            AptModuleInternalApiCall::Remove(package_name) => (
                format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y {}",
                    package_name
                ),
                &self.privilege,
            ),
            AptModuleInternalApiCall::Upgrade => (
                "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y".to_string(),
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

impl AptApiCall {
    fn from(api_call: AptModuleInternalApiCall, privilege: Privilege) -> AptApiCall {
        AptApiCall {
            api_call,
            privilege,
        }
    }
}

fn is_package_installed<Handler: HostHandler>(host_handler: &mut Handler, package: String) -> bool {
    let test = host_handler
        .run_command(format!("dpkg -s {}", package).as_str(), &Privilege::None)
        .unwrap();

    if test.return_code == 0 { true } else { false }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parsing_apt_module_block_from_yaml_str() {
        let raw_attributes = "---
- package: apache2
  state: present

- package: apache2
  state: absent

- upgrade: true
    ";

        let attributes: Vec<AptBlockExpectedState> = serde_yaml::from_str(raw_attributes).unwrap();

        assert_eq!(attributes[0].package, Some("apache2".to_string()));
        assert_eq!(attributes[0].state, Some(PackageExpectedState::Present));
        assert_eq!(attributes[0].upgrade, None);

        assert_eq!(attributes[1].package, Some("apache2".to_string()));
        assert_eq!(attributes[1].state, Some(PackageExpectedState::Absent));
        assert_eq!(attributes[1].upgrade, None);

        assert_eq!(attributes[2].package, None);
        assert_eq!(attributes[2].state, None);
        assert_eq!(attributes[2].upgrade, Some(true));
    }

    #[test]
    fn rejecting_incorrect_apt_module_block_from_yaml_str() {
        let raw_attribute = "---
- 
    ";
        assert!(serde_yaml::from_str::<AptBlockExpectedState>(raw_attribute).is_err());

        let raw_attribute = "---
- package: apache2
    ";
        assert!(serde_yaml::from_str::<AptBlockExpectedState>(raw_attribute).is_err());

        let raw_attribute = "---
- package:
  state: absent
    ";
        assert!(serde_yaml::from_str::<AptBlockExpectedState>(raw_attribute).is_err());

        let raw_attribute = "---
- package: apache2
  state: absent
  unknown_key: unknown_value
    ";
        assert!(serde_yaml::from_str::<AptBlockExpectedState>(raw_attribute).is_err());
    }
}
