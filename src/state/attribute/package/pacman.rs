use crate::managed_host::InternalApiCallOutcome;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Remediation;
use crate::error::Error;
use crate::state::attribute::Privilege;
use crate::managed_host::{AssessCompliance, ReachCompliance};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacmanBlockExpectedState {
    state: Option<PackageExpectedState>,
    package: Option<String>,
    upgrade: Option<bool>,
}

// Chained methods to allow building an PacmanBlockExpectedState as follows :
// let pacman_block = PacmanBlockExpectedState::builder()
//     .with_package_state("apache2", PackageExpectedState::Present)
//     .with_system_upgrade()
//     .build();
impl PacmanBlockExpectedState {
    pub fn builder() -> PacmanBlockExpectedState {
        PacmanBlockExpectedState {
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

    pub fn build(&self) -> Result<PacmanBlockExpectedState, Error> {
        // if let Err(error_detail) = self.check() {
        //     return Err(error_detail);
        // }
        Ok(self.clone())
    }
}

// impl Check for PacmanBlockExpectedState {
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

impl<Handler: HostHandler> AssessCompliance<Handler> for PacmanBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<Option<Vec<Remediation>>, Error> {
        if !host_handler
            .is_this_command_available("pacman", &Privilege::None)
            .unwrap()
        {
            return Err(Error::FailedDryRunEvaluation(
                "Pacman not working on this host".to_string(),
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
                            remediations.push(Remediation::Pacman(PacmanApiCall::from(
                                PacmanModuleInternalApiCall::Install(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        }
                    }
                    PackageExpectedState::Absent => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(host_handler, self.package.clone().unwrap()) {
                            // Package is present and needs to be removed
                            remediations.push(Remediation::Pacman(PacmanApiCall::from(
                                PacmanModuleInternalApiCall::Remove(self.package.clone().unwrap()),
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

        if let Some(value) = self.upgrade {
            if value {
                remediations.push(Remediation::Pacman(PacmanApiCall::from(
                    PacmanModuleInternalApiCall::Upgrade,
                    privilege.clone(),
                )));
            }
        }

        // If remediations are only None, it means a Match. If only one change is not a None, return the whole list.
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
pub struct PacmanApiCall {
    pub api_call: PacmanModuleInternalApiCall,
    privilege: Privilege,
}

impl<Handler: HostHandler> ReachCompliance<Handler> for PacmanApiCall {
    // fn display(&self) -> String {
    //     match &self.api_call {
    //         PacmanModuleInternalApiCall::Install(package_name) => {
    //             return format!("Install - {}", package_name);
    //         }
    //         PacmanModuleInternalApiCall::Remove(package_name) => {
    //             return format!("Remove - {}", package_name);
    //         }
    //         PacmanModuleInternalApiCall::Upgrade => {
    //             return String::from("Upgrade");
    //         }
    //     }
    // }

    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        let (cmd, privilege) = match &self.api_call {
            PacmanModuleInternalApiCall::Install(package_name) => (
                format!("pacman --noconfirm -S {}", package_name),
                &self.privilege,
            ),
            PacmanModuleInternalApiCall::Remove(package_name) => (
                format!("pacman --noconfirm -R {}", package_name),
                &self.privilege,
            ),
            PacmanModuleInternalApiCall::Upgrade => ("pacman -Syu".to_string(), &self.privilege),
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

impl PacmanApiCall {
    fn from(api_call: PacmanModuleInternalApiCall, privilege: Privilege) -> PacmanApiCall {
        PacmanApiCall {
            api_call,
            privilege,
        }
    }
}

fn is_package_installed<Handler: HostHandler>(host_handler: &mut Handler, package: String) -> bool {
    let test = host_handler
        .run_command(
            format!("LC_ALL=en_US.UTF-8 pacman -Q -i {}", package).as_str(),
            &Privilege::None,
        )
        .unwrap();

    if test.return_code == 0 { true } else { false }
}

// #[cfg(test)]
// mod tests {
//     use crate::prelude::*;

//     #[test]
//     fn parsing_pacman_module_block_from_yaml_str() {
//         let raw_tasklist_description = "---
// - name: Dummy steps to test deserialization and syntax of this module
//   steps:
//     - name: Package must be present
//       pacman:
//         package: apache
//         state: present
//     - name: Package must be absent
//       pacman:
//         package: apache
//         state: absent
//     - name: Package must be present with upgrade
//       pacman:
//         package: apache
//         state: present
//         upgrade: true
//         ";

//         let parsed_tasklist = TaskList::from_str(raw_tasklist_description, TaskListFormat::Yaml);

//         assert!(parsed_tasklist.is_ok());
//     }
// }
