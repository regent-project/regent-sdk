// Pacman Module : handle packages in Debian-like distributions

use crate::connection::hosthandler::ConnectionHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::{Apply, DryRun};
use crate::task::moduleblock::{Check, ModuleApiCall};
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
        if let Err(error_detail) = self.check() {
            return Err(error_detail);
        }
        Ok(self.clone())
    }
}

impl Check for PacmanBlockExpectedState {
    fn check(&self) -> Result<(), Error> {
        if let (None, None, None) = (&self.state, &self.package, self.upgrade) {
            return Err(Error::IncoherentExpectedState(format!(
                "All parameters are unset. Please describe the expected state."
            )));
        }
        if let (None, Some(package_name)) = (&self.state, &self.package) {
            return Err(Error::IncoherentExpectedState(format!(
                "Missing 'state' parameter. What is the expected state of the package ({}) ?",
                package_name
            )));
        }
        if let (Some(package_expected_state), None) = (&self.state, &self.package) {
            return Err(Error::IncoherentExpectedState(format!(
                "Missing 'package' parameter. Which package should be {:?} ?",
                package_expected_state
            )));
        }
        Ok(())
    }
}

impl DryRun for PacmanBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut ConnectionHandler,
        privilege: &Privilege,
    ) -> Result<StepChange, Error> {
        if !hosthandler
            .is_this_cmd_available("pacman", &privilege)
            .unwrap()
        {
            return Err(Error::FailedDryRunEvaluation(
                "Pacman not working on this host".to_string(),
            ));
        }

        let mut changes: Vec<ModuleApiCall> = Vec::new();

        match &self.state {
            None => {}
            Some(state) => {
                match state {
                    PackageExpectedState::Present => {
                        // Check is package is already installed or needs to be
                        if is_package_installed(hosthandler, self.package.clone().unwrap()) {
                            changes.push(ModuleApiCall::None(format!(
                                "{} already present",
                                self.package.clone().unwrap()
                            )));
                        } else {
                            // Package is absent and needs to be installed
                            changes.push(ModuleApiCall::Pacman(PacmanApiCall::from(
                                PacmanModuleInternalApiCall::Install(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        }
                    }
                    PackageExpectedState::Absent => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(hosthandler, self.package.clone().unwrap()) {
                            // Package is present and needs to be removed
                            changes.push(ModuleApiCall::Pacman(PacmanApiCall::from(
                                PacmanModuleInternalApiCall::Remove(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        } else {
                            changes.push(ModuleApiCall::None(format!(
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
                changes.push(ModuleApiCall::Pacman(PacmanApiCall::from(
                    PacmanModuleInternalApiCall::Upgrade,
                    privilege.clone(),
                )));
            }
        }

        // If changes are only None, it means a Match. If only one change is not a None, return the whole list.
        for change in changes.iter() {
            match change {
                ModuleApiCall::None(_) => {}
                _ => {
                    return Ok(StepChange::changes(changes));
                }
            }
        }
        return Ok(StepChange::matched("Package(s) already in expected state"));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacmanApiCall {
    pub api_call: PacmanModuleInternalApiCall,
    privilege: Privilege,
}

impl Apply for PacmanApiCall {
    fn display(&self) -> String {
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

    fn apply_moduleblock_change(&self, hosthandler: &mut ConnectionHandler) -> ApiCallResult {
        match &self.api_call {
            PacmanModuleInternalApiCall::Install(package_name) => {
                let cmd = format!("pacman --noconfirm -S {}", package_name);
                let cmd_result = hosthandler.run_cmd(cmd.as_str(), &self.privilege).unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!(
                            "{} install successful",
                            package_name
                        )),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(format!("{} install failed", package_name)),
                    );
                }
            }
            PacmanModuleInternalApiCall::Remove(package_name) => {
                let cmd = format!("pacman --noconfirm -R {}", package_name);
                let cmd_result = hosthandler.run_cmd(cmd.as_str(), &self.privilege).unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!(
                            "{} removal successful",
                            package_name
                        )),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(format!("{} removal failed", package_name)),
                    );
                }
            }
            PacmanModuleInternalApiCall::Upgrade => {
                let cmd = "pacman -Syu";
                let cmd_result = hosthandler.run_cmd(cmd, &self.privilege).unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(String::from("Upgrade successful")),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Upgrade failed")),
                    );
                }
            }
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

fn is_package_installed(hosthandler: &mut ConnectionHandler, package: String) -> bool {
    let test = hosthandler
        .run_cmd(
            format!("LC_ALL=en_US.UTF-8 pacman -Q -i {}", package).as_str(),
            &Privilege::Usual,
        )
        .unwrap();

    if test.rc == 0 { true } else { false }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn parsing_pacman_module_block_from_yaml_str() {
        let raw_tasklist_description = "---
- name: Dummy steps to test deserialization and syntax of this module
  steps:
    - name: Package must be present
      pacman:
        package: apache
        state: present
    - name: Package must be absent
      pacman:
        package: apache
        state: absent
    - name: Package must be present with upgrade
      pacman:
        package: apache
        state: present
        upgrade: true
        ";

        let parsed_tasklist = TaskList::from_str(raw_tasklist_description, TaskListFormat::Yaml);

        assert!(parsed_tasklist.is_ok());
    }
}
