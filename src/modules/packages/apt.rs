// APT Module : handle packages in Debian-like distributions

use crate::connection::hosthandler::ConnectionHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::{Apply, DryRun};
use crate::task::moduleblock::{Check, ModuleApiCall};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum AptModuleInternalApiCall {
    Install(String),
    Remove(String),
    Upgrade,
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
        if let Err(error_detail) = self.check() {
            return Err(error_detail);
        }
        Ok(self.clone())
    }
}

impl Check for AptBlockExpectedState {
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

impl DryRun for AptBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut ConnectionHandler,
        privilege: &Privilege,
    ) -> Result<StepChange, Error> {
        if !hosthandler
            .is_this_cmd_available("apt-get", &privilege)
            .unwrap()
            || !hosthandler
                .is_this_cmd_available("dpkg", &privilege)
                .unwrap()
        {
            return Err(Error::FailedDryRunEvaluation(
                "APT not working on this host".to_string(),
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
                            changes.push(ModuleApiCall::Apt(AptApiCall::from(
                                AptModuleInternalApiCall::Install(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        }
                    }
                    PackageExpectedState::Absent => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(hosthandler, self.package.clone().unwrap()) {
                            // Package is present and needs to be removed
                            changes.push(ModuleApiCall::Apt(AptApiCall::from(
                                AptModuleInternalApiCall::Remove(self.package.clone().unwrap()),
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

        // TODO: have this do an "apt update"
        // -> if no update available, state = Matched
        // -> if updates available, state = ApiCall -> action = "apt upgrade"
        if let Some(value) = self.upgrade {
            if value {
                changes.push(ModuleApiCall::Apt(AptApiCall::from(
                    AptModuleInternalApiCall::Upgrade,
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
pub struct AptApiCall {
    api_call: AptModuleInternalApiCall,
    privilege: Privilege,
}

impl Apply for AptApiCall {
    fn display(&self) -> String {
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

    fn apply_moduleblock_change(&self, hosthandler: &mut ConnectionHandler) -> ApiCallResult {
        match &self.api_call {
            AptModuleInternalApiCall::Install(package_name) => {
                hosthandler
                    .run_cmd("apt-get update", &self.privilege)
                    .unwrap();

                let cmd = format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y {}",
                    package_name
                );
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
            AptModuleInternalApiCall::Remove(package_name) => {
                let cmd = format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y {}",
                    package_name
                );
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
            AptModuleInternalApiCall::Upgrade => {
                hosthandler
                    .run_cmd("apt-get update", &self.privilege)
                    .unwrap();
                let cmd = "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y";
                let cmd_result = hosthandler.run_cmd(cmd, &self.privilege).unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(String::from("APT upgrade successful")),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("APT upgrade failed")),
                    );
                }
            }
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

fn is_package_installed(hosthandler: &mut ConnectionHandler, package: String) -> bool {
    let test = hosthandler
        .run_cmd(format!("dpkg -s {}", package).as_str(), &Privilege::Usual)
        .unwrap();

    if test.rc == 0 && test.stdout.contains("Status: install") {
        true
    } else if test.rc == 0 && test.stdout.contains("Status: deinstall") {
        false
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn parsing_apt_module_block_from_yaml_str() {
        let raw_tasklist_description = "---
- name: Dummy steps to test deserialization and syntax of this module
  steps:
    - name: Package must be present
      apt:
        package: apache2
        state: present
    - name: Package must be absent
      apt:
        package: apache2
        state: absent
    - name: Package must be present with upgrade
      apt:
        package: apache2
        state: present
        upgrade: true
        ";

        let parsed_tasklist = TaskList::from_str(raw_tasklist_description, TaskListFormat::Yaml);

        assert!(parsed_tasklist.is_ok());
    }
}
