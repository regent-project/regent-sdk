// YUM / DNF Module : handle packages in Fedora-like distributions

use crate::task::moduleblock::Check;
use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::ModuleApiCall;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum YumDnfModuleInternalApiCall {
    Install(String),
    Remove(String),
    Upgrade
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageExpectedState {
    Present,
    Absent
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
        YumDnfBlockExpectedState { state: None, package: None, upgrade: None }
    }

    pub fn with_system_upgrade(&mut self) -> &mut Self {
        self.upgrade = Some(true);
        self
    }

    pub fn with_package_state(&mut self, package_name: &str, package_state: PackageExpectedState) -> &mut Self {
        self.package = Some(package_name.to_string());
        self.state = Some(package_state);
        self
    }

    pub fn build(&self) -> Result<YumDnfBlockExpectedState, Error> {
        if let Err(error_detail) = self.check() {
            return Err(error_detail);
        }
        Ok(self.clone())
    }
}

impl Check for YumDnfBlockExpectedState {
    fn check(&self) -> Result<(), Error> {
        if let (None, None, None) = (&self.state, &self.package, self.upgrade) {
            return Err(Error::IncoherentExpectedState(
                format!("All parameters are unset. Please describe the expected state.")
            ));
        }
        if let (None, Some(package_name)) = (&self.state, &self.package) {
            return Err(Error::IncoherentExpectedState(
                format!("Missing 'state' parameter. What is the expected state of the package ({}) ?", package_name)
            ));
        }
        if let (Some(package_expected_state), None) = (&self.state, &self.package) {
            return Err(Error::IncoherentExpectedState(
                format!("Missing 'package' parameter. Which package should be {:?} ?", package_expected_state)
            ));
        }
        Ok(())
    }
}

#[allow(unused_assignments)] // 'package_manager' is never actually read, only borrowed
impl DryRun for YumDnfBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut HostHandler,
        privilege: Privilege,
    ) -> Result<StepChange, Error> {
        let package_manager: RedHatFlavoredPackageManager;

        if hosthandler.is_this_cmd_available("dnf").unwrap() {
            package_manager = RedHatFlavoredPackageManager::Dnf;
        } else if hosthandler.is_this_cmd_available("yum").unwrap() {
            package_manager = RedHatFlavoredPackageManager::Yum;
        } else {
            return Err(Error::FailedDryRunEvaluation(
                "Neither YUM nor DNF work on this host".to_string(),
            ));
        }

        let mut changes: Vec<ModuleApiCall> = Vec::new();

        match &self.state {
            None => {}
            Some(state) => {
                match state {
                    PackageExpectedState::Present => {
                        // Check is package is already installed or needs to be
                        if is_package_installed(
                            hosthandler,
                            &package_manager,
                            self.package.clone().unwrap(),
                            privilege.clone(),
                        ) {
                            changes.push(ModuleApiCall::None(format!(
                                "{} already present",
                                self.package.clone().unwrap()
                            )));
                        } else {
                            // Package is absent and needs to be installed
                            changes.push(ModuleApiCall::YumDnf(YumDnfApiCall::from(
                                YumDnfModuleInternalApiCall::Install(self.package.clone().unwrap()),
                                package_manager.clone(),
                                privilege.clone(),
                            )));
                        }
                    }
                    PackageExpectedState::Absent => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(
                            hosthandler,
                            &package_manager,
                            self.package.clone().unwrap(),
                            privilege.clone(),
                        ) {
                            // Package is present and needs to be removed
                            changes.push(ModuleApiCall::YumDnf(YumDnfApiCall::from(
                                YumDnfModuleInternalApiCall::Remove(self.package.clone().unwrap()),
                                package_manager.clone(),
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
        // TODO : have this to do a "dnf check-update" only
        // If updates available -> ApiCall, if not, Matched
        if let Some(value) = self.upgrade {
            if value {
                changes.push(ModuleApiCall::YumDnf(YumDnfApiCall::from(
                    YumDnfModuleInternalApiCall::Upgrade,
                    package_manager,
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
enum RedHatFlavoredPackageManager {
    Yum,
    Dnf
}

impl RedHatFlavoredPackageManager {
    fn command_name(&self) -> &str {
        match self {
            RedHatFlavoredPackageManager::Dnf => "dnf",
            RedHatFlavoredPackageManager::Yum => "yum"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct YumDnfApiCall {
    api_call: YumDnfModuleInternalApiCall,
    package_manager: RedHatFlavoredPackageManager,
    privilege: Privilege,
}

impl Apply for YumDnfApiCall {
    fn display(&self) -> String {
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

    fn apply_moduleblock_change(&self, hosthandler: &mut HostHandler) -> ApiCallResult {
        match &self.api_call {
            YumDnfModuleInternalApiCall::Install(package_name) => {
                let cmd = format!("{} install -y {}", self.package_manager.command_name(), package_name);
                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

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
                        ApiCallStatus::Failure(format!(
                            "{} install failed",
                            package_name
                        )),
                    );
                }
            }
            YumDnfModuleInternalApiCall::Remove(package_name) => {
                let cmd = format!("{} remove -y {}", self.package_manager.command_name(), package_name);
                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

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
                        ApiCallStatus::Failure(format!(
                            "{} removal failed",
                            package_name
                        )),
                    );
                }
            }
            YumDnfModuleInternalApiCall::Upgrade => {
                let cmd = format!("{} update -y --refresh", self.package_manager.command_name());
                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(String::from("Yum/DNF upgrade successful")),
                    );
                } else {
                    println!("------{}", cmd_result.stdout);
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Yum/DNF upgrade failed")),
                    );
                }
            }
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

fn is_package_installed(
    hosthandler: &mut HostHandler,
    package_manager: &RedHatFlavoredPackageManager,
    package_name: String,
    privilege: Privilege,
) -> bool {
    let test = hosthandler
        .run_cmd(
            format!("{} list installed {}", package_manager.command_name(), package_name).as_str(),
            privilege,
        )
        .unwrap();

    if test.rc == 0 {
        return true;
    } else {
        return false;
    }
}


#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn parsing_yumdnf_module_block_from_yaml_str() {
        let raw_tasklist_description = "---
- name: Dummy steps to test deserialization and syntax of this module
  steps:
    - name: Package must be present (yum)
      yum:
        package: httpd
        state: present
    - name: Package must be present (dnf)
      dnf:
        package: httpd
        state: present
        ";

        let parsed_tasklist = TaskList::from_str(raw_tasklist_description, TaskListFileType::Yaml);

        assert!(parsed_tasklist.is_ok());
        
    }
}