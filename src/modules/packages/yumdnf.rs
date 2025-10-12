// YUM / DNF Module : handle packages in Fedora-like distributions

use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::ModuleApiCall;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct YumDnfBlockExpectedState {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upgrade: Option<bool>,
}

#[allow(unused_assignments)] // 'tool' is never actually read, only borrowed
impl DryRun for YumDnfBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut HostHandler,
        privilege: Privilege,
    ) -> Result<StepChange, Error> {
        let mut tool = String::new();

        if hosthandler.is_this_cmd_available("dnf").unwrap() {
            tool = String::from("dnf");
        } else if hosthandler.is_this_cmd_available("yum").unwrap() {
            tool = String::from("yum");
        } else {
            return Err(Error::FailedDryRunEvaluation(
                "Neither YUM nor DNF work on this host".to_string(),
            ));
        }

        let mut changes: Vec<ModuleApiCall> = Vec::new();

        match &self.state {
            None => {}
            Some(state) => {
                match state.as_str() {
                    "present" => {
                        // Check is package is already installed or needs to be
                        if is_package_installed(
                            hosthandler,
                            &tool,
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
                                "install",
                                &tool,
                                Some(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        }
                    }
                    "absent" => {
                        // Check is package is already absent or needs to be removed
                        if is_package_installed(
                            hosthandler,
                            &tool,
                            self.package.clone().unwrap(),
                            privilege.clone(),
                        ) {
                            // Package is present and needs to be removed
                            changes.push(ModuleApiCall::YumDnf(YumDnfApiCall::from(
                                "remove",
                                &tool,
                                Some(self.package.clone().unwrap()),
                                privilege.clone(),
                            )));
                        } else {
                            changes.push(ModuleApiCall::None(format!(
                                "{} already absent",
                                self.package.clone().unwrap()
                            )));
                        }
                    }
                    _ => {}
                }
            }
        }
        // TODO : have this to do a "dnf check-update" only
        // If updates available -> ApiCall, if not, Matched
        if let Some(value) = self.upgrade {
            if value {
                changes.push(ModuleApiCall::YumDnf(YumDnfApiCall::from(
                    "upgrade",
                    &tool,
                    None,
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
pub struct YumDnfApiCall {
    action: String,
    tool: String,
    package: Option<String>,
    privilege: Privilege,
}

impl Apply for YumDnfApiCall {
    fn display(&self) -> String {
        match self.action.as_str() {
            "install" => {
                return format!("Install - {}", self.package.clone().unwrap());
            }
            "remove" => {
                return format!("Remove - {}", self.package.clone().unwrap());
            }
            "upgrade" => {
                return String::from("Upgrade");
            }
            _ => {
                return String::from("Wrong YumDnfApiCall action");
            }
        }
    }

    fn apply_moduleblock_change(&self, hosthandler: &mut HostHandler) -> ApiCallResult {
        match self.action.as_str() {
            "install" => {
                let cmd = format!("{} install -y {}", self.tool, self.package.clone().unwrap());
                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!(
                            "{} install successful",
                            self.package.clone().unwrap()
                        )),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(format!(
                            "{} install failed",
                            self.package.clone().unwrap()
                        )),
                    );
                }
            }
            "remove" => {
                let cmd = format!("{} remove -y {}", self.tool, self.package.clone().unwrap());
                let cmd_result = hosthandler
                    .run_cmd(cmd.as_str(), self.privilege.clone())
                    .unwrap();

                if cmd_result.rc == 0 {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!(
                            "{} removal successful",
                            self.package.clone().unwrap()
                        )),
                    );
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(format!(
                            "{} removal failed",
                            self.package.clone().unwrap()
                        )),
                    );
                }
            }
            "upgrade" => {
                let cmd = format!("{} update -y --refresh", self.tool);
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
            _ => {
                return ApiCallResult::none();
            }
        }
    }
}

impl YumDnfApiCall {
    pub fn from(
        action: &str,
        tool: &String,
        package: Option<String>,
        privilege: Privilege,
    ) -> YumDnfApiCall {
        YumDnfApiCall {
            action: action.to_string(),
            tool: tool.clone(),
            package,
            privilege,
        }
    }
}

fn is_package_installed(
    hosthandler: &mut HostHandler,
    tool: &String,
    package: String,
    privilege: Privilege,
) -> bool {
    let test = hosthandler
        .run_cmd(
            format!("{tool} list installed {}", package).as_str(),
            privilege,
        )
        .unwrap();

    if test.rc == 0 {
        return true;
    } else {
        return false;
    }
}
