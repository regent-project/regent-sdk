// Service Module : handle services running on a host

use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::ModuleApiCall;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceBlockExpectedState {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>, // Either state...
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>, // ... or enabled is required.
}

impl DryRun for ServiceBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut HostHandler,
        privilege: Privilege,
    ) -> Result<StepChange, Error> {
        // Prechecks

        if !hosthandler.is_this_cmd_available("systemctl").unwrap() {
            return Err(Error::FailedDryRunEvaluation(
                "SYSTEMCTL not available on this host".to_string(),
            ));
        }

        let service_is_running = match service_is_active(hosthandler, &self.name) {
            Ok(running_state) => running_state,
            Err(e) => return Err(Error::FailedDryRunEvaluation(e)),
        };

        let service_is_enabled = match service_is_enabled(hosthandler, &self.name) {
            Ok(enabled_state) => enabled_state,
            Err(e) => return Err(Error::FailedDryRunEvaluation(e)),
        };

        // Changes assessment
        let mut changes: Vec<ModuleApiCall> = Vec::new();

        // State or enabled :
        // - one of them is required
        // - mutually exclusive
        if let (None, None) = (&self.state, &self.enabled) {
            // PROBLEM : both 'state' and 'enabled' are empty
            return Err(Error::FailedDryRunEvaluation(
                "STATE and ENABLED fields are both empty in provided Task List".to_string(),
            ));
        } else {
            match &self.state {
                Some(state_content) => {
                    match state_content.as_str() {
                        "started" => {
                            if service_is_running {
                                changes.push(ModuleApiCall::None(format!(
                                    "{} already running",
                                    &self.name
                                )));
                            } else {
                                // Service needs to be started
                                changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                                    self.name.clone(),
                                    "start",
                                    privilege.clone(),
                                )));
                            }
                        }
                        "stopped" => {
                            if service_is_running {
                                // Service needs to be stopped
                                changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                                    self.name.clone(),
                                    "stop",
                                    privilege.clone(),
                                )));
                            } else {
                                changes.push(ModuleApiCall::None(format!(
                                    "{} already stopped",
                                    &self.name
                                )));
                            }
                        }
                        _ => {}
                    }
                }
                None => {}
            }

            match self.enabled {
                Some(service_must_be_enabled) => {
                    if service_must_be_enabled {
                        if service_is_enabled {
                            changes.push(ModuleApiCall::None(format!(
                                "{} already enabled",
                                &self.name
                            )));
                        } else {
                            // SERVICE MUST BE ENABLED
                            changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                                self.name.clone(),
                                "enable",
                                privilege.clone(),
                            )));
                        }
                    } else {
                        if service_is_enabled {
                            // SERVICE MUST BE DISABLED
                            changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                                self.name.clone(),
                                "disable",
                                privilege.clone(),
                            )));
                        } else {
                            changes.push(ModuleApiCall::None(format!(
                                "{} already disabled",
                                &self.name
                            )));
                        }
                    }
                }
                None => {}
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
pub struct ServiceApiCall {
    name: String,
    action: String,
    privilege: Privilege,
}

impl Apply for ServiceApiCall {
    fn display(&self) -> String {
        match self.action.as_str() {
            "start" => {
                return format!("Start service {}", self.name.clone());
            }
            "stop" => {
                return format!("Stop service {}", self.name.clone());
            }
            "enable" => {
                return format!("Enable service {}", self.name.clone());
            }
            "disable" => {
                return format!("Disable service {}", self.name.clone());
            }
            _ => {
                return String::from("Wrong ServiceApiCall action");
            }
        }
    }

    fn apply_moduleblock_change(&self, hosthandler: &mut HostHandler) -> ApiCallResult {
        match self.action.as_str() {
            "start" => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl start {}", self.name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} started", self.name.clone())),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to start service")),
                    );
                }
            }
            "stop" => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl stop {}", self.name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} stopped", self.name.clone())),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to stop service")),
                    );
                }
            }
            "enable" => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl enable {}", self.name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} enabled", self.name.clone())),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to enable service")),
                    );
                }
            }
            "disable" => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl disable {}", self.name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} disabled", self.name.clone())),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to disable service")),
                    );
                }
            }
            _ => ApiCallResult::none(),
        }
    }
}

impl ServiceApiCall {
    pub fn from(name: String, action: &str, privilege: Privilege) -> ServiceApiCall {
        ServiceApiCall {
            name,
            action: action.to_string(),
            privilege,
        }
    }
}

fn service_is_active(hosthandler: &mut HostHandler, name: &String) -> Result<bool, String> {
    match hosthandler.run_cmd(
        format!("systemctl is-active {}", name).as_str(),
        Privilege::Usual,
    ) {
        Ok(test_result) => {
            if test_result.rc == 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(e) => Err(format!("Unable to check service status : {:?}", e)),
    }
}

fn service_is_enabled(hosthandler: &mut HostHandler, name: &String) -> Result<bool, String> {
    match hosthandler.run_cmd(
        format!("systemctl is-enabled {}", name).as_str(),
        Privilege::Usual,
    ) {
        Ok(test_result) => {
            if test_result.rc == 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(e) => Err(format!("Unable to check service status : {:?}", e)),
    }
}
