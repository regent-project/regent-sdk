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
enum ServiceModuleInternalApiCall {
    Start(String),
    Stop(String),
    Enable(String),
    Disable(String)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum ServiceExpectedState {
    Started,
    Stopped
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceBlockExpectedState {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lowercase")]
    state: Option<ServiceExpectedState>,
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
                    match state_content {
                        ServiceExpectedState::Started => {
                            if service_is_running {
                                changes.push(ModuleApiCall::None(format!(
                                    "{} already running",
                                    &self.name
                                )));
                            } else {
                                // Service needs to be started
                                changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Start(self.name.clone()),
                                    privilege.clone(),
                                )));
                            }
                        }
                        ServiceExpectedState::Stopped => {
                            if service_is_running {
                                // Service needs to be stopped
                                changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                                    ServiceModuleInternalApiCall::Stop(self.name.clone()),
                                    privilege.clone(),
                                )));
                            } else {
                                changes.push(ModuleApiCall::None(format!(
                                    "{} already stopped",
                                    &self.name
                                )));
                            }
                        }
                    }
                }
                None => {}
            }

            if let Some(service_must_be_enabled) = self.enabled {
                if service_must_be_enabled {
                    if service_is_enabled {
                        changes.push(ModuleApiCall::None(format!(
                            "{} already enabled",
                            &self.name
                        )));
                    } else {
                        // SERVICE MUST BE ENABLED
                        changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                            ServiceModuleInternalApiCall::Enable(self.name.clone()),
                            privilege.clone(),
                        )));
                    }
                } else {
                    if service_is_enabled {
                        // SERVICE MUST BE DISABLED
                        changes.push(ModuleApiCall::Service(ServiceApiCall::from(
                            ServiceModuleInternalApiCall::Disable(self.name.clone()),
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
    api_call: ServiceModuleInternalApiCall,
    privilege: Privilege,
}

impl Apply for ServiceApiCall {
    fn display(&self) -> String {
        match &self.api_call {
            ServiceModuleInternalApiCall::Start(service_name) => {
                return format!("Start service {}", service_name);
            }
            ServiceModuleInternalApiCall::Stop(service_name) => {
                return format!("Stop service {}", service_name);
            }
            ServiceModuleInternalApiCall::Enable(service_name) => {
                return format!("Enable service {}", service_name);
            }
            ServiceModuleInternalApiCall::Disable(service_name) => {
                return format!("Disable service {}", service_name);
            }
        }
    }

    fn apply_moduleblock_change(&self, hosthandler: &mut HostHandler) -> ApiCallResult {
        match &self.api_call {
            ServiceModuleInternalApiCall::Start(service_name) => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl start {}", service_name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} started", service_name)),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to start service")),
                    );
                }
            }
            ServiceModuleInternalApiCall::Stop(service_name) => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl stop {}", service_name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} stopped", service_name)),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to stop service")),
                    );
                }
            }
            ServiceModuleInternalApiCall::Enable(service_name) => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl enable {}", service_name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} enabled", service_name)),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to enable service")),
                    );
                }
            }
            ServiceModuleInternalApiCall::Disable(service_name) => {
                let cmd_result = hosthandler
                    .run_cmd(
                        format!("systemctl disable {}", service_name).as_str(),
                        self.privilege.clone(),
                    )
                    .unwrap();

                if cmd_result.rc == 0 {
                    ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::ChangeSuccessful(format!("{} disabled", service_name)),
                    )
                } else {
                    return ApiCallResult::from(
                        Some(cmd_result.rc),
                        Some(cmd_result.stdout),
                        ApiCallStatus::Failure(String::from("Failed to disable service")),
                    );
                }
            }
        }
    }
}

impl ServiceApiCall {
    fn from(api_call: ServiceModuleInternalApiCall, privilege: Privilege) -> ServiceApiCall {
        ServiceApiCall {
            api_call,
            privilege,
        }
    }
}

fn service_is_active(hosthandler: &mut HostHandler, service_name: &String) -> Result<bool, String> {
    match hosthandler.run_cmd(
        format!("systemctl is-active {}", service_name).as_str(),
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

fn service_is_enabled(hosthandler: &mut HostHandler, service_name: &String) -> Result<bool, String> {
    match hosthandler.run_cmd(
        format!("systemctl is-enabled {}", service_name).as_str(),
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


#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn parsing_service_module_block_from_yaml_str() {
        let raw_tasklist_description = "---
- name: Dummy steps to test deserialization and syntax of this module
  steps:
    - name: Service must be started and enabled
      service:
        name: apache2
        state: started
        enabled: true
    - name: Service must be stopped and disabled
      service:
        name: apache2
        state: stopped
        enabled: false
        ";

        let parsed_tasklist = TaskList::from_str(raw_tasklist_description, TaskListFileType::Yaml);

        assert!(parsed_tasklist.is_ok());
        
    }
}