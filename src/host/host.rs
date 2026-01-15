use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::expected_state::global_state::{CompliancyStatus, DryRunMode};
use crate::step::stepchange::StepChange;
use crate::step::stepresult::StepApplyResult;
use crate::{error::Error, expected_state::global_state::ExpectedState, prelude::HostConnectionInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// TODO : add a connection mode field
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Host {
    pub address: String,
    pub vars: Option<HashMap<String, String>>,
    pub groups: Option<Vec<String>>,
}

impl Host {
    pub fn new() -> Host {
        Host {
            address: String::new(),
            vars: None,
            groups: None,
        }
    }

    pub fn from_string(address: String) -> Host {
        Host {
            address,
            vars: None,
            groups: None,
        }
    }

    pub fn add_to_group(&mut self, groupname: &String) {
        match &self.groups {
            Some(group_list) => {
                let mut new_group_list = group_list.clone();
                new_group_list.push(groupname.clone());
                self.groups = Some(new_group_list);
            }
            None => {
                self.groups = Some(vec![groupname.clone()]);
            }
        }
    }

    pub fn add_vars(&mut self, newvars: &HashMap<String, String>) {
        match &self.vars {
            Some(oldvars) => {
                let mut new_vars_list = oldvars.clone();
                new_vars_list.extend(newvars.clone());
                self.vars = Some(new_vars_list);
            }
            None => {
                self.vars = Some(newvars.clone());
            }
        }
    }

    pub fn add_var(&mut self, key: &str, value: &str) {
        match &self.vars {
            Some(oldvars) => {
                let mut new_vars_list = oldvars.clone();
                new_vars_list.insert(key.into(), value.into());
                self.vars = Some(new_vars_list);
            }
            None => {
                let mut new_vars = HashMap::new();
                new_vars.insert(key.into(), value.into());
                self.vars = Some(new_vars);
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Group {
    pub name: String,
    pub vars: Option<HashMap<String, String>>,
    pub hosts: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct ManagedHost {
    // address: String,
    // connection_info: ConnectionInfo,
    host_handler: HostHandler,
    privilege: Privilege,
}

impl ManagedHost {
    pub fn from(
        address: &str,
        connection_info: HostConnectionInfo,
        privilege: Privilege,
    ) -> ManagedHost {
        ManagedHost {
            host_handler: HostHandler::from(address.to_string(), connection_info).unwrap(),
            privilege,
        }
    }

    pub fn assess_compliance_with(
        &mut self,
        expected_state: &ExpectedState,
        dry_run_mode: DryRunMode,
    ) -> Result<CompliancyStatus, Error> {
        match dry_run_mode {
            DryRunMode::Sequential => {
                for attribute in &expected_state.attributes {
                    match attribute
                        .dry_run_moduleblock(&mut self.host_handler, self.privilege.clone())
                    {
                        Ok(step_change) => {
                            if let StepChange::ModuleApiCalls(_module_api_calls) = step_change {
                                return Ok(CompliancyStatus::NotCompliant);
                            }
                        }
                        Err(error_detail) => {
                            return Err(error_detail);
                        }
                    }
                }

                Ok(CompliancyStatus::Compliant)
            }
            DryRunMode::Parallel => {
                let mut join_handles = Vec::new();
                for attribute in &expected_state.attributes {
                    // Async ? std::thread ? rayon ?
                    let attribute_thread_join_handle = std::thread::spawn({
                        let mut host_handler = self.host_handler.clone();
                        let privilege = self.privilege.clone();
                        let attribute = attribute.clone();
                        move || attribute.dry_run_moduleblock(&mut host_handler, privilege)
                    });

                    join_handles.push(attribute_thread_join_handle);
                }

                for join_handle in join_handles {
                    match join_handle.join() {
                        Ok(Ok(StepChange::ModuleApiCalls(_module_api_calls))) => {
                            return Ok(CompliancyStatus::NotCompliant);
                        }
                        Ok(Err(error_detail)) => {
                            // One step failed. return
                            return Err(Error::FailedTaskDryRun(format!("{:?}", error_detail)));
                        }
                        Err(error_detail) => {
                            // One step failed. return
                            return Err(Error::FailedTaskDryRun(format!("{:?}", error_detail)));
                        }
                        _ => {}
                    }
                }

                Ok(CompliancyStatus::Compliant)
            }
        }
    }

    pub fn try_reach_compliance_with(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<(), Error> {
        for attribute in &expected_state.attributes {
            match attribute.dry_run_moduleblock(&mut self.host_handler, self.privilege.clone()) {
                Ok(step_change) => {
                    let step_result = step_change.apply_moduleblockchange(&mut self.host_handler);
                    if let StepApplyResult::Failed(details) = step_result.assess_result() {
                        return Err(Error::FailedToApplyExpectedState(details));
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        Ok(())
    }
}
