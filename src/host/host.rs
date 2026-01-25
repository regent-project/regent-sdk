use crate::connection::hosthandler::ConnectionHandler;
use crate::connection::hosthandler::NewConnectionDetails;
use crate::connection::specification::Privilege;
use crate::expected_state::global_state::{CompliancyStatus, DryRunMode};
use crate::step::stepchange::StepChange;
use crate::step::stepresult::StepApplyResult;
use crate::task::moduleblock::ModuleApiCall;
use crate::{error::Error, expected_state::global_state::ExpectedState};
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
    connection_details: NewConnectionDetails,
    connection_handler: ConnectionHandler,
    privilege: Privilege,
}

impl ManagedHost {
    pub fn from(
        connection_details: NewConnectionDetails,
        privilege: Privilege,
    ) -> Result<ManagedHost, Error> {
        match ConnectionHandler::from(&connection_details) {
            Ok(connection_handler) => Ok(ManagedHost {
                connection_details,
                connection_handler,
                privilege,
            }),
            Err(error_detail) => Err(error_detail),
        }
    }

    pub fn assess_compliance_with(
        &mut self,
        expected_state: &ExpectedState,
        dry_run_mode: DryRunMode,
    ) -> Result<CompliancyStatus, Error> {
        let mut compliant = true;
        let mut all_changes: Vec<ModuleApiCall> = Vec::new();

        match dry_run_mode {
            DryRunMode::Sequential => {
                for attribute in &expected_state.attributes {
                    match attribute
                        .dry_run_moduleblock(&mut self.connection_handler, &self.privilege)
                    {
                        Ok(step_change) => {
                            if let StepChange::ModuleApiCalls(changes) = step_change {
                                compliant = false;
                                all_changes.extend(changes);
                            }
                        }
                        Err(error_detail) => {
                            return Err(error_detail);
                        }
                    }
                }
            }
            DryRunMode::Parallel => {
                let (sender, receiver) = std::sync::mpsc::channel::<StepChange>();

                for attribute in &expected_state.attributes {
                    std::thread::spawn({
                        let privilege = self.privilege.clone();
                        let attribute = attribute.clone();
                        let sender_clone = sender.clone();
                        let mut connection_handler =
                            ConnectionHandler::from(&self.connection_details).unwrap();
                        move || {
                            let step_change = attribute
                                .dry_run_moduleblock(&mut connection_handler, &privilege)
                                .unwrap();
                            sender_clone.send(step_change).unwrap();
                        }
                    });
                }

                for _ in 0..expected_state.attributes.len() {
                    match receiver.recv() {
                        Ok(step_change) => {
                            if let StepChange::ModuleApiCalls(changes) = step_change {
                                compliant = false;
                                all_changes.extend(changes);
                            }
                        }
                        Err(error_detail) => {
                            return Err(Error::FailedDryRunEvaluation(format!("{}", error_detail)));
                        }
                    }
                }
            }
        }

        if compliant {
            Ok(CompliancyStatus::Compliant)
        } else {
            Ok(CompliancyStatus::NotCompliant(all_changes))
        }
    }

    pub fn try_reach_compliance_with(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<(), Error> {
        for attribute in &expected_state.attributes {
            match attribute.dry_run_moduleblock(&mut self.connection_handler, &self.privilege) {
                Ok(step_change) => {
                    let step_result =
                        step_change.apply_moduleblockchange(&mut self.connection_handler);
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
