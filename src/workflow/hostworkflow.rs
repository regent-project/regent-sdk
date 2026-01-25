use crate::connection::hosthandler::ConnectionHandler;
use crate::error::Error;
use crate::task::tasklist::TaskList;
use crate::workflow::taskflow::{TaskFlow, TaskStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostWorkFlow {
    pub task_flows: Vec<TaskFlow>,
    pub final_status: HostWorkFlowStatus,
}

impl HostWorkFlow {
    pub fn new() -> HostWorkFlow {
        HostWorkFlow {
            task_flows: Vec::new(),
            final_status: HostWorkFlowStatus::NotRunYet,
        }
    }

    pub fn from(task_list: &TaskList) -> HostWorkFlow {
        let mut task_flows: Vec<TaskFlow> = Vec::new();

        for task_block in task_list.tasks.iter() {
            task_flows.push(TaskFlow::from(task_block.clone()))
        }

        HostWorkFlow {
            task_flows,
            final_status: HostWorkFlowStatus::NotRunYet,
        }
    }

    pub fn dry_run(
        &mut self,
        hosthandler: &mut ConnectionHandler,
        tera_context: &mut tera::Context,
    ) -> Result<(), Error> {
        let mut changes_required = false;

        for task_flow in self.task_flows.iter_mut() {
            match task_flow.dry_run(hosthandler, tera_context) {
                Ok(()) => {
                    if let TaskStatus::ChangeRequired = task_flow.task_status {
                        changes_required = true;
                    }
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }

        if changes_required {
            self.final_status = HostWorkFlowStatus::ChangeRequired;
        } else {
            self.final_status = HostWorkFlowStatus::AlreadyMatched;
        }

        Ok(())
    }

    pub fn apply(
        &mut self,
        hosthandler: &mut ConnectionHandler,
        tera_context: &mut tera::Context,
    ) -> Result<(), Error> {
        if let HostWorkFlowStatus::AlreadyMatched = self.final_status {
            // Nothing to do, dry_run was performed before and concluded that nothing is to be
        } else {
            let mut already_matched = true;
            let mut allowed_failures = false;
            let mut failures = false;

            for task_flow in self.task_flows.iter_mut() {
                match task_flow.apply(hosthandler, tera_context) {
                    Ok(()) => match task_flow.task_status {
                        TaskStatus::ApplySuccesful => {
                            already_matched = false;
                        }
                        TaskStatus::AlreadyMatched => {}
                        TaskStatus::ApplyFailed => {
                            failures = true;
                            already_matched = false;
                        }
                        TaskStatus::ApplyFailedButAllowed => {
                            allowed_failures = true;
                            already_matched = false;
                        }
                        _ => {}
                    },
                    Err(error) => {
                        return Err(error);
                    }
                }
            }

            if already_matched {
                self.final_status = HostWorkFlowStatus::AlreadyMatched;
            } else if allowed_failures {
                self.final_status = HostWorkFlowStatus::ApplyWithAllowedFailure;
            } else if failures {
                self.final_status = HostWorkFlowStatus::ApplyFailed;
            } else {
                self.final_status = HostWorkFlowStatus::ApplySuccesful;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostWorkFlowStatus {
    NotRunYet,
    AlreadyMatched,
    ChangeRequired,
    ApplySuccesful,
    ApplyWithAllowedFailure,
    ApplyFailed,
    DryRunFailed,
    ConnectionInitFailed(String),
}
