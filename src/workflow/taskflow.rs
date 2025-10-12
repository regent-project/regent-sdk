use crate::connection::hosthandler::HostHandler;
use crate::error::Error;
use crate::task::taskblock::TaskBlock;
use crate::workflow::stepflow::{StepFlow, StepStatus};
use serde::{Deserialize, Serialize};

/// A TaskFlow withholds all step flows, a flow being being the combination of :
/// - an expected state
/// - changes required to have the host match this expected state
/// - results of actually trying to enforce these changes
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TaskFlow {
    pub name: Option<String>,
    pub with_sudo: Option<bool>,
    pub step_flows: Vec<StepFlow>,
    pub task_status: TaskStatus,
}

impl TaskFlow {
    pub fn new() -> TaskFlow {
        TaskFlow {
            name: None,
            with_sudo: None,
            step_flows: Vec::new(),
            task_status: TaskStatus::NotRunYet,
        }
    }

    pub fn from(task_block: TaskBlock) -> TaskFlow {
        let mut task_flow = TaskFlow::new();

        for step in task_block.steps.iter() {
            task_flow.step_flows.push(StepFlow::from(step.clone()));
        }
        task_flow.name = task_block.name;
        task_flow.with_sudo = task_block.with_sudo;

        task_flow
    }

    pub fn dry_run(
        &mut self,
        hosthandler: &mut HostHandler,
        tera_context: &mut tera::Context,
    ) -> Result<(), Error> {
        let mut changes_required = false;

        for step_flow in self.step_flows.iter_mut() {
            match step_flow.dry_run(hosthandler, tera_context) {
                Ok(()) => {
                    if let StepStatus::ChangeRequired = step_flow.step_status {
                        changes_required = true;
                    }
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }

        if changes_required {
            self.task_status = TaskStatus::ChangeRequired;
        } else {
            self.task_status = TaskStatus::AlreadyMatched;
        }

        Ok(())
    }

    pub fn apply(
        &mut self,
        hosthandler: &mut HostHandler,
        tera_context: &mut tera::Context,
    ) -> Result<(), Error> {
        let mut task_status = TaskStatus::ApplySuccesful;

        for step_flow in self.step_flows.iter_mut() {
            match step_flow.apply(hosthandler, tera_context) {
                Ok(()) => match &step_flow.step_status {
                    StepStatus::ApplyFailed => {
                        task_status = TaskStatus::ApplyFailed;
                        break;
                    }
                    StepStatus::ApplyFailedButAllowed => {
                        task_status = TaskStatus::ApplyFailedButAllowed;
                    }
                    _ => {}
                },
                Err(error) => {
                    return Err(error);
                }
            }
        }
        self.task_status = task_status;

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum TaskStatus {
    NotRunYet,
    AlreadyMatched,
    ChangeRequired,
    ApplySuccesful,
    ApplyFailedButAllowed,
    ApplyFailed,
}
