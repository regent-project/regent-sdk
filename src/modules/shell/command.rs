// Command module : <short description>

use crate::connection::hosthandler::ConnectionHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::Check;
use crate::task::moduleblock::ModuleApiCall;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandBlockExpectedState {
    content: String,
}

impl Check for CommandBlockExpectedState {
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl DryRun for CommandBlockExpectedState {
    fn dry_run_block(
        &self,
        _hosthandler: &mut ConnectionHandler,
        privilege: &Privilege,
    ) -> Result<StepChange, Error> {
        let mut changes: Vec<ModuleApiCall> = Vec::new();

        let privilege = privilege.clone();

        changes.push(ModuleApiCall::Command(CommandApiCall {
            cmd: self.content.clone(),
            privilege,
        }));

        return Ok(StepChange::changes(changes));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandApiCall {
    pub cmd: String,
    privilege: Privilege,
}

impl Apply for CommandApiCall {
    fn display(&self) -> String {
        return format!("Run command : {}", self.cmd);
    }

    fn apply_moduleblock_change(&self, hosthandler: &mut ConnectionHandler) -> ApiCallResult {
        let cmd_result = hosthandler
            .run_cmd(self.cmd.as_str(), &self.privilege)
            .unwrap();

        if cmd_result.rc == 0 {
            return ApiCallResult::from(
                Some(cmd_result.rc),
                Some(cmd_result.stdout),
                ApiCallStatus::ChangeSuccessful(String::from("Command successful")),
            );
        } else {
            return ApiCallResult::from(
                Some(cmd_result.rc),
                Some(cmd_result.stdout),
                ApiCallStatus::Failure(String::from("Command failed")),
            );
        }
    }
}
