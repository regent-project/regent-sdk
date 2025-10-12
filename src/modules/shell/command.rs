// Command module : <short description>

use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::{ApiCallResult, ApiCallStatus};
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::ModuleApiCall;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandBlockExpectedState {
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
}

impl DryRun for CommandBlockExpectedState {
    fn dry_run_block(
        &self,
        _hosthandler: &mut HostHandler,
        privilege: Privilege,
    ) -> Result<StepChange, Error> {
        let mut changes: Vec<ModuleApiCall> = Vec::new();

        match &self.content {
            None => {
                changes.push(ModuleApiCall::None(String::from("No command to run")));
            }
            Some(cmdcontent) => {
                changes.push(ModuleApiCall::Command(CommandApiCall {
                    cmd: cmdcontent.to_string(),
                    privilege,
                }));
            }
        }
        return Ok(StepChange::changes(changes));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandApiCall {
    cmd: String,
    privilege: Privilege,
}

impl Apply for CommandApiCall {
    fn display(&self) -> String {
        return format!("Run command : {}", self.cmd);
    }

    fn apply_moduleblock_change(&self, hosthandler: &mut HostHandler) -> ApiCallResult {
        let cmd_result = hosthandler
            .run_cmd(self.cmd.as_str(), self.privilege.clone())
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
