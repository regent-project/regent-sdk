use crate::connection::hosthandler::HostHandler;
use crate::result::apicallresult::ApiCallResult;
use crate::step::stepresult::StepResult;
use crate::task::moduleblock::Apply;
use crate::task::moduleblock::ModuleApiCall;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepChange {
    AlreadyMatched(String),
    ModuleApiCalls(Vec<ModuleApiCall>),
}

impl StepChange {
    pub fn matched(message: &str) -> StepChange {
        StepChange::AlreadyMatched(message.to_string())
    }

    pub fn changes(changes: Vec<ModuleApiCall>) -> StepChange {
        StepChange::ModuleApiCalls(changes)
    }

    pub fn display(&self) -> Vec<String> {
        match self {
            StepChange::AlreadyMatched(message) => {
                return Vec::from([message.clone()]);
            }
            StepChange::ModuleApiCalls(changeslist) => {
                let mut display_contents: Vec<String> = Vec::new();
                for change in changeslist {
                    let apicalldisplay = match change {
                        ModuleApiCall::None(message) => message.clone(),
                        // **BEACON_1**
                        ModuleApiCall::Debug(block) => block.display(),
                        ModuleApiCall::Service(block) => block.display(),
                        ModuleApiCall::LineInFile(block) => block.display(),
                        ModuleApiCall::Command(block) => block.display(),
                        ModuleApiCall::Apt(block) => block.display(),
                        ModuleApiCall::Ping(block) => block.display(),
                        ModuleApiCall::YumDnf(block) => block.display(),
                    };
                    display_contents.push(apicalldisplay);
                }
                return display_contents;
            }
        }
    }

    pub fn apply_moduleblockchange(&self, hosthandler: &mut HostHandler) -> StepResult {
        let raw_step_result = match self {
            StepChange::AlreadyMatched(_message) => return StepResult::none(),
            StepChange::ModuleApiCalls(changeslist) => {
                let mut results: Vec<ApiCallResult> = Vec::new();
                for change in changeslist {
                    let apicallresult = match change {
                        ModuleApiCall::None(_) => ApiCallResult::none(),
                        // **BEACON_2**
                        ModuleApiCall::Service(block) => {
                            block.apply_moduleblock_change(hosthandler)
                        }
                        ModuleApiCall::Debug(block) => block.apply_moduleblock_change(hosthandler),
                        ModuleApiCall::LineInFile(block) => {
                            block.apply_moduleblock_change(hosthandler)
                        }
                        ModuleApiCall::Command(block) => {
                            block.apply_moduleblock_change(hosthandler)
                        }
                        ModuleApiCall::Apt(block) => block.apply_moduleblock_change(hosthandler),
                        ModuleApiCall::Ping(block) => block.apply_moduleblock_change(hosthandler),
                        ModuleApiCall::YumDnf(block) => block.apply_moduleblock_change(hosthandler),
                    };
                    results.push(apicallresult);
                }
                StepResult::from(&results)
            }
        };

        let mut step_result = StepResult::new();

        // As JSON doesn't allow control characters in String fields, they need to be removed/replaced by spaces.
        // Otherwise, Tera can't display these fields.
        for result in raw_step_result.apicallresults.iter() {
            step_result.apicallresults.push(ApiCallResult {
                rc: result.rc,
                output: result.output.clone(),
                status: result.status.clone(),
            })
        }

        return step_result;
    }
}
