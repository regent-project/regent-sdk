use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::ApiCallResult;
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DebugBlockExpectedState {
    msg: String,
    // var: Option<String>, // TODO
}

impl DryRun for DebugBlockExpectedState {
    fn dry_run_block(
        &self,
        _hosthandler: &mut HostHandler,
        _privilege: Privilege,
    ) -> Result<StepChange, Error> {
        return Ok(StepChange::matched(self.msg.as_str()));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DebugApiCall {}

impl Apply for DebugApiCall {
    fn display(&self) -> String {
        "Debug module".into()
    }

    fn apply_moduleblock_change(&self, _hosthandler: &mut HostHandler) -> ApiCallResult {
        return ApiCallResult::none();
    }
}
