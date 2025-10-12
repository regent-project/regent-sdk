// APT Module : handle packages in Debian-like distributions

use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::ApiCallResult;
use crate::step::stepchange::StepChange;
use crate::task::moduleblock::{Apply, DryRun};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingBlockExpectedState {}

impl DryRun for PingBlockExpectedState {
    fn dry_run_block(
        &self,
        hosthandler: &mut HostHandler,
        privilege: Privilege,
    ) -> Result<StepChange, Error> {
        let cmd = String::from("DEBIAN_FRONTEND=noninteractive id");
        let cmd_result = hosthandler.run_cmd(cmd.as_str(), privilege)?;

        if cmd_result.rc == 0 {
            return Ok(StepChange::AlreadyMatched("Host reachable".to_string()));
        } else {
            return Err(Error::FailedDryRunEvaluation(
                "Host unreachable".to_string(),
            ));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingApiCall {
    privilege: Privilege,
}

impl Apply for PingApiCall {
    fn display(&self) -> String {
        return format!("Check SSH connectivity with remote host");
    }

    fn apply_moduleblock_change(&self, _hosthandler: &mut HostHandler) -> ApiCallResult {
        return ApiCallResult::none();
    }
}
