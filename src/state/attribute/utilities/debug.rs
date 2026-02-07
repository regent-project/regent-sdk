use crate::error::Error;
use crate::managed_host::InternalApiCallOutcome;
use crate::managed_host::{AssessCompliance, ReachCompliance};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugBlockExpectedState {
    msg: String,
    // var: Option<String>, // TODO
}

// impl Check for DebugBlockExpectedState {
//     fn check(&self) -> Result<(), Error> {
//         Ok(())
//     }
// }

impl<Handler: HostHandler> AssessCompliance<Handler> for DebugBlockExpectedState {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<Option<Vec<Remediation>>, Error> {
        return Ok(Some(Vec::from([Remediation::None(self.msg.clone())])));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DebugApiCall {}

impl<Handler: HostHandler> ReachCompliance<Handler>  for DebugApiCall {
    // fn display(&self) -> String {
    //     "Debug module".into()
    // }

    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error> {
        Ok(InternalApiCallOutcome::Success)
    }
}
