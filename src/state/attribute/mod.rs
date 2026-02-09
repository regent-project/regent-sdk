pub mod package;
pub mod shell;
pub mod system;
pub mod utilities;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::managed_host::InternalApiCallOutcome;
use crate::state::attribute::package::apt::AptApiCall;
use crate::state::attribute::package::apt::AptBlockExpectedState;
use crate::state::attribute::package::yumdnf::YumDnfApiCall;
use crate::state::attribute::package::yumdnf::YumDnfBlockExpectedState;
use crate::state::attribute::shell::command::CommandApiCall;
use crate::state::attribute::shell::command::CommandBlockExpectedState;
use crate::state::attribute::system::service::ServiceApiCall;
use crate::state::attribute::system::service::ServiceBlockExpectedState;
use crate::state::attribute::utilities::debug::DebugApiCall;
use crate::state::attribute::utilities::debug::DebugBlockExpectedState;
use crate::state::attribute::utilities::lineinfile::LineInFileApiCall;
use crate::state::attribute::utilities::lineinfile::LineInFileBlockExpectedState;
use crate::state::attribute::utilities::ping::PingApiCall;
use crate::state::attribute::utilities::ping::PingBlockExpectedState;
use crate::state::compliance::AttributeComplianceStatus;
use crate::{
    host_handler::{host_handler::HostHandler, privilege::Privilege},
    managed_host::{AssessCompliance, ReachCompliance},
    state::attribute::package::pacman::{PacmanApiCall, PacmanBlockExpectedState},
};
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::AttributeComplianceResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub privilege: Privilege,
    detail: AttributeDetail,
}

impl Attribute {
    pub fn from(detail: AttributeDetail, privilege: Privilege) -> Attribute {
        Attribute { privilege, detail }
    }

    /// Result because the assessment might fail. If it succeeds, it will return either None (AKA already compliant) or Some(Vec<Remediation>) (AKA what shall be done to reach the expected state).
    pub fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
    ) -> Result<AttributeComplianceAssessment, Error> {
        self.detail.assess(host_handler, &self.privilege)
    }

    pub fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
    ) -> Result<AttributeComplianceResult, Error> {
        self.detail.reach_compliance(host_handler, &self.privilege)
    }

    pub fn apt(details: AptBlockExpectedState, privilege: Privilege) -> Attribute {
        Attribute::from(AttributeDetail::Apt(details), privilege)
    }

    pub fn pacman(details: PacmanBlockExpectedState, privilege: Privilege) -> Attribute {
        Attribute::from(AttributeDetail::Pacman(details), privilege)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttributeDetail {
    Apt(AptBlockExpectedState),
    YumDnf(YumDnfBlockExpectedState),
    Pacman(PacmanBlockExpectedState),
    LineInFile(LineInFileBlockExpectedState),
    Debug(DebugBlockExpectedState),
    Ping(PingBlockExpectedState),
    Service(ServiceBlockExpectedState),
    Command(CommandBlockExpectedState),
}

impl AttributeDetail {
    pub fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error> {
        match self {
            AttributeDetail::Apt(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::YumDnf(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::Pacman(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::LineInFile(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::Debug(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::Ping(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::Service(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
            AttributeDetail::Command(expected_state_criteria) => {
                expected_state_criteria.assess_compliance(host_handler, privilege)
            }
        }
    }

    pub fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceResult, Error> {
        match self.assess(host_handler, privilege) {
            Ok(attribute_compliance) => match attribute_compliance {
                AttributeComplianceAssessment::Compliant => Ok(AttributeComplianceResult::from(AttributeComplianceStatus::AlreadyCompliant, None)),
                AttributeComplianceAssessment::NonCompliant(remediations) => {
                    if remediations.len() == 0 {
                        return Err(Error::InternalLogicError(format!(
                            "This should not have been called as the ManagedHost is already compliant"
                        )));
                    }

                    let mut actions_taken: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

                    for remediation in remediations {
                        let (remediation, internal_api_call_outcome) = match &remediation {
                            Remediation::None(message) => {
                                return Err(Error::InternalLogicError(format!(
                                    "Remediation::None({}) : get rid of this",
                                    message
                                )));
                            }
                            Remediation::Pacman(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Apt(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::YumDnf(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::LineInFile(attribute_api_call) => match attribute_api_call
                                .call(host_handler)
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation, internal_api_call_outcome)
                                }
                                Err(error_detail) => {
                                    return Err(error_detail);
                                }
                            },
                            Remediation::Debug(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Ping(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Service(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Command(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                        };

                        actions_taken.push((remediation, internal_api_call_outcome.clone()));

                        if let InternalApiCallOutcome::Failure(_detail) = &internal_api_call_outcome {
                            return Ok(AttributeComplianceResult::from(AttributeComplianceStatus::FailedReachedCompliance, Some(actions_taken)));
                        }
                    }

                    Ok(AttributeComplianceResult::from(AttributeComplianceStatus::ReachedCompliance, Some(actions_taken)))
                }
            },
            Err(error_detail) => Err(error_detail),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Remediation {
    None(String),
    Pacman(PacmanApiCall),
    Apt(AptApiCall),
    YumDnf(YumDnfApiCall),
    LineInFile(LineInFileApiCall),
    Debug(DebugApiCall),
    Ping(PingApiCall),
    Service(ServiceApiCall),
    Command(CommandApiCall),
}

impl Remediation {
    pub fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
    ) -> Result<InternalApiCallOutcome, Error> {
        match self {
            Remediation::None(_) => {
                // This case should not occur here according to current logic
                Err(Error::InternalLogicError(String::from("Unexpected remediation"))
                )
            }
            Remediation::Pacman(api_call) => api_call.call(host_handler),
            Remediation::Apt(api_call) => api_call.call(host_handler),
            Remediation::YumDnf(api_call) => api_call.call(host_handler),
            Remediation::LineInFile(api_call) => api_call.call(host_handler),
            Remediation::Debug(api_call) => api_call.call(host_handler),
            Remediation::Ping(api_call) => api_call.call(host_handler),
            Remediation::Service(api_call) => api_call.call(host_handler),
            Remediation::Command(api_call) => api_call.call(host_handler),
        }
    }
}
