pub mod package;
pub mod utilities;
pub mod system;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::managed_host::AttributeLevelOperationOutcome;
use crate::managed_host::HostLevelOperationOutcome;
use crate::managed_host::InternalApiCallOutcome;
use crate::state::attribute::package::apt::AptApiCall;
use crate::state::attribute::package::apt::AptBlockExpectedState;
use crate::state::attribute::package::yumdnf::YumDnfApiCall;
use crate::state::attribute::package::yumdnf::YumDnfBlockExpectedState;
use crate::state::attribute::system::service::ServiceApiCall;
use crate::state::attribute::system::service::ServiceBlockExpectedState;
use crate::state::attribute::utilities::debug::DebugApiCall;
use crate::state::attribute::utilities::debug::DebugBlockExpectedState;
use crate::state::attribute::utilities::lineinfile::LineInFileApiCall;
use crate::state::attribute::utilities::lineinfile::LineInFileBlockExpectedState;
use crate::state::attribute::utilities::ping::PingApiCall;
use crate::state::attribute::utilities::ping::PingBlockExpectedState;
use crate::{
    host_handler::{host_handler::HostHandler, privilege::Privilege},
    managed_host::{AssessCompliance, ReachCompliance},
    state::{
        attribute::package::pacman::{PacmanApiCall, PacmanBlockExpectedState},
        compliance::ComplianceStatus,
    },
};

#[derive(Clone, Serialize, Deserialize)]
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
    ) -> Result<Option<Vec<Remediation>>, Error> {
        self.detail.assess(host_handler, &self.privilege)
    }

    pub fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
    ) -> Result<AttributeLevelOperationOutcome, Error> {
        self.detail.reach_compliance(host_handler, &self.privilege)
    }

    pub fn apt(details: AptBlockExpectedState, privilege: Privilege) -> Attribute {
        Attribute::from(AttributeDetail::Apt(details), privilege)
    }

    pub fn pacman(details: PacmanBlockExpectedState, privilege: Privilege) -> Attribute {
        Attribute::from(AttributeDetail::Pacman(details), privilege)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AttributeDetail {
    Apt(AptBlockExpectedState),
    YumDnf(YumDnfBlockExpectedState),
    Pacman(PacmanBlockExpectedState),
    LineInFile(LineInFileBlockExpectedState),
    Debug(DebugBlockExpectedState),
    Ping(PingBlockExpectedState),
    Service(ServiceBlockExpectedState),
}

impl AttributeDetail {
    pub fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<Option<Vec<Remediation>>, Error> {
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
        }
    }

    pub fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeLevelOperationOutcome, Error> {
        match self.assess(host_handler, privilege) {
            Ok(optional_remediations) => match optional_remediations {
                Some(remediations) => {
                    if remediations.len() == 0 {
                        return Err(Error::InternalLogicError(format!(
                            "This should not have been called as the ManagedHost is already compliant"
                        )));
                    }

                    let mut actions_taken: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

                    for remediation in remediations {
                        match &remediation {
                            Remediation::None(message) => {
                                return Err(Error::InternalLogicError(format!(
                                    "Remediation::None({}) : get rid of this",
                                    message
                                )));
                            }
                            Remediation::Pacman(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Apt(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::YumDnf(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::LineInFile(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Debug(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Ping(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                            Remediation::Service(attribute_api_call) => {
                                match attribute_api_call.call(host_handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken
                                            .push((remediation, internal_api_call_outcome));
                                    }
                                    Err(error_detail) => {
                                        return Err(error_detail);
                                    }
                                }
                            }
                        }
                    }

                    Ok(AttributeLevelOperationOutcome::ComplianceReached(
                        actions_taken,
                    ))
                }
                None => Ok(AttributeLevelOperationOutcome::AlreadyCompliant),
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
}
