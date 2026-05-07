pub mod package;
pub mod shell;
pub mod system;
pub mod utilities;

use serde::{Deserialize, Serialize};
use tera::Context;

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::privilege::Privilege;
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvider;
use crate::state::Check;
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
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::AttributeComplianceResult;
use crate::state::compliance::AttributeComplianceStatus;
use crate::{
    hosts::handlers::HostHandler,
    hosts::managed_host::{AssessCompliance, ReachCompliance},
    state::attribute::package::pacman::{PacmanApiCall, PacmanBlockExpectedState},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attribute {
    pub privilege: Privilege,
    detail: AttributeDetail,
    pub name: Option<String>,
}

impl Attribute {
    pub fn from(detail: AttributeDetail, privilege: Privilege, name: Option<String>) -> Attribute {
        Attribute {
            privilege,
            detail,
            name,
        }
    }

    pub fn name(&self) -> String {
        match self.name {
            Some(ref name) => name.clone(),
            None => match self.detail {
                AttributeDetail::Apt(_) => "Apt".to_string(),
                AttributeDetail::YumDnf(_) => "YumDnf".to_string(),
                AttributeDetail::Pacman(_) => "Pacman".to_string(),
                AttributeDetail::Service(_) => "Service".to_string(),
                AttributeDetail::Command(_) => "Command".to_string(),
                AttributeDetail::LineInFile(_) => "LineInFile".to_string(),
                AttributeDetail::Ping(_) => "Ping".to_string(),
                AttributeDetail::Debug(_) => "Debug".to_string(),
            },
        }
    }

    pub fn consider_context(&self, context: &Context) -> Result<Attribute, RegentError> {
        // To have the template engine work, we serialize the Attribute, run the template engine, then deserialize
        // TODO : is the best way ?

        // Making use of template engine to consider dynamic variables (HostVars, GlobalVars...)
        let serialized_self = match serde_json::to_string(self) {
            Ok(serialized_self) => serialized_self,
            Err(details) => {
                // Shall never happen as self implements the Serialize trait
                return Err(RegentError::InternalLogicError(format!(
                    "Attribute tried to serialize self but failed : {}",
                    details
                )));
            }
        };

        let context_wise_serialized_self =
            match tera::Tera::one_off(serialized_self.as_str(), context, true) {
                Ok(context_aware_attribute) => context_aware_attribute,
                Err(details) => {
                    return Err(RegentError::FailureToConsiderContext(format!(
                        "Failed to consider dynamic context : {}",
                        details
                    )));
                }
            };
        match serde_json::from_str::<Attribute>(&context_wise_serialized_self) {
            Ok(context_aware_attribute) => Ok(context_aware_attribute),
            Err(detail) => Err(RegentError::FailureToConsiderContext(format!("{}", detail))),
        }
    }

    /// Result because the assessment might fail. If it succeeds, it will return either None (AKA already compliant) or Some(Vec<Remediation>) (AKA what shall be done to reach the expected state).
    pub async fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        self.detail
            .assess(
                host_handler,
                host_properties,
                &self.privilege,
                optional_secret_provider,
            )
            .await
    }

    pub async fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceResult, RegentError> {
        self.detail
            .reach_compliance(
                host_handler,
                host_properties,
                &self.privilege,
                optional_secret_provider,
            )
            .await
    }

    pub fn check(&self) -> Result<(), RegentError> {
        self.detail.check()
    }

    // Convenience methods for attributes building

    pub fn apt(
        details: AptBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Apt(details), privilege, name)
    }

    pub fn pacman(
        details: PacmanBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Pacman(details), privilege, name)
    }

    pub fn yumdnf(
        details: YumDnfBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::YumDnf(details), privilege, name)
    }

    pub fn command(
        details: CommandBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Command(details), privilege, name)
    }

    pub fn service(
        details: ServiceBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Service(details), privilege, name)
    }

    pub fn debug(
        details: DebugBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Debug(details), privilege, name)
    }

    pub fn lineinfile(
        details: LineInFileBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::LineInFile(details), privilege, name)
    }

    pub fn ping(
        details: PingBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Ping(details), privilege, name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
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
    pub async fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        match self {
            AttributeDetail::Apt(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::YumDnf(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Pacman(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::LineInFile(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Debug(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Ping(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Service(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Command(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
        }
    }

    pub async fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<AttributeComplianceResult, RegentError> {
        match self
            .assess(
                host_handler,
                host_properties,
                privilege,
                optional_secret_provider,
            )
            .await
        {
            Ok(attribute_compliance) => match attribute_compliance {
                AttributeComplianceAssessment::Compliant => Ok(AttributeComplianceResult::from(
                    AttributeComplianceStatus::AlreadyCompliant,
                    None,
                )),
                AttributeComplianceAssessment::NonCompliant(remediations) => {
                    if remediations.len() == 0 {
                        return Err(RegentError::InternalLogicError(format!(
                            "This should not have been called as the ManagedHost is already compliant"
                        )));
                    }

                    let mut actions_taken: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

                    for remediation in remediations {
                        let (remediation, internal_api_call_outcome) = match &remediation {
                            Remediation::None(message) => {
                                return Err(RegentError::InternalLogicError(format!(
                                    "Remediation::None({}) : get rid of this",
                                    message
                                )));
                            }
                            Remediation::Pacman(attribute_api_call) => match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation, internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            },
                            Remediation::Apt(attribute_api_call) => {
                                match attribute_api_call
                                    .call(host_handler, host_properties, optional_secret_provider)
                                    .await
                                {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(details) => {
                                        return Err(details);
                                    }
                                }
                            }
                            Remediation::YumDnf(attribute_api_call) => match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation, internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            },
                            Remediation::LineInFile(attribute_api_call) => match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation, internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            },
                            Remediation::Debug(attribute_api_call) => {
                                match attribute_api_call
                                    .call(host_handler, host_properties, optional_secret_provider)
                                    .await
                                {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(details) => {
                                        return Err(details);
                                    }
                                }
                            }
                            Remediation::Ping(attribute_api_call) => {
                                match attribute_api_call
                                    .call(host_handler, host_properties, optional_secret_provider)
                                    .await
                                {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(details) => {
                                        return Err(details);
                                    }
                                }
                            }
                            Remediation::Service(attribute_api_call) => {
                                match attribute_api_call
                                    .call(host_handler, host_properties, optional_secret_provider)
                                    .await
                                {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(details) => {
                                        return Err(details);
                                    }
                                }
                            }
                            Remediation::Command(attribute_api_call) => {
                                match attribute_api_call
                                    .call(host_handler, host_properties, optional_secret_provider)
                                    .await
                                {
                                    Ok(internal_api_call_outcome) => {
                                        (remediation, internal_api_call_outcome)
                                    }
                                    Err(details) => {
                                        return Err(details);
                                    }
                                }
                            }
                        };

                        actions_taken.push((remediation, internal_api_call_outcome.clone()));

                        if let InternalApiCallOutcome::Failure(_detail) = &internal_api_call_outcome
                        {
                            return Ok(AttributeComplianceResult::from(
                                AttributeComplianceStatus::FailedReachedCompliance,
                                Some(actions_taken),
                            ));
                        }
                    }

                    Ok(AttributeComplianceResult::from(
                        AttributeComplianceStatus::ReachedCompliance,
                        Some(actions_taken),
                    ))
                }
            },
            Err(details) => Err(details),
        }
    }

    pub fn check(&self) -> Result<(), RegentError> {
        match self {
            AttributeDetail::Apt(expected_state_block) => expected_state_block.check(),
            AttributeDetail::YumDnf(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Pacman(expected_state_block) => expected_state_block.check(),
            AttributeDetail::LineInFile(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Debug(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Ping(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Service(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Command(expected_state_block) => expected_state_block.check(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for Remediation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Remediation::None(details) => write!(f, "{}", details),
            Remediation::Pacman(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Apt(api_call) => write!(f, "{}", api_call.display()),
            Remediation::YumDnf(api_call) => write!(f, "{}", api_call.display()),
            Remediation::LineInFile(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Debug(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Ping(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Service(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Command(api_call) => write!(f, "{}", api_call.display()),
        }
    }
}

impl Remediation {
    pub async fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvider>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        match self {
            Remediation::None(_) => {
                // This case should not occur here according to current logic
                Err(RegentError::InternalLogicError(String::from(
                    "Unexpected remediation",
                )))
            }
            Remediation::Pacman(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Apt(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::YumDnf(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::LineInFile(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Debug(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Ping(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Service(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Command(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
        }
    }

    pub fn display(&self) -> String {
        match self {
            Remediation::None(s) => format!("None({})", s),
            Remediation::Pacman(api_call) => api_call.display(),
            Remediation::Apt(api_call) => api_call.display(),
            Remediation::YumDnf(api_call) => api_call.display(),
            Remediation::LineInFile(api_call) => api_call.display(),
            Remediation::Debug(api_call) => api_call.display(),
            Remediation::Ping(api_call) => api_call.display(),
            Remediation::Service(api_call) => api_call.display(),
            Remediation::Command(api_call) => api_call.display(),
        }
    }
}
