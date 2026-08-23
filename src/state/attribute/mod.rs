pub mod ai;
pub mod network;
pub mod package;
pub mod shell;
pub mod system;
pub mod utilities;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tera::Context;
use tokio::time::Instant;
use tokio::time::{sleep, timeout as tokio_timeout};
use tracing::{debug, error, info};

use crate::error::RegentError;

/// Timeout configuration for an attribute
///
/// This enum ensures that timeout configurations are mutually exclusive at compile time.
/// Only one timeout source can be specified: a Duration, seconds, or milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeTimeout {
    /// Use the default timeout from the attribute detail
    Default,
    /// Use a specific Duration
    Duration(Duration),
    /// Use seconds
    Seconds(u64),
    /// Use milliseconds
    Milliseconds(u64),
}

impl Default for AttributeTimeout {
    fn default() -> Self {
        AttributeTimeout::Default
    }
}
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::privilege::Privilege;
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::ai::ollama::OllamaApiCall;
use crate::state::attribute::ai::ollama::OllamaBlockExpectedState;
use crate::state::attribute::network::iptables::IptablesApiCall;
use crate::state::attribute::network::iptables::IptablesBlockExpectedState;
use crate::state::attribute::package::apt::AptApiCall;
use crate::state::attribute::package::apt::AptBlockExpectedState;
use crate::state::attribute::package::apt_repo::AptRepoApiCall;
use crate::state::attribute::package::apt_repo::AptRepoBlockExpectedState;
use crate::state::attribute::package::dnf_repo::DnfRepoApiCall;
use crate::state::attribute::package::dnf_repo::DnfRepoBlockExpectedState;
use crate::state::attribute::package::yumdnf::YumDnfApiCall;
use crate::state::attribute::package::yumdnf::YumDnfBlockExpectedState;
use crate::state::attribute::shell::command::CommandApiCall;
use crate::state::attribute::shell::command::CommandBlockExpectedState;
use crate::state::attribute::system::cron::CronApiCall;
use crate::state::attribute::system::cron::CronBlockExpectedState;
use crate::state::attribute::system::group::GroupApiCall;
use crate::state::attribute::system::group::GroupBlockExpectedState;
use crate::state::attribute::system::hostname::HostnameApiCall;
use crate::state::attribute::system::hostname::HostnameBlockExpectedState;
use crate::state::attribute::system::service::ServiceApiCall;
use crate::state::attribute::system::service::ServiceBlockExpectedState;
use crate::state::attribute::system::user::UserApiCall;
use crate::state::attribute::system::user::UserBlockExpectedState;
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
    hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout},
    state::attribute::package::pacman::{PacmanApiCall, PacmanBlockExpectedState},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attribute {
    pub name: Option<String>,
    pub privilege: Privilege,
    detail: AttributeDetail,
    timeout: AttributeTimeout,
}

impl Attribute {
    pub fn from(detail: AttributeDetail, privilege: Privilege, name: Option<String>) -> Attribute {
        Attribute {
            privilege,
            detail,
            name,
            timeout: AttributeTimeout::Default,
        }
    }

    pub fn name(&self) -> String {
        match self.name {
            Some(ref name) => name.clone(),
            None => match self.detail {
                AttributeDetail::Apt(_) => "Apt".to_string(),
                AttributeDetail::AptRepo(_) => "AptRepo".to_string(),
                AttributeDetail::YumDnf(_) => "YumDnf".to_string(),
                AttributeDetail::DnfRepo(_) => "DnfRepo".to_string(),
                AttributeDetail::Pacman(_) => "Pacman".to_string(),
                AttributeDetail::Service(_) => "Service".to_string(),
                AttributeDetail::Command(_) => "Command".to_string(),
                AttributeDetail::LineInFile(_) => "LineInFile".to_string(),
                AttributeDetail::Ping(_) => "Ping".to_string(),
                AttributeDetail::Debug(_) => "Debug".to_string(),
                AttributeDetail::User(_) => "User".to_string(),
                AttributeDetail::Group(_) => "Group".to_string(),
                AttributeDetail::Cron(_) => "Cron".to_string(),
                AttributeDetail::Hostname(_) => "Hostname".to_string(),
                AttributeDetail::Iptables(_) => "Iptables".to_string(),
                AttributeDetail::Ollama(_) => "Ollama".to_string(),
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
            Ok(context_aware_attribute) => {
                // Validate the configuration after template rendering to ensure
                // that template variables produced valid configuration
                context_aware_attribute.check().map_err(|e| {
                    RegentError::FailureToConsiderContext(format!(
                        "Post-template validation failed: {}",
                        e
                    ))
                })?;
                Ok(context_aware_attribute)
            }
            Err(detail) => Err(RegentError::FailureToConsiderContext(format!("{}", detail))),
        }
    }

    /// Result because the assessment might fail. If it succeeds, it will return either None (AKA already compliant) or Some(Vec of Remediation) (AKA what shall be done to reach the expected state).
    pub async fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        self.detail
            .assess(
                host_handler,
                host_properties,
                &self.privilege,
                optional_secret_provider,
                self.timeout()?,
            )
            .await
    }

    pub async fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceResult, RegentError> {
        self.detail
            .reach_compliance(
                host_handler,
                host_properties,
                &self.privilege,
                optional_secret_provider,
                self.timeout()?,
            )
            .await
    }

    pub fn check(&self) -> Result<(), RegentError> {
        self.detail.check()
    }

    pub fn timeout(&self) -> Result<Duration, RegentError> {
        match &self.timeout {
            AttributeTimeout::Default => Ok(self.detail.default_timeout()),
            AttributeTimeout::Duration(duration) => Ok(*duration),
            AttributeTimeout::Seconds(seconds) => Ok(Duration::from_secs(*seconds)),
            AttributeTimeout::Milliseconds(milliseconds) => {
                Ok(Duration::from_millis(*milliseconds))
            }
        }
    }

    // Convenience methods for attributes building

    /// Set a timeout using a Duration
    pub fn with_timeout(mut self, user_defined_timeout: Duration) -> Self {
        self.timeout = AttributeTimeout::Duration(user_defined_timeout);
        self
    }

    /// Set a timeout using seconds
    pub fn with_timeout_secs(mut self, seconds: u64) -> Self {
        self.timeout = AttributeTimeout::Seconds(seconds);
        self
    }

    /// Set a timeout using milliseconds
    pub fn with_timeout_millis(mut self, milliseconds: u64) -> Self {
        self.timeout = AttributeTimeout::Milliseconds(milliseconds);
        self
    }

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

    pub fn user(
        details: UserBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::User(details), privilege, name)
    }

    pub fn group(
        details: GroupBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Group(details), privilege, name)
    }

    pub fn cron(
        details: CronBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Cron(details), privilege, name)
    }

    pub fn hostname(
        details: HostnameBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Hostname(details), privilege, name)
    }

    pub fn apt_repo(
        details: AptRepoBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::AptRepo(details), privilege, name)
    }

    pub fn dnf_repo(
        details: DnfRepoBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::DnfRepo(details), privilege, name)
    }

    pub fn iptables(
        details: IptablesBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Iptables(details), privilege, name)
    }

    pub fn ollama(
        details: OllamaBlockExpectedState,
        privilege: Privilege,
        name: Option<String>,
    ) -> Attribute {
        Attribute::from(AttributeDetail::Ollama(details), privilege, name) // Used 'timeout' in 'from' method
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AttributeDetail {
    Apt(AptBlockExpectedState),
    AptRepo(AptRepoBlockExpectedState),
    YumDnf(YumDnfBlockExpectedState),
    DnfRepo(DnfRepoBlockExpectedState),
    Pacman(PacmanBlockExpectedState),
    LineInFile(LineInFileBlockExpectedState),
    Debug(DebugBlockExpectedState),
    Ping(PingBlockExpectedState),
    Service(ServiceBlockExpectedState),
    Command(CommandBlockExpectedState),
    User(UserBlockExpectedState),
    Group(GroupBlockExpectedState),
    Cron(CronBlockExpectedState),
    Hostname(HostnameBlockExpectedState),
    Iptables(IptablesBlockExpectedState),
    Ollama(OllamaBlockExpectedState),
}

impl AttributeDetail {
    pub fn default_timeout(&self) -> Duration {
        match self {
            AttributeDetail::Apt(details) => details.default_timeout(),
            AttributeDetail::AptRepo(details) => details.default_timeout(),
            AttributeDetail::YumDnf(details) => details.default_timeout(),
            AttributeDetail::DnfRepo(details) => details.default_timeout(),
            AttributeDetail::Pacman(details) => details.default_timeout(),
            AttributeDetail::LineInFile(details) => details.default_timeout(),
            AttributeDetail::Debug(details) => details.default_timeout(),
            AttributeDetail::Ping(details) => details.default_timeout(),
            AttributeDetail::Service(details) => details.default_timeout(),
            AttributeDetail::Command(details) => details.default_timeout(),
            AttributeDetail::User(details) => details.default_timeout(),
            AttributeDetail::Group(details) => details.default_timeout(),
            AttributeDetail::Cron(details) => details.default_timeout(),
            AttributeDetail::Hostname(details) => details.default_timeout(),
            AttributeDetail::Iptables(details) => details.default_timeout(),
            AttributeDetail::Ollama(details) => details.default_timeout(),
        }
    }

    pub async fn assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
        timeout_duration: Duration,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        match tokio_timeout(
            timeout_duration,
            self.raw_assess(
                host_handler,
                host_properties,
                privilege,
                optional_secret_provider,
            ),
        )
        .await
        {
            Ok(raw_assesment_result) => raw_assesment_result,
            Err(_details) => {
                error!(timeout = ?timeout_duration, "Timeout elapsed");
                return Err(RegentError::TimeOutReached(format!(
                    "Timeout elapsed ({} ms) trying to assess compliance",
                    timeout_duration.as_millis()
                )));
            }
        }
    }

    pub async fn raw_assess<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
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
            AttributeDetail::AptRepo(expected_state_criteria) => {
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
            AttributeDetail::DnfRepo(expected_state_criteria) => {
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
            AttributeDetail::User(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Group(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Cron(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Hostname(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Iptables(expected_state_criteria) => {
                expected_state_criteria
                    .assess_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                    )
                    .await
            }
            AttributeDetail::Ollama(expected_state_criteria) => {
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
        optional_secret_provider: &Option<SecretProvidersPool>,
        timeout_duration: Duration,
    ) -> Result<AttributeComplianceResult, RegentError> {
        let raw_assesment_result = match tokio_timeout(
            timeout_duration,
            self.raw_assess(
                host_handler,
                host_properties,
                privilege,
                optional_secret_provider,
            ),
        )
        .await
        {
            Ok(raw_assesment_result) => raw_assesment_result,
            Err(_details) => {
                error!(timeout = ?timeout_duration, "Timeout elapsed");
                return Err(RegentError::TimeOutReached(format!(
                    "Timeout elapsed ({} ms) trying to assess compliance",
                    timeout_duration.as_millis()
                )));
            }
        };
        match raw_assesment_result {
            Ok(attribute_compliance) => {
                info!(timeout = ?timeout_duration, "Start of reach compliance try");
                match tokio_timeout(
                    timeout_duration,
                    self.raw_reach_compliance(
                        host_handler,
                        host_properties,
                        privilege,
                        optional_secret_provider,
                        attribute_compliance,
                    ),
                )
                .await
                {
                    Ok(raw_compliance_reaching_result) => raw_compliance_reaching_result,
                    Err(_details) => {
                        error!(timeout = ?timeout_duration, "Timeout elapsed");
                        return Err(RegentError::TimeOutReached(format!(
                            "Timeout elapsed ({} ms) trying to assess compliance",
                            timeout_duration.as_millis()
                        )));
                    }
                }
            }
            Err(details) => Err(details),
        }
    }

    pub async fn raw_reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
        attribute_compliance: AttributeComplianceAssessment,
    ) -> Result<AttributeComplianceResult, RegentError> {
        match attribute_compliance {
            AttributeComplianceAssessment::Compliant => Ok(AttributeComplianceResult::from(
                AttributeComplianceStatus::AlreadyCompliant,
                None,
            )),
            AttributeComplianceAssessment::NonCompliant(remediations) => {
                if remediations.is_empty() {
                    return Err(RegentError::InternalLogicError(format!(
                        "This should not have been called as the ManagedHost is already compliant"
                    )));
                }

                let mut actions_taken: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

                for remediation_ref in remediations.iter() {
                    let (remediation, internal_api_call_outcome) = match remediation_ref {
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
                                (remediation_ref.clone(), internal_api_call_outcome)
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
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::AptRepo(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
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
                                (remediation_ref.clone(), internal_api_call_outcome)
                            }
                            Err(details) => {
                                return Err(details);
                            }
                        },
                        Remediation::DnfRepo(attribute_api_call) => match attribute_api_call
                            .call(host_handler, host_properties, optional_secret_provider)
                            .await
                        {
                            Ok(internal_api_call_outcome) => {
                                (remediation_ref.clone(), internal_api_call_outcome)
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
                                (remediation_ref.clone(), internal_api_call_outcome)
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
                                    (remediation_ref.clone(), internal_api_call_outcome)
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
                                    (remediation_ref.clone(), internal_api_call_outcome)
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
                                    (remediation_ref.clone(), internal_api_call_outcome)
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
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::User(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::Group(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::Cron(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::Hostname(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::Iptables(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                        Remediation::Ollama(attribute_api_call) => {
                            match attribute_api_call
                                .call(host_handler, host_properties, optional_secret_provider)
                                .await
                            {
                                Ok(internal_api_call_outcome) => {
                                    (remediation_ref.clone(), internal_api_call_outcome)
                                }
                                Err(details) => {
                                    return Err(details);
                                }
                            }
                        }
                    };

                    actions_taken.push((remediation, internal_api_call_outcome.clone()));

                    if let InternalApiCallOutcome::Failure(_detail) = &internal_api_call_outcome {
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
            AttributeComplianceAssessment::NonCompliantFatal(details) => {
                Ok(AttributeComplianceResult::from(
                    AttributeComplianceStatus::NonCompliantFatal(details), None))
            }
        }
    }

    pub fn check(&self) -> Result<(), RegentError> {
        match self {
            AttributeDetail::Apt(expected_state_block) => expected_state_block.check(),
            AttributeDetail::AptRepo(expected_state_block) => expected_state_block.check(),
            AttributeDetail::YumDnf(expected_state_block) => expected_state_block.check(),
            AttributeDetail::DnfRepo(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Pacman(expected_state_block) => expected_state_block.check(),
            AttributeDetail::LineInFile(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Debug(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Ping(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Service(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Command(expected_state_block) => expected_state_block.check(),
            AttributeDetail::User(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Group(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Cron(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Hostname(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Iptables(expected_state_block) => expected_state_block.check(),
            AttributeDetail::Ollama(expected_state_block) => expected_state_block.check(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Remediation {
    None(String),
    Pacman(PacmanApiCall),
    Apt(AptApiCall),
    AptRepo(AptRepoApiCall),
    YumDnf(YumDnfApiCall),
    DnfRepo(DnfRepoApiCall),
    LineInFile(LineInFileApiCall),
    Debug(DebugApiCall),
    Ping(PingApiCall),
    Service(ServiceApiCall),
    Command(CommandApiCall),
    User(UserApiCall),
    Group(GroupApiCall),
    Cron(CronApiCall),
    Hostname(HostnameApiCall),
    Iptables(IptablesApiCall),
    Ollama(OllamaApiCall),
}

impl std::fmt::Debug for Remediation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Remediation::None(details) => write!(f, "{}", details),
            Remediation::Pacman(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Apt(api_call) => write!(f, "{}", api_call.display()),
            Remediation::AptRepo(api_call) => write!(f, "{}", api_call.display()),
            Remediation::YumDnf(api_call) => write!(f, "{}", api_call.display()),
            Remediation::DnfRepo(api_call) => write!(f, "{}", api_call.display()),
            Remediation::LineInFile(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Debug(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Ping(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Service(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Command(api_call) => write!(f, "{}", api_call.display()),
            Remediation::User(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Group(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Cron(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Hostname(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Iptables(api_call) => write!(f, "{}", api_call.display()),
            Remediation::Ollama(api_call) => write!(f, "{}", api_call.display()),
        }
    }
}

impl Remediation {
    pub async fn reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
        timeout_duration: Duration,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        match tokio_timeout(
            timeout_duration,
            self.raw_reach_compliance(host_handler, host_properties, optional_secret_provider),
        )
        .await
        {
            Ok(raw_assesment_result) => raw_assesment_result,
            Err(_details) => {
                error!(timeout = ?timeout_duration, "Timeout elapsed");
                return Err(RegentError::TimeOutReached(format!(
                    "Timeout elapsed ({} ms) trying to run internal API call",
                    timeout_duration.as_millis()
                )));
            }
        }
    }

    pub async fn raw_reach_compliance<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
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
            Remediation::AptRepo(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::YumDnf(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::DnfRepo(api_call) => {
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
            Remediation::User(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Group(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Cron(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Hostname(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Iptables(api_call) => {
                api_call
                    .call(host_handler, host_properties, optional_secret_provider)
                    .await
            }
            Remediation::Ollama(api_call) => {
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
            Remediation::AptRepo(api_call) => api_call.display(),
            Remediation::YumDnf(api_call) => api_call.display(),
            Remediation::DnfRepo(api_call) => api_call.display(),
            Remediation::LineInFile(api_call) => api_call.display(),
            Remediation::Debug(api_call) => api_call.display(),
            Remediation::Ping(api_call) => api_call.display(),
            Remediation::Service(api_call) => api_call.display(),
            Remediation::Command(api_call) => api_call.display(),
            Remediation::User(api_call) => api_call.display(),
            Remediation::Group(api_call) => api_call.display(),
            Remediation::Cron(api_call) => api_call.display(),
            Remediation::Hostname(api_call) => api_call.display(),
            Remediation::Iptables(api_call) => api_call.display(),
            Remediation::Ollama(api_call) => api_call.display(),
        }
    }
}

// This type makes it impossible to have empty remediation lists elsewhere AKA error logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationsList {
    inner: Vec<Remediation>,
}

impl RemediationsList {
    pub fn from(remediations: Vec<Remediation>) -> Result<RemediationsList, RegentError> {
        if remediations.len() == 0 {
            Err(RegentError::InternalLogicError(format!(
                "Empty remediation list passed"
            )))
        } else {
            Ok(RemediationsList {
                inner: remediations,
            })
        }
    }

    pub fn remediations(&self) -> &Vec<Remediation> {
        &self.inner
    }

    pub fn into_inner(self) -> Vec<Remediation> {
        self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Remediation> {
        self.inner.iter()
    }
}

impl IntoIterator for RemediationsList {
    type Item = Remediation;
    type IntoIter = std::vec::IntoIter<Remediation>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a RemediationsList {
    type Item = &'a Remediation;
    type IntoIter = std::slice::Iter<'a, Remediation>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl FromIterator<Remediation> for RemediationsList {
    fn from_iter<T: IntoIterator<Item = Remediation>>(iter: T) -> Self {
        RemediationsList {
            inner: Vec::from_iter(iter),
        }
    }
}
