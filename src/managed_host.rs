use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Error;
use crate::host_handler::host_handler::HostHandler;
use crate::host_handler::privilege::Privilege;
use crate::state::ExpectedState;
use crate::state::attribute::Remediation;
use crate::state::compliance::ComplianceAssesment;
use crate::state::compliance::ComplianceStatus;

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedHost<Handler>
where
    Handler: HostHandler,
{
    endpoint: String,
    handler: Handler,
    vars: HashMap<String, String>,
}

impl<Handler: HostHandler + Send + Clone + 'static> ManagedHost<Handler> {
    pub fn from(
        endpoint: &str,
        handler: Handler,
        vars: HashMap<String, String>,
    ) -> ManagedHost<Handler> {
        ManagedHost {
            endpoint: endpoint.to_string(),
            handler,
            vars,
        }
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        self.handler.connect(&self.endpoint)
    }
    pub fn is_connected(&mut self) -> bool {
        self.handler.is_connected()
    }
    pub fn disconnect(&mut self) -> Result<(), Error> {
        self.handler.disconnect()
    }
    // fn is_this_command_available(&mut self, command: &str) -> Result<bool, Error> {
    //     self.handler.is_this_command_available(command)
    // }
    // fn run_command(&mut self, command: &str) -> Result<CommandResult, Error> {
    //     self.handler.run_command(command)
    // }

    // Defaults to sequential assessment
    pub fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ComplianceAssesment, Error> {
        if ! self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut required_remediations: Vec<Remediation> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler) {
                Ok(option_remediations) => {
                    if let Some(remediations) = option_remediations {
                        already_compliant = false;
                        required_remediations.extend(remediations);
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if already_compliant {
            Ok(ComplianceAssesment::AlreadyCompliant)
        } else {
            Ok(ComplianceAssesment::NonCompliant(required_remediations))
        }
    }

    pub fn assess_compliance_in_parallel(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ComplianceAssesment, Error> {
        if ! self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut required_remediations: Vec<Remediation> = Vec::new();

        let (sender, receiver) =
            std::sync::mpsc::channel::<Result<Option<Vec<Remediation>>, Error>>();

        for attribute in &expected_state.attributes {
            let attribute_clone = attribute.clone();
            let sender_clone = sender.clone();
            std::thread::spawn({
                let mut host_handler = self.handler.clone();
                move || {
                    let result = attribute_clone.assess(&mut host_handler);
                    let _ = sender_clone.send(result);
                }
            });
        }

        for _ in 0..expected_state.attributes.len() {
            match receiver.recv() {
                Ok(result_dry_run_attribute) => match result_dry_run_attribute {
                    Ok(option_remediations) => {
                        if let Some(remediations) = option_remediations {
                            already_compliant = false;
                            required_remediations.extend(remediations);
                        }
                    }
                    Err(error_detail) => {
                        return Err(error_detail);
                    }
                },
                Err(error_detail) => {
                    return Err(Error::FailedDryRunEvaluation(format!("{}", error_detail)));
                }
            }
        }

        if already_compliant {
            Ok(ComplianceAssesment::AlreadyCompliant)
        } else {
            Ok(ComplianceAssesment::NonCompliant(required_remediations))
        }
    }

    pub fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ComplianceStatus, Error> {
        if ! self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut actions_taken: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler) {
                Ok(option_remediations) => {
                    if let Some(remediations) = option_remediations {
                        for remediation in remediations {
                            match attribute.reach_compliance(&mut self.handler) {
                                Ok(attribute_level_outcome) => {
                                    match attribute_level_outcome {
                                        AttributeLevelOperationOutcome::ComplianceReached(
                                            partial_actions_taken,
                                        ) => {
                                            let mut api_call_failed = false;
                                            for (_remediation, internal_api_call_outcome) in
                                                &partial_actions_taken
                                            {
                                                match internal_api_call_outcome {
                                                    InternalApiCallOutcome::Success => {}
                                                    InternalApiCallOutcome::AllowedFailure(
                                                        _details,
                                                    ) => {
                                                        // TODO : allow failures
                                                        api_call_failed = true;
                                                    }
                                                    InternalApiCallOutcome::Failure(_details) => {
                                                        api_call_failed = true;
                                                    }
                                                }
                                            }
                                            actions_taken.extend(partial_actions_taken);

                                            if api_call_failed {
                                                return Ok(
                                                    ComplianceStatus::FailedReachedCompliance(
                                                        actions_taken,
                                                    ),
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                Err(error_detail) => {
                                    actions_taken.push((
                                        remediation,
                                        InternalApiCallOutcome::Failure(format!(
                                            "{:?}",
                                            error_detail
                                        )),
                                    ));
                                    return Ok(ComplianceStatus::FailedReachedCompliance(
                                        actions_taken,
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if actions_taken.len() == 0 {
            Ok(ComplianceStatus::AlreadyCompliant)
        } else {
            Ok(ComplianceStatus::ReachedCompliance(actions_taken))
        }
    }
}

pub trait AssessCompliance<Handler: HostHandler> {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<Option<Vec<Remediation>>, Error>;
}

pub trait ReachCompliance<Handler: HostHandler> {
    // fn display(&self) -> String;
    fn call(&self, host_handler: &mut Handler) -> Result<InternalApiCallOutcome, Error>;
}

#[derive(Serialize, Deserialize)]
pub enum HostLevelOperationOutcome {
    HostHandlingFailed,
    AssessComplianceFailed,
    AlreadyCompliant,
    NotCompliant(Vec<Remediation>),
    ReachComplianceFailed(Vec<(Remediation, InternalApiCallOutcome)>),
    ComplianceReachedWithAllowedFailure(Vec<(Remediation, InternalApiCallOutcome)>),
    ComplianceReached(Vec<(Remediation, InternalApiCallOutcome)>),
}

#[derive(Serialize, Deserialize)]
pub enum AttributeLevelOperationOutcome {
    // HostHandlingFailed,
    // AssessComplianceFailed,
    AlreadyCompliant,
    NotCompliant(Vec<Remediation>),
    ReachComplianceFailed(InternalApiCallOutcome),
    ComplianceReachedWithAllowedFailure(InternalApiCallOutcome),
    ComplianceReached(Vec<(Remediation, InternalApiCallOutcome)>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InternalApiCallOutcome {
    Success,
    Failure(String),
    AllowedFailure(String),
}
