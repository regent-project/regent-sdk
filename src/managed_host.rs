use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Error;
use crate::host_handler::host_handler::HostHandler;
use crate::host_handler::privilege::Privilege;
use crate::state::ExpectedState;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceStatus;
use crate::state::compliance::HostComplianceAssessment;
use crate::state::compliance::HostComplianceStatus;
use crate::state::attribute::Attribute;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::AttributeComplianceResult;
use crate::state::compliance::HostComplianceResult;

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
    ) -> Result<HostComplianceAssessment, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut attributes_compliance_assessment: Vec<(Attribute, AttributeComplianceAssessment)> = Vec::new();


        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler) {
                Ok(attribute_compliance) => {
                    if let AttributeComplianceAssessment::NonCompliant(_remediations) = &attribute_compliance {
                        already_compliant = false;
                    }
                    attributes_compliance_assessment.push((attribute.clone(), attribute_compliance));
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if already_compliant {
            Ok(HostComplianceAssessment::from(
                HostComplianceStatus::AlreadyCompliant,
                attributes_compliance_assessment
            ))
        } else {
            Ok(HostComplianceAssessment::from(
                HostComplianceStatus::NonCompliant,
                attributes_compliance_assessment
            ))
        }
    }

    pub fn assess_compliance_in_parallel(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<HostComplianceAssessment, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut attributes_compliance_assessment: Vec<(Attribute, AttributeComplianceAssessment)> = Vec::new();

        let (sender, receiver) =
            std::sync::mpsc::channel::<(Attribute, Result<AttributeComplianceAssessment, Error>)>();

        for attribute in &expected_state.attributes {
            let attribute_clone = attribute.clone();
            let sender_clone = sender.clone();
            std::thread::spawn({
                let mut host_handler = self.handler.clone();
                move || {
                    let result = attribute_clone.assess(&mut host_handler);
                    let _ = sender_clone.send((attribute_clone, result));
                }
            });
        }

        for _ in 0..expected_state.attributes.len() {
            match receiver.recv() {
                Ok((attribute, result_dry_run_attribute)) => match result_dry_run_attribute {
                    Ok(attribute_compliance) => {
                        if let AttributeComplianceAssessment::NonCompliant(_remediations) = &attribute_compliance {
                            already_compliant = false;
                        }
                        attributes_compliance_assessment.push((attribute, attribute_compliance));
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
            Ok(HostComplianceAssessment::from(
                HostComplianceStatus::AlreadyCompliant,
                attributes_compliance_assessment
            ))
        } else {
            Ok(HostComplianceAssessment::from(
                HostComplianceStatus::NonCompliant,
                attributes_compliance_assessment
            ))
        }
    }

    pub fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<HostComplianceResult, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut final_host_status = HostComplianceStatus::AlreadyCompliant;
        let mut reaching_compliance_failed = false;
        let mut actions_taken: Vec<(Attribute, AttributeComplianceResult)> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler) {
                Ok(attribute_compliance) => {
                    match attribute_compliance {
                        AttributeComplianceAssessment::Compliant => {
                            // Nothing to do except save this step in the final result
                            actions_taken.push((attribute.clone(), AttributeComplianceResult::from(
                                AttributeComplianceStatus::AlreadyCompliant, None)));
                        }
                        AttributeComplianceAssessment::NonCompliant(remediations) => {
                            // Try to remedy
                            let mut attribute_results: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

                            for remediation in remediations {
                                match remediation.reach_compliance(&mut self.handler) {
                                    Ok(internal_api_call_outcome) => {
                                        attribute_results.push((remediation, internal_api_call_outcome.clone()));

                                        if let InternalApiCallOutcome::Failure(_details) = internal_api_call_outcome {
                                            reaching_compliance_failed = true;
                                            
                                            // Stop processing remediations
                                            break;
                                        }
                                        
                                    }
                                    Err(error_detail) => {
                                        // TODO : return the whole automation up to this point, and not just an error without context like this
                                        return Err(error_detail);
                                    }
                                }
                            }

                            if reaching_compliance_failed {
                                // Stop processing more attributes and save it as failed
                                final_host_status = HostComplianceStatus::FailedReachedCompliance;
                                actions_taken.push((attribute.clone(), AttributeComplianceResult::from(
                                    AttributeComplianceStatus::FailedReachedCompliance, Some(attribute_results)
                                )));
                                break;
                            } else {
                                final_host_status = HostComplianceStatus::ReachedCompliance;
                                // Save the result and move on to the next attribute
                                actions_taken.push((attribute.clone(), AttributeComplianceResult::from(
                                    AttributeComplianceStatus::ReachedCompliance, Some(attribute_results)
                                )));
                            }
                            
                        }
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }
        Ok(HostComplianceResult::from(final_host_status, actions_taken))
    }
}

pub trait AssessCompliance<Handler: HostHandler> {
    fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<AttributeComplianceAssessment, Error>;
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InternalApiCallOutcome {
    Success,
    Failure(String),
    AllowedFailure(String),
}
