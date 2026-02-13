use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Error;
use crate::host_handler::host_handler::HostHandler;
use crate::host_handler::privilege::Privilege;
use crate::state::ExpectedState;
use crate::state::attribute::Remediation;
use crate::state::compliance::Action;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::compliance::HostStatus;
use crate::state::compliance::ManagedHostStatus;

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedHost<Handler>
where
    Handler: HostHandler,
{
    endpoint: String,
    pub handler: Handler,
    vars: HashMap<String, String>,
}

impl<Handler: HostHandler + Send + Clone + 'static> ManagedHost<Handler> {
    pub fn new(endpoint: &str, handler: Handler) -> ManagedHost<Handler> {
        ManagedHost {
            endpoint: endpoint.to_string(),
            handler,
            vars: HashMap::new(),
        }
    }

    pub fn from(
        endpoint: &str,
        handler: Handler,
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> ManagedHost<Handler> {
        let mut final_vars: HashMap<String, String> = HashMap::new();

        for (key, value) in vars.into_iter() {
            final_vars.insert(key, value);
        }
        ManagedHost {
            endpoint: endpoint.to_string(),
            handler,
            vars: final_vars,
        }
    }

    pub fn add_var(&mut self, key: String, value: String) {
        self.vars.insert(key, value);
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

    // Defaults to sequential assessment
    pub fn assess_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut final_remediations_list: Vec<Remediation> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler) {
                Ok(attribute_compliance) => {
                    if let AttributeComplianceAssessment::NonCompliant(remediations) =
                        attribute_compliance
                    {
                        already_compliant = false;
                        final_remediations_list.extend(remediations);
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if already_compliant {
            Ok(ManagedHostStatus::already_compliant())
        } else {
            Ok(ManagedHostStatus::not_compliant(final_remediations_list))
        }
    }

    pub fn assess_compliance_in_parallel(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut already_compliant = true;
        let mut final_remediations_list: Vec<Remediation> = Vec::new();

        let (sender, receiver) =
            std::sync::mpsc::channel::<Result<AttributeComplianceAssessment, Error>>();

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
                    Ok(attribute_compliance) => {
                        if let AttributeComplianceAssessment::NonCompliant(remediations) =
                            attribute_compliance
                        {
                            already_compliant = false;
                            final_remediations_list.extend(remediations);
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
            Ok(ManagedHostStatus::already_compliant())
        } else {
            Ok(ManagedHostStatus::not_compliant(final_remediations_list))
        }
    }

    pub fn reach_compliance(
        &mut self,
        expected_state: &ExpectedState,
    ) -> Result<ManagedHostStatus, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnectedToHost);
        }

        let mut final_host_status = HostStatus::AlreadyCompliant;
        let mut reaching_compliance_failed = false;
        let mut actions_taken: Vec<Action> = Vec::new();

        for attribute in &expected_state.attributes {
            match attribute.assess(&mut self.handler) {
                Ok(attribute_compliance) => {
                    match attribute_compliance {
                        AttributeComplianceAssessment::Compliant => {
                            // Nothing to do
                        }
                        AttributeComplianceAssessment::NonCompliant(remediations) => {
                            // Host is not compliant as there are remediations to perform
                            // Host status switches from AlreadyCompliant to ReachComplianceSuccess by default
                            final_host_status = HostStatus::ReachComplianceSuccess;

                            // Try to remedy

                            for remediation in remediations {
                                match remediation.reach_compliance(&mut self.handler) {
                                    Ok(internal_api_call_outcome) => {
                                        actions_taken.push(Action::from(
                                            remediation,
                                            Some(internal_api_call_outcome.clone()),
                                        ));

                                        if let InternalApiCallOutcome::Failure(_details) =
                                            internal_api_call_outcome
                                        {
                                            reaching_compliance_failed = true;
                                            final_host_status = HostStatus::ReachComplianceFailed;

                                            // Stop processing more mediations for this attribute
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
                                // Stop processing more attributes
                                break;
                            }
                        }
                    }
                }
                Err(error_detail) => {
                    return Err(error_detail);
                }
            }
        }

        if let HostStatus::ReachComplianceFailed = final_host_status {
            Ok(ManagedHostStatus::reach_compliance_failed(actions_taken))
        } else {
            Ok(ManagedHostStatus::reach_compliance_success(actions_taken))
        }
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
pub enum AttributeLevelOperationOutcome {
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
