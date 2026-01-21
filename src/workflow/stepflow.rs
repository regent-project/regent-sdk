use crate::connection::hosthandler::HostHandler;
use crate::connection::specification::Privilege;
use crate::error::Error;
use crate::result::apicallresult::ApiCallStatus;
use crate::step::stepchange::StepChange;
use crate::step::stepresult::StepResult;
use crate::task::step::Step;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StepFlow {
    pub step_expected: Step,
    pub allowed_to_fail: bool,
    pub step_change: Option<StepChange>,
    pub step_result: Option<StepResult>,
    pub step_status: StepStatus,
}

impl StepFlow {
    pub fn from(step: Step) -> StepFlow {
        StepFlow {
            step_expected: step.clone(),
            allowed_to_fail: match step.allowed_to_fail {
                Some(value) => value,
                None => false,
            },
            step_change: None,
            step_result: None,
            step_status: StepStatus::NotRunYet,
        }
    }

    pub fn dry_run(
        &mut self,
        hosthandler: &mut HostHandler,
        tera_context: &mut tera::Context,
    ) -> Result<(), Error> {
        let privilege = match (
            self.step_expected.with_sudo,
            self.step_expected.with_sudo_rs,
        ) {
            (None, None)
            | (None, Some(false))
            | (Some(false), None)
            | (Some(false), Some(false)) => match &self.step_expected.run_as {
                None => Privilege::Usual,
                Some(username) => Privilege::WithSudoAsUser(username.into()),
            },
            (Some(true), Some(false)) | (Some(true), None) => match &self.step_expected.run_as {
                None => Privilege::WithSudo,
                Some(username) => Privilege::WithSudoAsUser(username.into()),
            },
            (Some(false), Some(true)) | (None, Some(true)) => match &self.step_expected.run_as {
                None => Privilege::WithSudoRs,
                Some(username) => Privilege::WithSudoRsAsUser(username.into()),
            },
            (Some(true), Some(true)) => {
                return Err(Error::FailedInitialization(
                    "Paramaters with_sudo and with_sudo_rs are mutually exclusive".into(),
                ));
            }
        };

        match self
            .step_expected
            .moduleblock
            .consider_context(tera_context)
            .unwrap() // TODO : If register of a step is used in another step later, dry_run is impossible -> handle this case
            .dry_run_moduleblock(hosthandler, privilege)
        {
            Ok(mbchange) => {
                match &mbchange {
                    StepChange::AlreadyMatched(_) => {
                        self.step_status = StepStatus::AlreadyMatched;
                    }
                    StepChange::ModuleApiCalls(_) => {
                        self.step_status = StepStatus::ChangeRequired;
                    }
                }
                self.step_change = Some(mbchange);
            }
            Err(error) => {
                return Err(error);
            }
        }

        Ok(())
    }
    pub fn apply(
        &mut self,
        hosthandler: &mut HostHandler,
        tera_context: &mut tera::Context,
    ) -> Result<(), Error> {
        let privilege = match (
            self.step_expected.with_sudo,
            self.step_expected.with_sudo_rs,
        ) {
            (None, None)
            | (None, Some(false))
            | (Some(false), None)
            | (Some(false), Some(false)) => match &self.step_expected.run_as {
                None => Privilege::Usual,
                Some(username) => Privilege::WithSudoAsUser(username.into()),
            },
            (Some(true), Some(false)) | (Some(true), None) => match &self.step_expected.run_as {
                None => Privilege::WithSudo,
                Some(username) => Privilege::WithSudoAsUser(username.into()),
            },
            (Some(false), Some(true)) | (None, Some(true)) => match &self.step_expected.run_as {
                None => Privilege::WithSudoRs,
                Some(username) => Privilege::WithSudoRsAsUser(username.into()),
            },
            (Some(true), Some(true)) => {
                return Err(Error::FailedInitialization(
                    "Paramaters with_sudo and with_sudo_rs are mutually exclusive".into(),
                ));
            }
        };

        // Dry run -> Changes
        match self
            .step_expected
            .moduleblock
            .consider_context(tera_context)
            .unwrap()
            .dry_run_moduleblock(hosthandler, privilege)
        {
            Ok(mbchange) => {
                match &mbchange {
                    StepChange::AlreadyMatched(_) => {
                        self.step_status = StepStatus::AlreadyMatched;
                    }
                    StepChange::ModuleApiCalls(_) => {
                        self.step_status = StepStatus::ChangeRequired;
                    }
                }
                self.step_change = Some(mbchange);
            }
            Err(error) => {
                return Err(error);
            }
        }

        // Apply the changes
        match &self.step_change {
            Some(change) => {
                let result = change.apply_moduleblockchange(hosthandler);
                let mut step_status = StepStatus::ApplySuccessful;

                for apicallresult in result.apicallresults.clone().iter() {
                    match apicallresult.status {
                        ApiCallStatus::Failure(_) => {
                            if self.allowed_to_fail {
                                step_status = StepStatus::ApplyFailedButAllowed;
                            } else {
                                step_status = StepStatus::ApplyFailed;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                // Register : push step result to context under the specified variable name
                if let Some(variable_name) = &self.step_expected.register {
                    tera_context.insert(variable_name, &StepResult::from(&result.apicallresults));
                }

                self.step_status = step_status;
                self.step_result = Some(result);
            }
            None => {
                return Err(Error::WorkFlowNotFollowed(
                    "StepStatus = ChangeRequired but StepChange is empty. Something needs to be done but no information on what to do is provided.".into()
                ))
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum StepStatus {
    NotRunYet,
    AlreadyMatched,
    ChangeRequired,
    ApplySuccessful,
    ApplyFailedButAllowed,
    ApplyFailed,
}
