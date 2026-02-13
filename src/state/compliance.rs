use serde::{Deserialize, Serialize};

use crate::{managed_host::InternalApiCallOutcome, state::attribute::Remediation};

#[derive(Serialize, Deserialize)]
pub struct ManagedHostStatus {
    state: HostStatus,
    actions_taken: Option<Vec<Action>>,
}

impl ManagedHostStatus {
    pub fn already_compliant() -> Self {
        Self {
            state: HostStatus::AlreadyCompliant,
            actions_taken: None,
        }
    }

    pub fn not_compliant(remediations: Vec<Remediation>) -> Self {
        Self {
            state: HostStatus::NotCompliant,
            actions_taken: Some(
                remediations
                    .into_iter()
                    .map(|remediation| Action::from(remediation, None))
                    .collect(),
            ),
        }
    }

    pub fn reach_compliance_success(actions: Vec<Action>) -> Self {
        Self {
            state: HostStatus::ReachComplianceSuccess,
            actions_taken: Some(actions),
        }
    }

    pub fn reach_compliance_failed(actions: Vec<Action>) -> Self {
        Self {
            state: HostStatus::ReachComplianceFailed,
            actions_taken: Some(actions),
        }
    }

    pub fn is_already_compliant(&self) -> bool {
        matches!(self.state, HostStatus::AlreadyCompliant)
    }

    pub fn is_not_compliant(&self) -> bool {
        matches!(self.state, HostStatus::NotCompliant)
    }

    pub fn is_reach_compliance_success(&self) -> bool {
        matches!(self.state, HostStatus::ReachComplianceSuccess)
    }

    pub fn is_reach_compliance_failed(&self) -> bool {
        matches!(self.state, HostStatus::ReachComplianceFailed)
    }

    pub fn all_remediations(&self) -> Vec<Remediation> {
        // TODO : improve this by returning Option or Result
        if let None = self.actions_taken {
            return Vec::new();
        }

        self.actions_taken
            .as_ref()
            .unwrap()
            .iter()
            .map(|action| action.remediation.clone())
            .collect()
    }

    pub fn actions_taken(&self) -> Vec<(Remediation, InternalApiCallOutcome)> {
        // TODO : improve this by returning Option or Result
        match &self.actions_taken {
            None => {
                return Vec::new();
            }
            Some(actions) => {
                let mut actions_taken: Vec<(Remediation, InternalApiCallOutcome)> = Vec::new();

                for action in actions {
                    match &action.action_result {
                        Some(action_result) => {
                            actions_taken.push((action.remediation.clone(), action_result.clone()));
                        }
                        None => {
                            break;
                        }
                    }
                }
                actions_taken
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HostStatus {
    AlreadyCompliant,
    NotCompliant,
    ReachComplianceFailed,
    ReachComplianceSuccess,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Action {
    remediation: Remediation,
    // action_result is Option since it can not have been tried yet
    action_result: Option<InternalApiCallOutcome>,
}

impl Action {
    pub fn from(remediation: Remediation, action_result: Option<InternalApiCallOutcome>) -> Self {
        Self {
            remediation,
            action_result,
        }
    }
}

#[derive(Debug)]
pub enum AttributeComplianceAssessment {
    Compliant,
    NonCompliant(Vec<Remediation>),
}

impl AttributeComplianceAssessment {
    pub fn remediations(&self) -> Vec<&Remediation> {
        match self {
            AttributeComplianceAssessment::Compliant => Vec::new(),
            AttributeComplianceAssessment::NonCompliant(remediations) => {
                remediations.iter().collect()
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttributeComplianceResult {
    status: AttributeComplianceStatus,
    details: Option<Vec<(Remediation, InternalApiCallOutcome)>>,
}

impl AttributeComplianceResult {
    pub fn from(
        status: AttributeComplianceStatus,
        details: Option<Vec<(Remediation, InternalApiCallOutcome)>>,
    ) -> Self {
        AttributeComplianceResult { status, details }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AttributeComplianceStatus {
    AlreadyCompliant,
    ReachedCompliance,
    NonCompliant,
    FailedReachedCompliance,
}
