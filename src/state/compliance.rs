use crate::{managed_host::InternalApiCallOutcome, state::attribute::Remediation};

#[derive(Debug)]
pub enum ComplianceAssesment {
    AlreadyCompliant,
    NonCompliant(Vec<Remediation>),
}

#[derive(Debug)]
pub enum ComplianceStatus {
    AlreadyCompliant,
    ReachedCompliance(Vec<(Remediation, InternalApiCallOutcome)>),
    NonCompliant(Vec<Remediation>),
    FailedReachedCompliance(Vec<(Remediation, InternalApiCallOutcome)>),
}
