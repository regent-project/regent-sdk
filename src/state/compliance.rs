use crate::{managed_host::InternalApiCallOutcome, state::attribute::{Attribute, Remediation}};

// #[derive(Debug)]
// pub enum ComplianceAssessment {
//     AlreadyCompliant,
//     NonCompliant(Vec<Remediation>),
// }

#[derive(Debug)]
pub enum HostComplianceStatus {
    AlreadyCompliant,
    ReachedCompliance,
    NonCompliant,
    FailedReachedCompliance,
}

#[derive(Debug)]
pub struct HostComplianceAssessment {
    status: HostComplianceStatus,
    details: Vec<(Attribute, AttributeComplianceAssessment)>
}

impl HostComplianceAssessment {
    pub fn from(status: HostComplianceStatus, details: Vec<(Attribute, AttributeComplianceAssessment)>) -> Self {
        HostComplianceAssessment {
            status,
            details,
        }
    }

    pub fn is_already_compliant(&self) -> bool {
        matches!(self.status, HostComplianceStatus::AlreadyCompliant)
    }

    pub fn is_reached_compliance(&self) -> bool {
        matches!(self.status, HostComplianceStatus::ReachedCompliance)
    }

    pub fn is_non_compliant(&self) -> bool {
        matches!(self.status, HostComplianceStatus::NonCompliant)
    }

    pub fn is_failed_reached_compliance(&self) -> bool {
        matches!(self.status, HostComplianceStatus::FailedReachedCompliance)
    }
}

#[derive(Debug)]
pub enum AttributeComplianceAssessment {
    Compliant,
    NonCompliant(Vec<Remediation>),
}

#[derive(Debug)]
pub struct HostComplianceResult {
    status: HostComplianceStatus,
    details: Vec<(Attribute, AttributeComplianceResult)>
}

impl HostComplianceResult {
    pub fn from(status: HostComplianceStatus, details: Vec<(Attribute, AttributeComplianceResult)>) -> Self {
        HostComplianceResult {
            status,
            details,
        }
    }
}

#[derive(Debug)]
pub struct AttributeComplianceResult {
    status: AttributeComplianceStatus,
    details: Option<Vec<(Remediation, InternalApiCallOutcome)>>
}

impl AttributeComplianceResult {
    pub fn from(status: AttributeComplianceStatus, details: Option<Vec<(Remediation, InternalApiCallOutcome)>>) -> Self {
        AttributeComplianceResult {
            status,
            details,
        }
    }
}

#[derive(Debug)]
pub enum AttributeComplianceStatus {
    AlreadyCompliant,
    ReachedCompliance,
    NonCompliant,
    FailedReachedCompliance,
}