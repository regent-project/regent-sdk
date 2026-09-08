//! DNS resolution attribute
//!
//! This module provides the `DnsExpectedState` type for verifying that DNS names
//! resolve as expected. It is an assessment-only attribute: it reports compliance
//! but never produces remediations, because a wrong DNS configuration cannot be
//! fixed automatically by the SDK.
//!
//! The attribute relies on the `dig` command being available on the target host.
//!
//! **Compatible OS:**
//! - Linux - uses `dig +short`
//! - Any host where `dig` is available
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::network::dns::{DnsExpectedState, DnsRecordType};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//! use std::net::IpAddr;
//!
//! // Assert www.example.com resolves to 93.184.216.34 (A record) via a specific server
//! let dns = DnsExpectedState::check_response_and_server(
//!     "www.example.com",
//!     DnsRecordType::A("93.184.216.34".parse().unwrap()),
//!     "8.8.8.8".parse().unwrap(),
//! );
//!
//! // Assert www.example.com resolves to a known AAAA record using OS-configured servers
//! let dns_os = DnsExpectedState::check_response(
//!     "www.example.com",
//!     DnsRecordType::Aaaa("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()),
//! );
//!
//! // Assert alias.example.com is a CNAME for www.example.com using OS-configured servers
//! let dns_cname = DnsExpectedState::check_response(
//!     "alias.example.com",
//!     DnsRecordType::Cname("www.example.com".to_string()),
//! );
//!
//! // Assert www.example.com resolves at all, querying a specific server
//! let dns_server = DnsExpectedState::check_server(
//!     "www.example.com",
//!     "8.8.8.8".parse().unwrap(),
//! );
//!
//! // Assert www.example.com resolves at all, using OS-configured servers
//! let dns_simple = DnsExpectedState::simple_check("www.example.com");
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::dns(dns, Privilege::None, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! `CheckResponseAndServer` - assert a name resolves to a response via a server:
//!
//! ```yaml
//! Attributes:
//!   - Name: www.example.com resolves to 93.184.216.34 via 8.8.8.8
//!     Privilege: !None
//!     Detail: !Dns
//!       DnsName: www.example.com
//!       ExpectedResponse:
//!         A: 93.184.216.34
//!       Server: 8.8.8.8
//! ```
//!
//! `CheckResponse` - assert a name resolves to a response via OS-configured servers:
//!
//! ```yaml
//! Attributes:
//!   - Name: www.example.com resolves to an AAAA record
//!     Privilege: !None
//!     Detail: !Dns
//!       DnsName: www.example.com
//!       ExpectedResponse:
//!         Aaaa: 2606:2800:220:1:248:1893:25c8:1946
//! ```
//!
//! A CNAME response is expressed as a string:
//!
//! ```yaml
//! Attributes:
//!   - Name: alias.example.com is a CNAME for www.example.com
//!     Privilege: !None
//!     Detail: !Dns
//!       DnsName: alias.example.com
//!       ExpectedResponse:
//!         Cname: www.example.com
//! ```
//!
//! `CheckServer` - assert a name resolves at all via a specific server:
//!
//! ```yaml
//! Attributes:
//!   - Name: www.example.com resolves via 8.8.8.8
//!     Privilege: !None
//!     Detail: !Dns
//!       DnsName: www.example.com
//!       Server: 8.8.8.8
//! ```
//!
//! `SimpleCheck` - assert a name resolves at all via OS-configured servers:
//!
//! ```yaml
//! Attributes:
//!   - Name: www.example.com resolves
//!     Privilege: !None
//!     Detail: !Dns
//!       DnsName: www.example.com
//! ```
//!
//! # Note on remediation
//!
//! This attribute is assessment-only. If the name does not resolve as expected,
//! compliance is reported as `NonCompliantFatal`, but no remediation is generated.
//! The associated `DnsApiCall` always returns an `InternalLogicError` because DNS
//! configuration cannot be remediated automatically.

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DnsRecordType {
    A(IpAddr),
    Aaaa(IpAddr),
    Cname(String),
}

impl DnsRecordType {
    fn dig_arg_equivalent(&self) -> &'static str {
        match self {
            DnsRecordType::A(_) => "A",
            DnsRecordType::Aaaa(_) => "AAAA",
            DnsRecordType::Cname(_) => "CNAME",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(rename_all = "PascalCase")]
pub enum DnsExpectedState {
    #[serde(rename_all = "PascalCase")]
    CheckResponseAndServer {
        dns_name: String,
        expected_response: DnsRecordType,
        server: IpAddr,
    },
    #[serde(rename_all = "PascalCase")]
    CheckResponse {
        dns_name: String,
        expected_response: DnsRecordType,
    },
    #[serde(rename_all = "PascalCase")]
    CheckServer { dns_name: String, server: IpAddr },
    #[serde(rename_all = "PascalCase")]
    SimpleCheck { dns_name: String },
}

impl DnsExpectedState {
    pub fn check_response_and_server(
        dns_name: &str,
        expected_response: DnsRecordType,
        server: IpAddr,
    ) -> DnsExpectedState {
        DnsExpectedState::CheckResponseAndServer {
            dns_name: dns_name.to_string(),
            expected_response,
            server,
        }
    }

    pub fn check_response(dns_name: &str, expected_response: DnsRecordType) -> DnsExpectedState {
        DnsExpectedState::CheckResponse {
            dns_name: dns_name.to_string(),
            expected_response,
        }
    }

    pub fn check_server(dns_name: &str, server: IpAddr) -> DnsExpectedState {
        DnsExpectedState::CheckServer {
            dns_name: dns_name.to_string(),
            server,
        }
    }

    pub fn simple_check(dns_name: &str) -> DnsExpectedState {
        DnsExpectedState::SimpleCheck {
            dns_name: dns_name.to_string(),
        }
    }
}

impl Check for DnsExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        let (dns_name, expected_response) = match &self {
            DnsExpectedState::CheckResponseAndServer {
                dns_name,
                expected_response,
                server: _,
            } => (dns_name, Some(expected_response)),
            DnsExpectedState::CheckResponse {
                dns_name,
                expected_response,
            } => (dns_name, Some(expected_response)),
            DnsExpectedState::CheckServer {
                dns_name,
                server: _,
            } => (dns_name, None),
            DnsExpectedState::SimpleCheck { dns_name } => (dns_name, None),
        };

        if dns_name.trim().is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "DnsName is empty".to_string(),
            ));
        }
        if !is_valid_dns_name(dns_name) {
            return Err(RegentError::IncoherentExpectedState(format!(
                "DnsName '{dns_name}' is not a valid DNS name"
            )));
        }

        if let Some(expected_response) = expected_response {
            match expected_response {
                DnsRecordType::A(ip) => {
                    if !ip.is_ipv4() {
                        return Err(RegentError::IncoherentExpectedState(format!(
                            "A record expects an IPv4 address but got {ip}"
                        )));
                    }
                }
                DnsRecordType::Aaaa(ip) => {
                    if !ip.is_ipv6() {
                        return Err(RegentError::IncoherentExpectedState(format!(
                            "AAAA record expects an IPv6 address but got {ip}"
                        )));
                    }
                }
                DnsRecordType::Cname(target) => {
                    if target.trim().is_empty() {
                        return Err(RegentError::IncoherentExpectedState(
                            "CNAME response is empty".to_string(),
                        ));
                    }
                    if !is_valid_dns_name(target) {
                        return Err(RegentError::IncoherentExpectedState(format!(
                            "CNAME response '{target}' is not a valid DNS name"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but DNS resolution is only supported on Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl Timeout for DnsExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DnsExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host
        if let Some(properties) = host_properties {
            self.check_host_compatibility(properties)?;
        }

        if let Err(details) = host_handler
            .is_this_command_available("dig", &Privilege::None)
            .await
        {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "command dig no available on this host : {:?}",
                details
            )));
        }

        let (dns_name, server, expected_response) = match &self {
            DnsExpectedState::CheckResponseAndServer {
                dns_name,
                expected_response,
                server,
            } => (dns_name, Some(*server), Some(expected_response)),
            DnsExpectedState::CheckResponse {
                dns_name,
                expected_response,
            } => (dns_name, None, Some(expected_response)),
            DnsExpectedState::CheckServer { dns_name, server } => (dns_name, Some(*server), None),
            DnsExpectedState::SimpleCheck { dns_name } => (dns_name, None, None),
        };

        // Query the specific record type when an expected response is given, so
        // that A/AAAA/CNAME answers are each matched against the right kind of
        // value. When no response is expected we let `dig` use its default
        // lookup and only care whether anything came back.
        let record_type = match expected_response {
            Some(response) => Some(response.dig_arg_equivalent()),
            None => None,
        };

        let dns_name = normalize_name(dns_name);

        let command_result = match host_handler
            .run_command(
                &final_dns_query(&dns_name, server, record_type),
                &Privilege::None,
            )
            .await
        {
            Ok(command_result) => command_result,
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Unable to run dig command: {:?}",
                    details
                )));
            }
        };

        if command_result.return_code != 0 {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Failed dig command: {:?}",
                command_result
            )));
        }

        // Trim and drop empty lines so a blank `dig +short` output is treated as
        // "no answer" regardless of the record type.
        let responses: Vec<&str> = command_result
            .stdout
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect();

        // If no response, the name didn't resolve to anything
        if responses.is_empty() {
            return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                "Name doesn't resolve".to_string(),
            ));
        }

        match expected_response {
            None => {
                // Just checking resolution, any response is accepted
                Ok(AttributeComplianceAssessment::Compliant)
            }
            Some(expected_response_details) => match expected_response_details {
                DnsRecordType::A(expected) => {
                    let parsed: Vec<IpAddr> =
                        responses.iter().filter_map(|l| l.parse().ok()).collect();
                    if parsed.contains(expected) {
                        Ok(AttributeComplianceAssessment::Compliant)
                    } else {
                        Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "Name resolves but expected A record {expected} not found among results ({:?})",
                            responses
                        )))
                    }
                }
                DnsRecordType::Aaaa(expected) => {
                    let parsed: Vec<IpAddr> =
                        responses.iter().filter_map(|l| l.parse().ok()).collect();
                    if parsed.contains(expected) {
                        Ok(AttributeComplianceAssessment::Compliant)
                    } else {
                        Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "Name resolves but expected AAAA record {expected} not found among results ({:?})",
                            responses
                        )))
                    }
                }
                DnsRecordType::Cname(expected) => {
                    let expected_normalized_version = normalize_name(expected);
                    if responses
                        .iter()
                        .any(|line| normalize_name(line) == expected_normalized_version)
                    {
                        Ok(AttributeComplianceAssessment::Compliant)
                    } else {
                        Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "Name resolves but expected CNAME record {expected} not found among results ({:?})",
                            responses
                        )))
                    }
                }
            },
        }
    }
}

/// This is a placeholder type: DNS misconfiguration cannot be remediated
/// automatically, so the assess step never produces a DnsApiCall. Any method
/// invoked on this type returns an InternalLogicError to signal a bug.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsApiCall {}

impl DnsApiCall {
    pub fn display(&self) -> String {
        return format!("Should not have been called");
    }
}

impl Check for DnsApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Err(RegentError::InternalLogicError(
            "(check) DnsApiCall should not have been called as we cannot remediate automatically a wrong DNS configuration".to_string()
        ))
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        Err(RegentError::InternalLogicError(
            "(check_host_compatibility) DnsApiCall should not have been called as we cannot remediate automatically a wrong DNS configuration".to_string()
        ))
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for DnsApiCall {
    async fn call(
        &self,
        _host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        Err(RegentError::InternalLogicError(
            "(call) DnsApiCall should not have been called as we cannot remediate automatically a wrong DNS configuration".to_string()
        ))
    }
}

fn final_dns_query(dns_name: &str, server: Option<IpAddr>, record_type: Option<&str>) -> String {
    let record_type_arg = match record_type {
        Some(record) => format!(" {record}"),
        None => String::new(),
    };
    match server {
        Some(server_address) => {
            format!("dig @{server_address} +short {dns_name}{record_type_arg}")
        }
        None => {
            format!("dig +short {dns_name}{record_type_arg}")
        }
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_valid_dns_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');

    !name.is_empty()
        && name.len() <= 253
        && !name.contains("..")
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '-'
                || character == '_'
                || character == '.'
                || character == '*'
        })
}
