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
//! # Variants
//!
//! `DnsExpectedState` is an untagged, PascalCase enum. Pick the variant that
//! matches what you want to assert:
//!
//! - `CheckResponseAndServer`: name must resolve to a given response using a given server
//! - `CheckResponse`: name must resolve to a given response using OS-configured servers
//! - `CheckServer`: name must resolve (any response) using a given server
//! - `SimpleCheck`: name must resolve (any response) using OS-configured servers
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::network::dns::DnsExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Assert www.example.com resolves to 93.184.216.34 via a specific server
//! let dns = DnsExpectedState::check_response_and_server("www.example.com", "93.184.216.34", "8.8.8.8");
//!
//! // Assert www.example.com resolves to a known address using OS-configured servers
//! let dns_os = DnsExpectedState::check_response("www.example.com", "93.184.216.34");
//!
//! // Assert www.example.com resolves at all, querying a specific server
//! let dns_server = DnsExpectedState::check_server("www.example.com", "8.8.8.8");
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
//!       Response: 93.184.216.34
//!       Server: 8.8.8.8
//! ```
//!
//! `CheckResponse` - assert a name resolves to a response via OS-configured servers:
//!
//! ```yaml
//! Attributes:
//!   - Name: www.example.com resolves to 93.184.216.34
//!     Privilege: !None
//!     Detail: !Dns
//!       DnsName: www.example.com
//!       Response: 93.184.216.34
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
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Desired DNS resolution state.
///
/// See the module-level documentation for YAML examples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(rename_all = "PascalCase")]
pub enum DnsExpectedState {
    /// Check that `dns_name` resolves to `response` using `server`.
    #[serde(rename_all = "PascalCase")]
    CheckResponseAndServer {
        /// DNS name to resolve.
        dns_name: String,
        /// Expected resolved address/result.
        response: String,
        /// DNS server to query (`@server` passed to `dig`).
        server: String,
    },
    /// Check that `dns_name` resolves to `response` using OS-configured servers.
    #[serde(rename_all = "PascalCase")]
    CheckResponse {
        /// DNS name to resolve.
        dns_name: String,
        /// Expected resolved address/result.
        response: String,
    },
    /// Check that `dns_name` resolves using `server`; any successful response is accepted.
    #[serde(rename_all = "PascalCase")]
    CheckServer {
        /// DNS name to resolve.
        dns_name: String,
        /// DNS server to query (`@server` passed to `dig`).
        server: String,
    },
    /// Check that `dns_name` resolves using OS-configured servers; any successful response is accepted.
    #[serde(rename_all = "PascalCase")]
    SimpleCheck {
        /// DNS name to resolve.
        dns_name: String,
    },
}

impl DnsExpectedState {
    /// Create a `CheckResponseAndServer` configuration: assert that `dns_name`
    /// resolves to `response` using `server`.
    pub fn check_response_and_server(
        dns_name: &str,
        response: &str,
        server: &str,
    ) -> DnsExpectedState {
        DnsExpectedState::CheckResponseAndServer {
            dns_name: dns_name.to_string(),
            response: response.to_string(),
            server: server.to_string(),
        }
    }

    /// Create a `CheckResponse` configuration: assert that `dns_name` resolves to
    /// `response` using OS-configured servers.
    pub fn check_response(dns_name: &str, response: &str) -> DnsExpectedState {
        DnsExpectedState::CheckResponse {
            dns_name: dns_name.to_string(),
            response: response.to_string(),
        }
    }

    /// Create a `CheckServer` configuration: assert that `dns_name` resolves (any
    /// successful response) using `server`.
    pub fn check_server(dns_name: &str, server: &str) -> DnsExpectedState {
        DnsExpectedState::CheckServer {
            dns_name: dns_name.to_string(),
            server: server.to_string(),
        }
    }

    /// Create a `SimpleCheck` configuration: assert that `dns_name` resolves (any
    /// successful response) using OS-configured servers.
    pub fn simple_check(dns_name: &str) -> DnsExpectedState {
        DnsExpectedState::SimpleCheck {
            dns_name: dns_name.to_string(),
        }
    }
}

impl Check for DnsExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // TODO : Add checks on all potentially present but empty strings
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        // Windows ?
        Ok(())
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
        _host_properties: &Option<HostProperties>,
        _privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
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
                response,
                server,
            } => (dns_name, Some(server.to_string()), Some(response.to_string())),
            DnsExpectedState::CheckResponse { dns_name, response } => (dns_name, None, Some(response.to_string())),
            DnsExpectedState::CheckServer { dns_name, server } => {
                (dns_name, Some(server.to_string()), None)
            }
            DnsExpectedState::SimpleCheck { dns_name } => (dns_name, None, None),
        };

        let responses: Vec<String> = match host_handler
            .run_command(&final_dns_query(dns_name, server), &Privilege::None)
            .await
        {
            Ok(command_result) => {
                if command_result.return_code == 0 {
                    // Turn the response into the return type of this function
                    command_result
                        .stdout
                        .lines()
                        .map(|line| line.to_string())
                        .collect()
                } else {
                    return Err(RegentError::FailedDryRunEvaluation(format!(
                        "Failed dig command: {:?}",
                        command_result
                    )));
                }
            }
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Unable to run dig command: {:?}",
                    details
                )));
            }
        };

        // If no response, the name didn't resolve to anything
        if responses.is_empty() {
            return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                "Name doesnt\'t resolve".to_string()
            ));
        } else {
            match expected_response {
                Some(expected_response) => {
                    if responses.contains(&expected_response) {
                        return Ok(AttributeComplianceAssessment::Compliant);
                    } else {
                        return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                            format!("Name resolves but expected response not found among results ({:?})", responses)
                        ))
                    }
                }
                None => {
                    // Just checking resolution, any response is accepted
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
            }
        }

    }
}

/// Remediation API call for the DNS attribute.
///
/// This is a placeholder type: DNS misconfiguration cannot be remediated
/// automatically, so the assess step never produces a `DnsApiCall`. Any method
/// invoked on this type returns an `InternalLogicError` to surface the fact that
/// it should never have been reached.
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
        // This should never be called as the Assess step should never produce remediations.
        // That's why we return directly a logic error here.
        Err(RegentError::InternalLogicError(
            "(call) DnsApiCall should not have been called as we cannot remediate automatically a wrong DNS configuration".to_string()
        ))
    }
}

fn final_dns_query(dns_name: &str, server: Option<String>) -> String {
    match server {
        Some(server_address) => {
            format!("dig @{server_address} +short {dns_name}")
        }
        None => {
            format!("dig +short {dns_name}")
        }
    }
}
