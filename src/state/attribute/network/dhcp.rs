//! DHCP lease probing attribute
//!
//! This module provides the `DhcpExpectedState` type for verifying that a host's
//! network interface can obtain a DHCP lease as expected. It is an
//! assessment-only attribute: it reports compliance but never produces
//! remediations, because a wrong DHCP configuration cannot be fixed automatically
//! by the SDK.
//!
//! To avoid altering the host's real interface configuration, the assessment does
//! not run `dhclient` directly on the target interface. Instead it creates a
//! short-lived macvlan virtual interface on top of it, runs a one-shot `dhclient`
//! probe on that virtual interface, then removes it. The probe's lease and pid
//! files are isolated under `/tmp` so the host's real DHCP state is never touched.
//!
//! The attribute relies on the `dhclient`, `ip`, and `timeout` commands being
//! available on the target host, and requires `sudo`/`sudo-rs` privileges.
//!
//! **Compatible OS:** Linux (wired ethernet interfaces only).
//!
//! **Incompatible interfaces:** wireless interfaces are refused cleanly. A macvlan
//! cannot get an independent DHCP identity over a managed-mode Wi-Fi link (the AP
//! only delivers to the single associated MAC).
//!
//! - `CheckResponseAndServer`: lease must match a given response and come from a given server
//! - `CheckResponse`: lease must match a given response from any server
//! - `CheckServer`: lease must come from a given server (any valid response)
//! - `SimpleCheck`: any valid lease from any server
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::network::dhcp::DhcpExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//! use std::net::IpAddr;
//!
//! // Assert eth0 gets a lease matching a response from a specific server
//! let dhcp = DhcpExpectedState::check_response_and_server(
//!     "eth0",
//!     None,
//!     "10.0.0.5".parse().unwrap(),
//!     "255.255.255.0".parse().unwrap(),
//!     vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
//!     "10.0.0.1".parse().unwrap(),
//!     false,
//! );
//!
//! // Assert eth0 gets a lease matching a response from any server
//! let dhcp_resp = DhcpExpectedState::check_response(
//!     "eth0",
//!     None,
//!     "10.0.0.5".parse().unwrap(),
//!     "255.255.255.0".parse().unwrap(),
//!     vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
//! );
//!
//! // Assert eth0 gets a lease from a specific server, any valid response
//! let dhcp_server = DhcpExpectedState::check_server(
//!     "eth0",
//!     None,
//!     "10.0.0.1".parse().unwrap(),
//!     false,
//! );
//!
//! // Assert eth0 gets a lease from any server
//! let dhcp_simple = DhcpExpectedState::simple_check("eth0", None);
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::dhcp(dhcp, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! `CheckResponseAndServer` - assert an interface gets a given lease from a given server:
//!
//! ```yaml
//! Attributes:
//!   - Name: eth0 gets expected lease from 10.0.0.1
//!     Privilege: !WithSudo
//!     Detail: !Dhcp
//!       ParentInterface: eth0
//!       Check: !CheckResponseAndServer
//!         Response:
//!           Ip: 10.0.0.5
//!           Mask: 255.255.255.0
//!           Dns:
//!             - 8.8.8.8
//!             - 8.8.4.4
//!         Server: 10.0.0.1
//!         RogueServerAllowed: false
//! ```
//!
//! With an explicit MAC for the virtual interface (omit `MacAddress` to let the
//! kernel assign one):
//!
//! ```yaml
//! Attributes:
//!   - Name: eth0 gets expected lease from 10.0.0.1 with custom MAC
//!     Privilege: !WithSudo
//!     Detail: !Dhcp
//!       ParentInterface: eth0
//!       MacAddress: aa:bb:cc:dd:ee:ff
//!       Check: !CheckResponseAndServer
//!         Response:
//!           Ip: 10.0.0.5
//!           Mask: 255.255.255.0
//!           Dns:
//!             - 8.8.8.8
//!         Server: 10.0.0.1
//!         RogueServerAllowed: false
//! ```
//!
//! `CheckResponse` - assert an interface gets a given lease from any server:
//!
//! ```yaml
//! Attributes:
//!   - Name: eth0 gets expected lease
//!     Privilege: !WithSudo
//!     Detail: !Dhcp
//!       ParentInterface: eth0
//!       Check: !CheckResponse
//!         Response:
//!           Ip: 10.0.0.5
//!           Mask: 255.255.255.0
//!           Dns:
//!             - 8.8.8.8
//!             - 8.8.4.4
//! ```
//!
//! `CheckServer` - assert an interface gets a lease from a given server:
//!
//! ```yaml
//! Attributes:
//!   - Name: eth0 gets a lease from 10.0.0.1
//!     Privilege: !WithSudo
//!     Detail: !Dhcp
//!       ParentInterface: eth0
//!       Check: !CheckServer
//!         Server: 10.0.0.1
//!         RogueServerAllowed: false
//! ```
//!
//! `SimpleCheck` - assert an interface gets a lease from any server:
//!
//! ```yaml
//! Attributes:
//!   - Name: eth0 gets a lease
//!     Privilege: !WithSudo
//!     Detail: !Dhcp
//!       ParentInterface: eth0
//!       Check: SimpleCheck
//! ```
//!
//! # Note on remediation
//!
//! This attribute is assessment-only. If the interface does not get an expected
//! lease, compliance is reported as `NonCompliantFatal`, but no remediation is
//! generated. The associated `DnsApiCall` always returns an `InternalLogicError`
//! because DHCP configuration cannot be remediated automatically.

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::hosts::properties::OsKind;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DhcpCheckBehavior {
    /// Only a given configuration from a given server is accepted
    #[serde(rename_all = "PascalCase")]
    CheckResponseAndServer {
        response: ExpectedDhcpResponse,
        server: IpAddr,
        rogue_server_allowed: bool,
    },
    /// Host gets back a configuration, any server can reply as long as the response is the one expected
    #[serde(rename_all = "PascalCase")]
    CheckResponse { response: ExpectedDhcpResponse },
    /// This server must respond, any valid response will do
    #[serde(rename_all = "PascalCase")]
    CheckServer {
        server: IpAddr,
        rogue_server_allowed: bool,
    },
    /// Host gets back a configuration, any valid response from any server will do
    #[serde(rename_all = "PascalCase")]
    SimpleCheck,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DhcpExpectedState {
    parent_interface: String,
    mac_address: Option<String>,
    check: DhcpCheckBehavior,
}

impl DhcpExpectedState {
    pub fn check_response_and_server(
        parent_interface: &str,
        client_mac_address: Option<&str>,
        expected_ip: IpAddr,
        expected_mask: IpAddr,
        expected_dns: Vec<IpAddr>,
        server: IpAddr,
        rogue_server_allowed: bool,
    ) -> DhcpExpectedState {
        DhcpExpectedState {
            parent_interface: parent_interface.to_string(),
            mac_address: client_mac_address.map(|m| m.to_string()),
            check: DhcpCheckBehavior::CheckResponseAndServer {
                response: ExpectedDhcpResponse::new(expected_ip, expected_mask, expected_dns),
                server,
                rogue_server_allowed,
            },
        }
    }

    pub fn check_response(
        parent_interface: &str,
        client_mac_address: Option<&str>,
        expected_ip: IpAddr,
        expected_mask: IpAddr,
        expected_dns: Vec<IpAddr>,
    ) -> DhcpExpectedState {
        DhcpExpectedState {
            parent_interface: parent_interface.to_string(),
            mac_address: client_mac_address.map(|m| m.to_string()),
            check: DhcpCheckBehavior::CheckResponse {
                response: ExpectedDhcpResponse::new(expected_ip, expected_mask, expected_dns),
            },
        }
    }

    pub fn check_server(
        parent_interface: &str,
        client_mac_address: Option<&str>,
        server: IpAddr,
        rogue_server_allowed: bool,
    ) -> DhcpExpectedState {
        DhcpExpectedState {
            parent_interface: parent_interface.to_string(),
            mac_address: client_mac_address.map(|m| m.to_string()),
            check: DhcpCheckBehavior::CheckServer {
                server,
                rogue_server_allowed,
            },
        }
    }

    pub fn simple_check(
        parent_interface: &str,
        client_mac_address: Option<&str>,
    ) -> DhcpExpectedState {
        DhcpExpectedState {
            parent_interface: parent_interface.to_string(),
            mac_address: client_mac_address.map(|m| m.to_string()),
            check: DhcpCheckBehavior::SimpleCheck,
        }
    }
}

impl Check for DhcpExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // No field may be an empty string.
        if self.parent_interface.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "ParentInterface is empty".to_string(),
            ));
        }

        // When a MAC address is provided, it must be a valid one.
        if let Some(mac) = &self.mac_address {
            if mac.is_empty() {
                return Err(RegentError::IncoherentExpectedState(
                    "MacAddress is present but empty".to_string(),
                ));
            }
            if !is_valid_mac_address(mac) {
                return Err(RegentError::IncoherentExpectedState(format!(
                    "MacAddress '{mac}' is not a valid MAC address (expected 6 hex octets \
                     separated by ':', e.g. aa:bb:cc:dd:ee:ff)"
                )));
            }
        }

        // Variant-specific validation.
        match &self.check {
            DhcpCheckBehavior::CheckResponseAndServer {
                response,
                server: _,
                rogue_server_allowed: _,
            } => {
                check_expected_response(response)?;
            }
            DhcpCheckBehavior::CheckResponse { response } => {
                check_expected_response(response)?;
            }
            DhcpCheckBehavior::CheckServer {
                server: _,
                rogue_server_allowed: _,
            } => {}
            DhcpCheckBehavior::SimpleCheck => {}
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
                "Host is {:?} but iptables is only supported on Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl Timeout for DhcpExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(20)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DhcpExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if matches!(privilege, Privilege::None) {
            return Err(RegentError::WrongInitialization(format!(
                "DHCP assesment needs sudo/sudo-rs privileges"
            )));
        }

        if let Err(details) = host_handler
            .is_this_command_available("dhclient", &Privilege::None)
            .await
        {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "command dig no available on this host : {:?}",
                details
            )));
        }

        if let Err(details) = host_handler
            .is_this_command_available("ip", &Privilege::None)
            .await
        {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "command ip not available on this host : {:?}",
                details
            )));
        }

        if let Err(details) = host_handler
            .is_this_command_available("timeout", &Privilege::None)
            .await
        {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "command timeout not available on this host : {:?}",
                details
            )));
        }

        let parent_interface = self.parent_interface.clone();
        let mac_address = self.mac_address.clone();

        match host_handler
            .run_command(
                &is_wireless_interface_cmd(&parent_interface),
                &Privilege::None,
            )
            .await
        {
            Ok(result) if result.return_code == 0 => {
                return Err(RegentError::IncompatibleHost(format!(
                    "{parent_interface} is a wireless interface; the DHCP probe uses a \
                     macvlan virtual interface, which is not supported over Wi-Fi"
                )));
            }
            Ok(_) => { /* not wireless: proceed */ }
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Unable to determine whether {parent_interface} is wireless: {:?}",
                    details
                )));
            }
        }

        // When the user provides a MAC address, make sure it is not already in use
        // by a real interface on the host. Reusing an existing MAC would create L2
        // conflicts (two interfaces answering to the same address on the same wire).
        if let Some(mac) = &mac_address {
            match host_handler
                .run_command(&mac_in_use_check_cmd(mac), &Privilege::None)
                .await
            {
                Ok(result) if result.return_code == 0 => {
                    return Err(RegentError::IncoherentExpectedState(format!(
                        "MAC address {mac} is already used by an interface on this host, \
                         this might create conflicts"
                    )));
                }
                Ok(_) => { /* MAC not in use: proceed */ }
                Err(details) => {
                    return Err(RegentError::FailedDryRunEvaluation(format!(
                        "Unable to check whether MAC address {mac} is already in use: {:?}",
                        details
                    )));
                }
            }
        }

        let virtual_interface = virtual_interface_name(&parent_interface);
        let (lease_file, pid_file) = probe_tmp_file_paths(&virtual_interface);

        let _ = host_handler
            .run_command(&cleanup_probe_files_cmd(&lease_file, &pid_file), &privilege)
            .await;
        let _ = host_handler
            .run_command(&delete_interface_cmd(&virtual_interface), &privilege)
            .await;

        if let Err(details) = host_handler
            .run_command(
                &create_virtual_interface_cmd(
                    &parent_interface,
                    &virtual_interface,
                    mac_address.as_deref(),
                ),
                &privilege,
            )
            .await
        {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Failed to create virtual interface {virtual_interface} on {parent_interface} for DHCP probing: {:?}",
                details
            )));
        }

        if let Err(details) = host_handler
            .run_command(&bring_up_interface_cmd(&virtual_interface), &privilege)
            .await
        {
            let _ = host_handler
                .run_command(&delete_interface_cmd(&virtual_interface), &privilege)
                .await;
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Failed to bring up virtual interface {virtual_interface} for DHCP probing: {:?}",
                details
            )));
        }

        let probe_timeout_secs = self.default_timeout().as_secs();

        let probe_result = host_handler
            .run_command(
                &final_dhcp_query(
                    &virtual_interface,
                    probe_timeout_secs,
                    &lease_file,
                    &pid_file,
                ),
                &privilege,
            )
            .await;

        // Cleanup: remove the virtual interface and the isolated probe files
        // unconditionally.
        let _ = host_handler
            .run_command(&delete_interface_cmd(&virtual_interface), &privilege)
            .await;
        let _ = host_handler
            .run_command(&cleanup_probe_files_cmd(&lease_file, &pid_file), &privilege)
            .await;

        let dhcp_response = match probe_result {
            Ok(command_result) => {
                // 124 is the exit status used by the `timeout` command when the
                // wrapped command exceeded its time limit.
                if command_result.return_code == 124 {
                    return Err(RegentError::TimeOutReached(format!(
                        "dhclient on {virtual_interface} did not finish within {probe_timeout_secs}s"
                    )));
                }
                if command_result.return_code == 0 {
                    let raw_stdout_and_stderr = command_result.stdout + &command_result.stderr;

                    match parse_dhcp_response(&raw_stdout_and_stderr) {
                        Ok(dhcp_response) => dhcp_response,
                        Err(details) => {
                            return Err(RegentError::FailedDryRunEvaluation(format!(
                                "Failed to parse dhclient command result: {}",
                                details
                            )));
                        }
                    }
                } else {
                    return Err(RegentError::FailedDryRunEvaluation(format!(
                        "Failed dhclient command: {:?}",
                        command_result
                    )));
                }
            }
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Unable to run dhclient command: {:?}",
                    details
                )));
            }
        };

        match &self.check {
            DhcpCheckBehavior::CheckResponseAndServer {
                response,
                server,
                rogue_server_allowed,
            } => {
                // Did the expected server answered ?
                match dhcp_response.responding_servers.get(server) {
                    Some(_expected_server) => {
                        match (dhcp_response.responding_servers.len(), rogue_server_allowed) {
                            (0, _) => {
                                // Nobody answered ?
                                Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                    "No responding server at all"
                                )))
                            }
                            (1, _) | (_, true) => {
                                match dhcp_response.responding_servers.get(server) {
                                    Some(_expected_server) => {
                                        match (
                                            dhcp_response.responding_servers.len(),
                                            rogue_server_allowed,
                                        ) {
                                            (0, _) => {
                                                // Nobody answered ?
                                                Ok(AttributeComplianceAssessment::NonCompliantFatal(
                                                    format!("No responding server at all")
                                                ))
                                            }
                                            (1, _) | (_, true) => {
                                                Ok(AttributeComplianceAssessment::Compliant)
                                            }
                                            (_, false) => Ok(
                                                AttributeComplianceAssessment::NonCompliantFatal(
                                                    format!(
                                                        "Expected server answered but there are also rogue DHCP servers ({:?})",
                                                        dhcp_response
                                                    ),
                                                ),
                                            ),
                                        }
                                    }
                                    None => Ok(AttributeComplianceAssessment::NonCompliantFatal(
                                        format!(
                                            "Expected server not among responding_servers ({:?})",
                                            dhcp_response
                                        ),
                                    )),
                                }
                            }
                            (_, false) => {
                                Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                    "Expected server answered but there are also rogue DHCP servers ({:?})",
                                    dhcp_response
                                )))
                            }
                        }
                    }
                    None => Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                        "Expected server not among responding_servers ({:?})",
                        dhcp_response
                    ))),
                }
            }
            DhcpCheckBehavior::CheckResponse { response } => {
                match dhcp_response.matches_expected_response(&response) {
                    ComparisonOutcome::Matches => Ok(AttributeComplianceAssessment::Compliant),
                    ComparisonOutcome::Different(why) => {
                        Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "Unexpected response. {}",
                            why
                        )))
                    }
                }
            }
            DhcpCheckBehavior::CheckServer {
                server,
                rogue_server_allowed,
            } => {
                // Did the expected server answered ?
                match dhcp_response.responding_servers.get(server) {
                    Some(_expected_server) => {
                        match (dhcp_response.responding_servers.len(), rogue_server_allowed) {
                            (0, _) => {
                                // Nobody answered ?
                                Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                    "No responding server at all"
                                )))
                            }
                            (1, _) | (_, true) => Ok(AttributeComplianceAssessment::Compliant),
                            (_, false) => {
                                Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                    "Expected server answered but there are also rogue DHCP servers ({:?})",
                                    dhcp_response
                                )))
                            }
                        }
                    }
                    None => Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                        "Expected server not among responding_servers ({:?})",
                        dhcp_response
                    ))),
                }
            }
            DhcpCheckBehavior::SimpleCheck => {
                // Nothing special here, we are just interested in getting a response, any value will do
                Ok(AttributeComplianceAssessment::Compliant)
            }
        }
    }
}

/// This is a placeholder type: DNS misconfiguration cannot be remediated
/// automatically, so the assess step never produces a `DnsApiCall`.
/// Each part returns an `InternalLogicError` to signal a bug.
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

#[derive(Debug)]
struct DhcpResponse {
    ip: Option<IpAddr>,
    mask: Option<IpAddr>,
    dns: Vec<IpAddr>,
    responding_servers: HashSet<IpAddr>,
}

impl DhcpResponse {
    fn matches_expected_response(
        &self,
        expected_response: &ExpectedDhcpResponse,
    ) -> ComparisonOutcome {
        if self.ip != Some(expected_response.ip) {
            return ComparisonOutcome::Different(format!(
                "Different IP : expected {}, got {:?}",
                expected_response.ip, &self.ip
            ));
        }

        if self.mask != Some(expected_response.mask) {
            return ComparisonOutcome::Different(format!(
                "Different mask : expected {}, got {:?}",
                expected_response.mask, &self.mask
            ));
        }

        // DNS servers may be returned in any order by the DHCP server, so compare
        // the two sets order-independently.
        let mut got_dns = self.dns.clone();
        let mut expected_dns = expected_response.dns.clone();
        got_dns.sort();
        expected_dns.sort();
        if got_dns != expected_dns {
            return ComparisonOutcome::Different(format!(
                "Different DNS : expected {:?}, got {:?}",
                expected_response.dns, &self.dns
            ));
        }

        ComparisonOutcome::Matches
    }
}

fn final_dhcp_query(
    interface: &str,
    timeout_secs: u64,
    lease_file: &str,
    pid_file: &str,
) -> String {
    // -1: one-shot, exit 0 after acquiring a lease (or exit 2 after one failed
    // attempt). The `-d` (foreground) flag is intentionally NOT used: in one-shot
    // mode it makes dhclient stay in the foreground managing the lease instead
    // of exiting, which would cause every successful probe to run until the
    // `timeout` wrapper kills it. Without `-d`, dhclient exits promptly on
    // success; on no answer it retransmits until `timeout` cuts it (rc 124).
    format!(
        "timeout {timeout_secs} dhclient -1 -v -cf /dev/null -lf {lease_file} -pf {pid_file} {interface}"
    )
}

/// Paths for the isolated dhclient lease and pid files used during a probe.
/// They live under /tmp so the probe never reads or writes the host's real
/// dhcp lease state: this guarantees a fresh DHCP exchange every run and avoids
/// leaving state behind in the host's persistent dhcp directories.
fn probe_tmp_file_paths(virtual_interface: &str) -> (String, String) {
    let lease = format!("/tmp/regent-dhcp-{virtual_interface}.leases");
    let pid = format!("/tmp/regent-dhcp-{virtual_interface}.pid");
    (lease, pid)
}

fn cleanup_probe_files_cmd(lease_file: &str, pid_file: &str) -> String {
    format!("rm -f {lease_file} {pid_file}")
}

/// Linux interface names are limited to 15 characters (IFNAMSIZ). Derive a virtual
/// interface name from the parent by prefixing it with "v" and truncating the parent
/// part so the total length never exceeds the limit.
fn virtual_interface_name(parent: &str) -> String {
    const MAX_IFACE_LEN: usize = 15;
    let max_parent_len = MAX_IFACE_LEN - "v".len();
    let truncated: String = parent.chars().take(max_parent_len).collect();
    format!("v{truncated}")
}

fn create_virtual_interface_cmd(
    parent: &str,
    virtual_interface: &str,
    mac_address: Option<&str>,
) -> String {
    match mac_address {
        Some(mac) => format!(
            "ip link add link {parent} name {virtual_interface} address {mac} type macvlan mode bridge"
        ),
        None => {
            format!("ip link add link {parent} name {virtual_interface} type macvlan mode bridge")
        }
    }
}

fn bring_up_interface_cmd(interface: &str) -> String {
    format!("ip link set {interface} up")
}

fn delete_interface_cmd(interface: &str) -> String {
    format!("ip link delete {interface}")
}

/// Returns 0 (success) if the given interface is wireless, non-zero otherwise.
/// Relies on the /sys/class/net/<iface>/wireless/ directory the kernel exposes
/// for wireless netdevs.
fn is_wireless_interface_cmd(interface: &str) -> String {
    format!("test -d /sys/class/net/{interface}/wireless")
}

/// Returns 0 if the given MAC address is already in use by an interface on the
/// host, non-zero otherwise. Uses `ip -o link show` piped through a case-insensitive
/// fixed-string grep for the MAC.
fn mac_in_use_check_cmd(mac: &str) -> String {
    format!("ip -o link show | grep -iF '{mac}'")
}

/// Validate an `ExpectedDhcpResponse`: the DNS list must not contain duplicates.
/// Empty or malformed IP fields are rejected at deserialization time by serde
/// (which parses them as `IpAddr`).
fn check_expected_response(response: &ExpectedDhcpResponse) -> Result<(), RegentError> {
    let mut seen = HashSet::new();
    for entry in &response.dns {
        if !seen.insert(*entry) {
            return Err(RegentError::IncoherentExpectedState(format!(
                "Duplicate DNS server in expected response: {entry}"
            )));
        }
    }
    Ok(())
}

/// Check that a string is a valid MAC address: exactly 6 hex octets separated by
/// colons (e.g. `aa:bb:cc:dd:ee:ff`). Hex digits are case-insensitive.
fn is_valid_mac_address(mac: &str) -> bool {
    let octets: Vec<&str> = mac.split(':').collect();
    octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && octet.chars().all(|c| c.is_ascii_hexdigit()))
}

fn parse_dhcp_response(raw_output: &str) -> Result<DhcpResponse, String> {
    let mut responding_servers = HashSet::new();
    for line in raw_output.lines() {
        if line.contains("DHCPOFFER") {
            if let Some(pos) = line.find("from ") {
                let ip_part = &line[pos + 5..];
                let ip_str: String = ip_part
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if let Ok(ip) = ip_str.parse() {
                    responding_servers.insert(ip);
                }
            } else {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if let Some(last) = tokens.last() {
                    let cleaned = last.trim_matches(|c| c == '(' || c == ')' || c == ';');
                    if let Ok(ip) = cleaned.parse() {
                        responding_servers.insert(ip);
                    }
                }
            }
        }
    }

    let mut eval_ip: Option<IpAddr> = None;
    let mut eval_mask: Option<IpAddr> = None;
    let mut eval_dns: Vec<IpAddr> = Vec::new();

    for line in raw_output.lines() {
        if line.contains("yiaddr") && eval_ip.is_none() {
            if let Some(pos) = line.find("yiaddr ") {
                let ip_part = &line[pos + 7..];
                let ip_str: String = ip_part
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                eval_ip = ip_str.parse().ok();
            }
        }
        if line.contains("bound to") && eval_ip.is_none() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                eval_ip = parts[2].parse().ok();
            }
        }
        if line.to_lowercase().contains("subnet-mask") && eval_mask.is_none() {
            if let Some(last) = line.split_whitespace().last() {
                eval_mask = last.trim_end_matches(';').parse().ok();
            }
        }
        if line.to_lowercase().contains("domain-name-servers") {
            if let Some(pos) = line.find("domain-name-servers") {
                let dns_part = &line[pos..];
                if let Some(space_pos) = dns_part.find(' ') {
                    let raw = dns_part[space_pos + 1..].trim_end_matches(';');
                    eval_dns.extend(
                        raw.split_whitespace()
                            .filter_map(|s| s.parse::<IpAddr>().ok()),
                    );
                }
            }
        }
    }

    Ok(DhcpResponse {
        ip: eval_ip,
        mask: eval_mask,
        dns: eval_dns,
        responding_servers,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExpectedDhcpResponse {
    ip: IpAddr,
    mask: IpAddr,
    dns: Vec<IpAddr>,
}

impl ExpectedDhcpResponse {
    pub fn new(ip: IpAddr, mask: IpAddr, dns: Vec<IpAddr>) -> ExpectedDhcpResponse {
        ExpectedDhcpResponse { ip, mask, dns }
    }
}

enum ComparisonOutcome {
    Matches,
    Different(String),
}
