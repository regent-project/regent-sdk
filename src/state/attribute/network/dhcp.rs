//! DHCP lease probing attribute
//!
//! This module provides theDhcpExpectedState type for verifying that a host's
//! network interface can obtain a DHCP lease as expected. It is an
//! assessment-only attribute: it reports compliance but never produces
//! remediations, because a wrong DHCP configuration cannot be fixed automatically
//! by the SDK.
//!
//! # How the probe avoids altering the host
//!
//! The assessment never runsdhclient on the target interface itself. Instead it:
//!
//! 1. creates a short-lived macvlan virtual interface on top of the parent one,
//! 2. runs a one-shotdhclient probe on that virtual interface with
//!   -sf /bin/true`, which suppressesdhclient-script entirely. This is what
//!    makes the probe read-only: the default script assigns the offered address,
//!    installs the routes carried by therouters option (including a default
//!    route) and rewrites/etc/resolv.conf — and that last change would outlive
//!    the probe,
//! 3. reads the offered configuration back from its own isolated lease file, so the
//!    host's real DHCP lease state is never read or written,
//! 4. releases the lease (`dhclient -r`) so the address returns to the server's pool
//!    and nodhclient daemon is left behind (`-1 without-d daemonizes once a
//!    lease is acquired), then deletes the virtual interface and the temporary
//!    directory.
//!
//! Lease and pid files live inside amktemp -d directory, created root-owned with
//!0700 permissions, so a local unprivileged user cannot redirect these
//! root-owned writes through a symlink.
//!
//! The attribute relies on thedhclient`,ip`,timeout andmktemp commands
//! being available on the target host, and requiressudo`/`sudo-rs privileges.
//!
//! **Compatible OS:** Linux (wired ethernet interfaces only).
//!
//! **Incompatible interfaces:** wireless interfaces are refused cleanly. A macvlan
//! cannot get an independent DHCP identity over a managed-mode Wi-Fi link (the AP
//! only delivers to the single associated MAC).
//!
//! # Variants
//!
//! -CheckResponseAndServer`: lease must match a given response and come from a given server
//! -CheckResponse`: lease must match a given response from any server
//! -CheckServer`: lease must come from a given server (any valid response)
//! -SimpleCheck`: any valid lease from any server
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
//! CheckResponseAndServer - assert an interface gets a given lease from a given server:
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
//! With an explicit MAC for the virtual interface (omit MacAddressto let the
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
//! CheckResponse- assert an interface gets a given lease from any server:
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
//! CheckServer- assert an interface gets a lease from a given server:
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
//! SimpleCheck- assert an interface gets a lease from any server:
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
//! generated. The associated `DhcpApiCallalways returns anInternalLogicError`
//! because DHCP configuration cannot be remediated automatically.

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::hosts::properties::OsKind;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::compliance::AttributeComplianceAssessment;
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

const PROBE_DIR_PREFIX: &str = "/tmp/regent-dhcp-";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DhcpCheckBehavior {
    #[serde(rename_all = "PascalCase")]
    CheckResponseAndServer {
        response: ExpectedDhcpResponse,
        server: IpAddr,
        rogue_server_allowed: bool,
    },
    #[serde(rename_all = "PascalCase")]
    CheckResponse { response: ExpectedDhcpResponse },
    #[serde(rename_all = "PascalCase")]
    CheckServer {
        server: IpAddr,
        rogue_server_allowed: bool,
    },
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
                "Host is {:?} but the DHCP attribute is only supported on Linux",
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
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if matches!(privilege, Privilege::None) {
            return Err(RegentError::WrongInitialization(
                "DHCP assessment needs sudo/sudo-rs privileges".to_string(),
            ));
        }

        if let Some(properties) = host_properties {
            self.check_host_compatibility(properties)?;
        }

        for required_command in ["dhclient", "ip", "timeout", "mktemp"] {
            let command_available = host_handler
                .is_this_command_available(required_command, privilege)
                .await
                .unwrap_or(false);

            if !command_available {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "command {required_command} not available on this host"
                )));
            }
        }

        let parent_interface = self.parent_interface.as_str();
        let mac_address = self.mac_address.as_deref();

        match host_handler
            .run_command(
                &is_wireless_interface_cmd(parent_interface),
                &Privilege::None,
            )
            .await
        {
            Ok(result) if result.return_code == 0 => {
                return Err(RegentError::IncompatibleHost(format!(
                    "{parent_interface} is a wireless interface (not supported)"
                )));
            }
            Ok(_) => { /* not wireless: proceed */ }
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Unable to determine if {parent_interface} is wireless: {:?}",
                    details
                )));
            }
        }

        // When the user provides a MAC address, make sure it is not already in use
        // by a real interface on the host.
        if let Some(mac) = mac_address {
            match host_handler
                .run_command(&mac_in_use_check_cmd(mac), privilege)
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

        // Isolate the probe's lease and pid files in a root-owned 0700 directory.
        // Created before anything else that needs cleaning up.
        let probe_dir = match host_handler
            .run_command(&create_probe_dir_cmd(), privilege)
            .await
        {
            Ok(result) if result.return_code == 0 => extract_probe_dir(&result.stdout)?,
            Ok(result) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Failed to create the temporary directory for the DHCP probe: {:?}",
                    result
                )));
            }
            Err(details) => {
                return Err(RegentError::FailedDryRunEvaluation(format!(
                    "Unable to create the temporary directory for the DHCP probe: {:?}",
                    details
                )));
            }
        };

        let virtual_interface = virtual_interface_name();
        let lease_file = format!("{probe_dir}/probe.leases");
        let pid_file = format!("{probe_dir}/probe.pid");
        let probe_timeout_secs = self.default_timeout().as_secs();

        let probe_outcome = probe_dhcp_lease(
            host_handler,
            privilege,
            parent_interface,
            mac_address,
            &virtual_interface,
            &lease_file,
            &pid_file,
            probe_timeout_secs,
        )
        .await;

        // Cleanup runs whatever the probe did, and is safe to run unconditionally:
        // the virtual interface name is random, so nothing but this probe can own it.
        cleanup_probe(
            host_handler,
            privilege,
            &virtual_interface,
            &probe_dir,
            &lease_file,
            &pid_file,
        )
        .await;

        let dhcp_response = probe_outcome?;

        match &self.check {
            DhcpCheckBehavior::CheckResponseAndServer {
                response,
                server,
                rogue_server_allowed,
            } => {
                if let Some(why) =
                    assess_responding_servers(&dhcp_response, server, *rogue_server_allowed)
                {
                    return Ok(AttributeComplianceAssessment::NonCompliantFatal(why));
                }

                match dhcp_response.matches_expected_response(response) {
                    ComparisonOutcome::Matches => Ok(AttributeComplianceAssessment::Compliant),
                    ComparisonOutcome::Different(why) => {
                        Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "Unexpected response. {}",
                            why
                        )))
                    }
                }
            }
            DhcpCheckBehavior::CheckResponse { response } => {
                match dhcp_response.matches_expected_response(response) {
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
            } => match assess_responding_servers(&dhcp_response, server, *rogue_server_allowed) {
                Some(why) => Ok(AttributeComplianceAssessment::NonCompliantFatal(why)),
                None => Ok(AttributeComplianceAssessment::Compliant),
            },
            DhcpCheckBehavior::SimpleCheck => {
                // Nothing special here, we are just interested in getting a lease,
                // andprobe_dhcp_leaseonly returns once it parsed an address.
                Ok(AttributeComplianceAssessment::Compliant)
            }
        }
    }
}

/// This is a placeholder type: DHCP misconfiguration cannot be remediated
/// automatically. Each part returns an InternalLogicError to signal a bug.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhcpApiCall {}

impl DhcpApiCall {
    pub fn display(&self) -> String {
        return format!("Should not have been called");
    }
}

impl Check for DhcpApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Err(RegentError::InternalLogicError(
            "(check) DhcpApiCall should not have been called as we cannot remediate automatically a wrong DHCP configuration".to_string()
        ))
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        Err(RegentError::InternalLogicError(
            "(check_host_compatibility) DhcpApiCall should not have been called as we cannot remediate automatically a wrong DHCP configuration".to_string()
        ))
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for DhcpApiCall {
    async fn call(
        &self,
        _host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        Err(RegentError::InternalLogicError(
            "(call) DhcpApiCall should not have been called as we cannot remediate automatically a wrong DHCP configuration".to_string()
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn probe_dhcp_lease<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
    parent_interface: &str,
    mac_address: Option<&str>,
    virtual_interface: &str,
    lease_file: &str,
    pid_file: &str,
    timeout_secs: u64,
) -> Result<DhcpResponse, RegentError> {
    match host_handler
        .run_command(
            &create_virtual_interface_cmd(parent_interface, virtual_interface, mac_address),
            privilege,
        )
        .await
    {
        Ok(result) if result.return_code == 0 => {}
        Ok(result) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Failed to create virtual interface {virtual_interface} on {parent_interface} for DHCP probing: {:?}",
                result
            )));
        }
        Err(details) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Unable to create virtual interface {virtual_interface} on {parent_interface} for DHCP probing: {:?}",
                details
            )));
        }
    }

    match host_handler
        .run_command(&bring_up_interface_cmd(virtual_interface), privilege)
        .await
    {
        Ok(result) if result.return_code == 0 => {}
        Ok(result) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Failed to bring up virtual interface {virtual_interface} for DHCP probing: {:?}",
                result
            )));
        }
        Err(details) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Unable to bring up virtual interface {virtual_interface} for DHCP probing: {:?}",
                details
            )));
        }
    }

    let probe_result = match host_handler
        .run_command(
            &dhcp_probe_cmd(virtual_interface, timeout_secs, lease_file, pid_file),
            privilege,
        )
        .await
    {
        Ok(result) => result,
        Err(details) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "Unable to run dhclient command: {:?}",
                details
            )));
        }
    };

    // TIMEOUT_EXIT_STATUS = 124
    if probe_result.return_code == 124 {
        return Err(RegentError::TimeOutReached(format!(
            "dhclient on {virtual_interface} did not finish within {timeout_secs}s"
        )));
    }

    if probe_result.return_code != 0 {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Failed dhclient command: {:?}",
            probe_result
        )));
    }

    // Which servers answered
    let raw_stdout_and_stderr = probe_result.stdout + &probe_result.stderr;
    let responding_servers = parse_responding_servers(&raw_stdout_and_stderr);

    // What was offered, on the other hand, comes from the lease file: with
    //-sf /bin/trueno script runs, so the options never show up in the output.
    let raw_lease = match host_handler
        .run_command(&read_lease_file_cmd(lease_file), privilege)
        .await
    {
        Ok(result) if result.return_code == 0 => result.stdout,
        Ok(result) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "dhclient acquired a lease on {virtual_interface} but its lease file could not be read: {:?}",
                result
            )));
        }
        Err(details) => {
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "dhclient acquired a lease on {virtual_interface} but its lease file could not be read: {:?}",
                details
            )));
        }
    };

    let lease = parse_lease_file(&raw_lease);

    if lease.ip.is_none() {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "dhclient acquired a lease on {virtual_interface} but no address could be parsed \
             out of its lease file"
        )));
    }

    Ok(DhcpResponse {
        ip: lease.ip,
        mask: lease.mask,
        dns: lease.dns,
        responding_servers,
    })
}

/// Every step is allowed to fail: the probe may have stopped early, and this runs on
/// the error path too.
async fn cleanup_probe<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
    virtual_interface: &str,
    probe_dir: &str,
    lease_file: &str,
    pid_file: &str,
) {
    // Release before deleting the interface: the address goes back to the server's
    // pool, and the dhclient that-1 left daemonized is stopped.
    let _ = host_handler
        .run_command(
            &release_lease_cmd(virtual_interface, lease_file, pid_file),
            privilege,
        )
        .await;

    // Belt and braces: if the release could not run, still stop whatever client is
    // holding the pid file.
    let _ = host_handler
        .run_command(&stop_dhclient_cmd(pid_file), privilege)
        .await;

    let _ = host_handler
        .run_command(&delete_interface_cmd(virtual_interface), privilege)
        .await;

    let _ = host_handler
        .run_command(&remove_probe_dir_cmd(probe_dir), privilege)
        .await;
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

fn assess_responding_servers(
    dhcp_response: &DhcpResponse,
    expected_server: &IpAddr,
    rogue_server_allowed: bool,
) -> Option<String> {
    if dhcp_response.responding_servers.is_empty() {
        return Some("No responding server at all".to_string());
    }

    if !dhcp_response.responding_servers.contains(expected_server) {
        return Some(format!(
            "Expected server {expected_server} not among responding servers ({:?})",
            dhcp_response.responding_servers
        ));
    }

    if !rogue_server_allowed && dhcp_response.responding_servers.len() > 1 {
        return Some(format!(
            "Expected server {expected_server} answered but there are also rogue DHCP servers ({:?})",
            dhcp_response.responding_servers
        ));
    }

    None
}

fn dhcp_probe_cmd(interface: &str, timeout_secs: u64, lease_file: &str, pid_file: &str) -> String {
    // -1: one-shot, exit 0 after acquiring a lease (or exit 2 after one failed
    // attempt). The -d (foreground) flag is intentionally NOT used: in one-shot
    // mode it makes dhclient stay in the foreground managing the lease instead
    // of exiting, which would cause every successful probe to run until the
    // timeout wrapper kills it. Without -d, dhclient returns promptly on
    // success; on no answer it retransmits until timeout cuts it (rc 124).
    // -sf /bin/true is what keeps the probe read-only.
    format!(
        "timeout {timeout_secs} dhclient -1 -v -sf /bin/true -cf /dev/null -lf {} -pf {} {}",
        shell_quote(lease_file),
        shell_quote(pid_file),
        shell_quote(interface)
    )
}

fn release_lease_cmd(interface: &str, lease_file: &str, pid_file: &str) -> String {
    format!(
        "timeout 5 dhclient -r -sf /bin/true -cf /dev/null -lf {} -pf {} {}",
        shell_quote(lease_file),
        shell_quote(pid_file),
        shell_quote(interface)
    )
}

fn stop_dhclient_cmd(pid_file: &str) -> String {
    format!("timeout 5 dhclient -x -pf {}", shell_quote(pid_file))
}

fn read_lease_file_cmd(lease_file: &str) -> String {
    format!("cat {}", shell_quote(lease_file))
}

fn create_probe_dir_cmd() -> String {
    format!("mktemp -d {PROBE_DIR_PREFIX}XXXXXX")
}

fn remove_probe_dir_cmd(probe_dir: &str) -> String {
    format!("rm -rf {}", shell_quote(probe_dir))
}

/// The ssh2 handler folds stderr into stdout, so the output may carry unrelated
/// lines: keep the last line that looks like the path that was asked for.
fn extract_probe_dir(raw_output: &str) -> Result<String, RegentError> {
    raw_output
        .lines()
        .map(str::trim)
        .rfind(|line| line.starts_with(PROBE_DIR_PREFIX) && !line.contains(char::is_whitespace))
        .map(str::to_string)
        .ok_or_else(|| {
            RegentError::FailedDryRunEvaluation(format!(
                "Could not find the temporary directory for the DHCP probe in mktemp output: {:?}",
                raw_output
            ))
        })
}

/// Linux caps interface names at 15 characters (IFNAMSIZ); this one is 9.
fn virtual_interface_name() -> String {
    format!(
        "rgt{}",
        nanoid!(
            6,
            &[
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
            ]
        )
    )
}

fn create_virtual_interface_cmd(
    parent: &str,
    virtual_interface: &str,
    mac_address: Option<&str>,
) -> String {
    match mac_address {
        Some(mac) => format!(
            "ip link add link {} name {} address {} type macvlan mode bridge",
            shell_quote(parent),
            shell_quote(virtual_interface),
            shell_quote(mac)
        ),
        None => format!(
            "ip link add link {} name {} type macvlan mode bridge",
            shell_quote(parent),
            shell_quote(virtual_interface)
        ),
    }
}

fn bring_up_interface_cmd(interface: &str) -> String {
    format!("ip link set {} up", shell_quote(interface))
}

fn delete_interface_cmd(interface: &str) -> String {
    format!("ip link delete {}", shell_quote(interface))
}

fn is_wireless_interface_cmd(interface: &str) -> String {
    format!(
        "test -d {}",
        shell_quote(&format!("/sys/class/net/{interface}/wireless"))
    )
}

fn mac_in_use_check_cmd(mac: &str) -> String {
    format!("ip -o link show | grep -iF {}", shell_quote(mac))
}

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

fn is_valid_mac_address(mac: &str) -> bool {
    let octets: Vec<&str> = mac.split(':').collect();
    octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && octet.chars().all(|c| c.is_ascii_hexdigit()))
}

fn parse_responding_servers(raw_output: &str) -> HashSet<IpAddr> {
    let mut responding_servers = HashSet::new();

    for line in raw_output.lines() {
        if !line.contains("DHCPOFFER") && !line.contains("DHCPACK") {
            continue;
        }

        if let Some(pos) = line.find("from ") {
            let ip_part = &line[pos + "from ".len()..];
            let ip_str: String = ip_part
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(ip) = ip_str.parse() {
                responding_servers.insert(ip);
                continue;
            }
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let Some(last) = tokens.last() {
            let cleaned = last.trim_matches(|c| c == '(' || c == ')' || c == ';');
            if let Ok(ip) = cleaned.parse() {
                responding_servers.insert(ip);
            }
        }
    }

    responding_servers
}

#[derive(Debug, Default, PartialEq)]
struct DhcpLease {
    ip: Option<IpAddr>,
    mask: Option<IpAddr>,
    dns: Vec<IpAddr>,
}

/// The relevant statements look like this, inside a lease { ... } block:
///
/// ```text
/// lease {
///   interface "rgt0a1b2c";
///   fixed-address 10.0.0.5;
///   option subnet-mask 255.255.255.0;
///   option domain-name-servers 8.8.8.8,8.8.4.4;
/// }
/// ```
///
/// A lease file can hold several blocks appended over the course of an exchange, so
/// the last value seen for each statement wins: that is the most recent lease.
fn parse_lease_file(raw_lease: &str) -> DhcpLease {
    let mut lease = DhcpLease::default();

    for line in raw_lease.lines() {
        let statement = line.trim().trim_end_matches(';').trim();
        // Bothfixed-address 1.2.3.4; andoption subnet-mask 1.2.3.0; shapes.
        let statement = statement.strip_prefix("option ").unwrap_or(statement);

        if let Some(value) = statement.strip_prefix("fixed-address ") {
            if let Ok(ip) = value.trim().parse() {
                lease.ip = Some(ip);
            }
        } else if let Some(value) = statement.strip_prefix("subnet-mask ") {
            if let Ok(mask) = value.trim().parse() {
                lease.mask = Some(mask);
            }
        } else if let Some(value) = statement.strip_prefix("domain-name-servers ") {
            // Lease files separate these with commas, unlike most other options.
            let servers: Vec<IpAddr> = value
                .split(',')
                .filter_map(|entry| entry.trim().parse().ok())
                .collect();
            if !servers.is_empty() {
                lease.dns = servers;
            }
        }
    }

    lease
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
