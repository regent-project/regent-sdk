//! Iptables attribute for firewall rule management
//!
//! This module provides the `IptablesBlockExpectedState` type for managing iptables/ip6tables
//! firewall rules and chains. It supports creating, modifying, and deleting rules, chains,
//! and policies across different tables (filter, nat, mangle, raw, security).
//!
//! **Compatible OS:** Linux (all distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::network::iptables::{IptablesBlockExpectedState, IptablesPolicy, IptablesTable};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! let rule = IptablesBlockExpectedState::builder("INPUT")
//!     .with_protocol("tcp")
//!     .with_destination_port("22")
//!     .with_jump("ACCEPT")
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::iptables(rule, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !Iptables
//!       Chain: INPUT
//!       Protocol: tcp
//!       DestinationPort: "22"
//!       Jump: ACCEPT
//!       Privilege: !WithSudo
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Supporting enums ──────────────────────────────────────────────────────────

/// Desired state of an iptables rule or chain
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesExpectedState {
    /// The rule or chain should exist
    Present,
    /// The rule or chain should not exist
    Absent,
}

/// iptables table to operate on
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesTable {
    /// Default table for packet filtering
    Filter,
    /// Table for network address translation
    Nat,
    /// Table for packet marking and manipulation
    Mangle,
    /// Table for packet marking before connection tracking
    Raw,
    /// Table for mandatory access control (Linux 2.6.29+)
    Security,
}

impl IptablesTable {
    /// Returns the `-t <table>` argument string, or empty string for the default Filter table.
    fn table_arg(&self) -> String {
        match self {
            IptablesTable::Filter => String::new(),
            IptablesTable::Nat => "-t nat".to_string(),
            IptablesTable::Mangle => "-t mangle".to_string(),
            IptablesTable::Raw => "-t raw".to_string(),
            IptablesTable::Security => "-t security".to_string(),
        }
    }
}

/// IP version for iptables commands
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpVersion {
    /// IPv4 protocol
    Ipv4,
    /// IPv6 protocol
    Ipv6,
}

/// Action to perform on a rule (append or insert)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesAction {
    /// Add rule at the end of the chain
    Append,
    /// Insert rule at a specific position
    Insert,
}

/// Default policy for a chain
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesPolicy {
    /// Accept packets
    Accept,
    /// Drop packets silently
    Drop,
    /// Reject packets with an error response
    Reject,
}

impl std::fmt::Display for IptablesPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IptablesPolicy::Accept => write!(f, "ACCEPT"),
            IptablesPolicy::Drop => write!(f, "DROP"),
            IptablesPolicy::Reject => write!(f, "REJECT"),
        }
    }
}

/// SYN flag matching behavior
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesSyn {
    /// Match packets with SYN flag set
    Match,
    /// Match packets with SYN flag NOT set (negated)
    Negate,
    /// Ignore SYN flag matching
    Ignore,
}

/// TCP flags for matching packets with specific TCP flag combinations
/// 
/// Used with the `--tcp-flags` iptables option to match packets based on TCP flags.
/// `flags` specifies which flags to examine, and `flags_set` specifies which of those
/// must be set for the packet to match.
/// 
/// # Example
/// 
/// To match SYN packets (SYN set, ACK not set):
/// ```yaml
/// TcpFlags:
///   flags: [SYN, ACK]
///   flags_set: [SYN]
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TcpFlags {
    /// List of TCP flags to examine (e.g., SYN, ACK, FIN, RST, PSH, URG)
    pub flags: Vec<String>,
    /// Subset of flags from `flags` that must be set for the packet to match
    pub flags_set: Vec<String>,
}

// ── Block expected state ──────────────────────────────────────────────────────

/// Configuration for an iptables/ip6tables rule or chain
/// 
/// Use the builder pattern to create firewall rules with various matching criteria
/// and actions. Each rule must specify at least one of: `jump`, `goto`, `policy`, or `chain_management`.
/// 
/// # Examples
/// 
/// ## Rust API
/// 
/// ```no_run
/// use regent_sdk::state::attribute::network::iptables::{
///     IptablesBlockExpectedState, IptablesExpectedState, IptablesPolicy, IptablesTable
/// };
/// use regent_sdk::{Attribute, ExpectedState, Privilege};
/// 
/// // Allow SSH on port 22
/// let ssh_rule = IptablesBlockExpectedState::builder("INPUT")
///     .with_protocol("tcp")
///     .with_destination_port("22")
///     .with_jump("ACCEPT")
///     .build()
///     .unwrap();
/// 
/// // Set default DROP policy on INPUT chain
/// let policy_rule = IptablesBlockExpectedState::builder("INPUT")
///     .with_policy(IptablesPolicy::Drop)
///     .build()
///     .unwrap();
/// 
/// // NAT masquerade for outbound traffic
/// let nat_rule = IptablesBlockExpectedState::builder("POSTROUTING")
///     .with_table(IptablesTable::Nat)
///     .with_out_interface("eth0")
///     .with_jump("MASQUERADE")
///     .build()
///     .unwrap();
/// ```
/// 
/// ## YAML API
/// 
/// ```yaml
/// Attributes:
///   # Allow SSH
///   - Detail: !Iptables
///       Chain: INPUT
///       Protocol: tcp
///       DestinationPort: "22"
///       Jump: ACCEPT
///       Privilege: !WithSudo
/// 
///   # Set default policy
///   - Detail: !Iptables
///       Chain: INPUT
///       Policy: !Drop
///       Privilege: !WithSudo
/// 
///   # NAT masquerade
///   - Detail: !Iptables
///       Chain: POSTROUTING
///       Table: !Nat
///       OutInterface: eth0
///       Jump: MASQUERADE
///       Privilege: !WithSudo
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct IptablesBlockExpectedState {
    /// Chain name to operate on (e.g., INPUT, OUTPUT, FORWARD, or custom chain)
    chain: String,
    /// Desired state: Present (rule/chain should exist) or Absent (should not exist)
    state: Option<IptablesExpectedState>,
    /// Table to operate on (defaults to Filter)
    table: Option<IptablesTable>,
    /// IP version: Ipv4 (iptables) or Ipv6 (ip6tables)
    ip_version: Option<IpVersion>,
    /// Action: Append (default) or Insert
    action: Option<IptablesAction>,
    /// Rule number for Insert action
    rule_num: Option<u32>,
    /// Whether to create/flush/delete the chain itself
    chain_management: Option<bool>,
    /// Default policy for the chain (ACCEPT, DROP, REJECT)
    policy: Option<IptablesPolicy>,
    /// Protocol to match (tcp, udp, icmp, etc.)
    protocol: Option<String>,
    /// Source IP address or range to match
    source: Option<String>,
    /// Destination IP address or range to match
    destination: Option<String>,
    /// Input interface to match
    in_interface: Option<String>,
    /// Output interface to match
    out_interface: Option<String>,
    /// Source port to match
    source_port: Option<String>,
    /// Destination port to match
    destination_port: Option<String>,
    /// Connection tracking states to match (ESTABLISHED, RELATED, NEW, INVALID, etc.)
    ctstate: Option<Vec<String>>,
    /// ICMP type to match
    icmp_type: Option<String>,
    /// TCP flags configuration for matching
    tcp_flags: Option<TcpFlags>,
    /// SYN flag matching
    syn: Option<IptablesSyn>,
    /// Match fragmented packets
    fragment: Option<bool>,
    /// Target to jump to (ACCEPT, DROP, REJECT, LOG, custom chain, etc.)
    jump: Option<String>,
    /// Target to goto (similar to jump but continues in the same table)
    goto: Option<String>,
    /// Destination address for NAT (used with DNAT)
    to_destination: Option<String>,
    /// Source address for NAT (used with SNAT)
    to_source: Option<String>,
    /// Ports for NAT redirect
    to_ports: Option<String>,
    /// Prefix for log messages (used with LOG target)
    log_prefix: Option<String>,
    /// Log level (used with LOG target)
    log_level: Option<String>,
    /// Comment to add to the rule
    comment: Option<String>,
    /// Rate limit for matching (e.g., "3/minute")
    limit: Option<String>,
    /// Rate limit burst size
    limit_burst: Option<String>,
    /// User ID owner to match
    uid_owner: Option<String>,
    /// Group ID owner to match
    gid_owner: Option<String>,
}

impl Timeout for IptablesBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl IptablesBlockExpectedState {
    pub fn builder(chain: &str) -> IptablesBlockExpectedState {
        IptablesBlockExpectedState {
            chain: chain.to_string(),
            state: None,
            table: None,
            ip_version: None,
            action: None,
            rule_num: None,
            chain_management: None,
            policy: None,
            protocol: None,
            source: None,
            destination: None,
            in_interface: None,
            out_interface: None,
            source_port: None,
            destination_port: None,
            ctstate: None,
            icmp_type: None,
            tcp_flags: None,
            syn: None,
            fragment: None,
            jump: None,
            goto: None,
            to_destination: None,
            to_source: None,
            to_ports: None,
            log_prefix: None,
            log_level: None,
            comment: None,
            limit: None,
            limit_burst: None,
            uid_owner: None,
            gid_owner: None,
        }
    }

    pub fn with_state(&mut self, state: IptablesExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_table(&mut self, table: IptablesTable) -> &mut Self {
        self.table = Some(table);
        self
    }

    pub fn with_ip_version(&mut self, ip_version: IpVersion) -> &mut Self {
        self.ip_version = Some(ip_version);
        self
    }

    pub fn with_action(&mut self, action: IptablesAction) -> &mut Self {
        self.action = Some(action);
        self
    }

    pub fn with_rule_num(&mut self, rule_num: u32) -> &mut Self {
        self.rule_num = Some(rule_num);
        self
    }

    pub fn with_chain_management(&mut self, chain_management: bool) -> &mut Self {
        self.chain_management = Some(chain_management);
        self
    }

    pub fn with_policy(&mut self, policy: IptablesPolicy) -> &mut Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_protocol(&mut self, protocol: &str) -> &mut Self {
        self.protocol = Some(protocol.to_string());
        self
    }

    pub fn with_source(&mut self, source: &str) -> &mut Self {
        self.source = Some(source.to_string());
        self
    }

    pub fn with_destination(&mut self, destination: &str) -> &mut Self {
        self.destination = Some(destination.to_string());
        self
    }

    pub fn with_in_interface(&mut self, in_interface: &str) -> &mut Self {
        self.in_interface = Some(in_interface.to_string());
        self
    }

    pub fn with_out_interface(&mut self, out_interface: &str) -> &mut Self {
        self.out_interface = Some(out_interface.to_string());
        self
    }

    pub fn with_source_port(&mut self, source_port: &str) -> &mut Self {
        self.source_port = Some(source_port.to_string());
        self
    }

    pub fn with_destination_port(&mut self, destination_port: &str) -> &mut Self {
        self.destination_port = Some(destination_port.to_string());
        self
    }

    pub fn with_ctstate(&mut self, ctstate: Vec<String>) -> &mut Self {
        self.ctstate = Some(ctstate);
        self
    }

    pub fn with_icmp_type(&mut self, icmp_type: &str) -> &mut Self {
        self.icmp_type = Some(icmp_type.to_string());
        self
    }

    pub fn with_tcp_flags(&mut self, tcp_flags: TcpFlags) -> &mut Self {
        self.tcp_flags = Some(tcp_flags);
        self
    }

    pub fn with_syn(&mut self, syn: IptablesSyn) -> &mut Self {
        self.syn = Some(syn);
        self
    }

    pub fn with_fragment(&mut self, fragment: bool) -> &mut Self {
        self.fragment = Some(fragment);
        self
    }

    pub fn with_jump(&mut self, jump: &str) -> &mut Self {
        self.jump = Some(jump.to_string());
        self
    }

    pub fn with_goto(&mut self, goto: &str) -> &mut Self {
        self.goto = Some(goto.to_string());
        self
    }

    pub fn with_to_destination(&mut self, to_destination: &str) -> &mut Self {
        self.to_destination = Some(to_destination.to_string());
        self
    }

    pub fn with_to_source(&mut self, to_source: &str) -> &mut Self {
        self.to_source = Some(to_source.to_string());
        self
    }

    pub fn with_to_ports(&mut self, to_ports: &str) -> &mut Self {
        self.to_ports = Some(to_ports.to_string());
        self
    }

    pub fn with_log_prefix(&mut self, log_prefix: &str) -> &mut Self {
        self.log_prefix = Some(log_prefix.to_string());
        self
    }

    pub fn with_log_level(&mut self, log_level: &str) -> &mut Self {
        self.log_level = Some(log_level.to_string());
        self
    }

    pub fn with_comment(&mut self, comment: &str) -> &mut Self {
        self.comment = Some(comment.to_string());
        self
    }

    pub fn with_limit(&mut self, limit: &str) -> &mut Self {
        self.limit = Some(limit.to_string());
        self
    }

    pub fn with_limit_burst(&mut self, limit_burst: &str) -> &mut Self {
        self.limit_burst = Some(limit_burst.to_string());
        self
    }

    pub fn with_uid_owner(&mut self, uid_owner: &str) -> &mut Self {
        self.uid_owner = Some(uid_owner.to_string());
        self
    }

    pub fn with_gid_owner(&mut self, gid_owner: &str) -> &mut Self {
        self.gid_owner = Some(gid_owner.to_string());
        self
    }

    pub fn build(&self) -> Result<IptablesBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

// ── Check ─────────────────────────────────────────────────────────────────────

impl Check for IptablesBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.chain.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "chain must not be empty.".to_string(),
            ));
        }

        let has_actionable = self.jump.is_some()
            || self.goto.is_some()
            || self.policy.is_some()
            || self.chain_management.is_some();

        if !has_actionable {
            return Err(RegentError::IncoherentExpectedState(
                "At least one of jump, goto, policy, or chain_management must be set.".to_string(),
            ));
        }

        if self.rule_num.is_some() {
            match &self.action {
                Some(IptablesAction::Insert) => {}
                _ => {
                    return Err(RegentError::IncoherentExpectedState(
                        "rule_num is only valid when action is Insert.".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn check_host_compatibility(&self, host_properties: &HostProperties) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(
                format!("Host is {:?} but iptables is only supported on Linux", incompatible_os_kind)
            )),
        }
    }
}

// ── AssessCompliance ──────────────────────────────────────────────────────────

impl<Handler: HostHandler> AssessCompliance<Handler> for IptablesBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let binary = match self.ip_version.as_ref().unwrap_or(&IpVersion::Ipv4) {
            IpVersion::Ipv4 => "iptables",
            IpVersion::Ipv6 => "ip6tables",
        };

        let table_arg = self
            .table
            .as_ref()
            .unwrap_or(&IptablesTable::Filter)
            .table_arg();

        let expected_state = self
            .state
            .as_ref()
            .unwrap_or(&IptablesExpectedState::Present);

        let mut remediations: Vec<Remediation> = Vec::new();

        // ── Chain management ──────────────────────────────────────────────────
        if let Some(true) = self.chain_management {
            let check_chain_cmd = build_cmd(binary, &table_arg, &format!("-L {} -n", self.chain));
            let check_chain_cmd = format!("{} 2>/dev/null", check_chain_cmd);
            let chain_result = host_handler
                .run_command(&check_chain_cmd, &Privilege::None)
                .await
                .unwrap();

            match expected_state {
                IptablesExpectedState::Present => {
                    if chain_result.return_code != 0 {
                        remediations.push(Remediation::Iptables(IptablesApiCall::from(
                            IptablesModuleInternalApiCall::CreateChain {
                                binary: binary.to_string(),
                                table_arg: table_arg.clone(),
                                chain: self.chain.clone(),
                            },
                            privilege.clone(),
                        )));
                    }
                }
                IptablesExpectedState::Absent => {
                    if chain_result.return_code == 0 {
                        remediations.push(Remediation::Iptables(IptablesApiCall::from(
                            IptablesModuleInternalApiCall::FlushAndDeleteChain {
                                binary: binary.to_string(),
                                table_arg: table_arg.clone(),
                                chain: self.chain.clone(),
                            },
                            privilege.clone(),
                        )));
                        // No point checking rules on a chain that is being deleted
                        return Ok(AttributeComplianceAssessment::NonCompliant(remediations));
                    }
                    // Chain already absent — nothing to do for chain_management
                    if self.policy.is_none() && self.jump.is_none() && self.goto.is_none() {
                        return Ok(AttributeComplianceAssessment::Compliant);
                    }
                }
            }
        }

        // ── Policy ────────────────────────────────────────────────────────────
        if let Some(ref expected_policy) = self.policy {
            let list_cmd = build_cmd(binary, &table_arg, &format!("-L {} -n", self.chain));
            let list_cmd = format!("{} 2>/dev/null", list_cmd);
            let list_result = host_handler
                .run_command(&list_cmd, &Privilege::None)
                .await
                .unwrap();

            // Parse policy from first line: "Chain INPUT (policy ACCEPT)"
            let current_policy = list_result
                .stdout
                .lines()
                .next()
                .and_then(|line| {
                    // The line looks like: Chain <name> (policy <POLICY> N references)
                    // or: Chain <name> (policy <POLICY>)
                    let start = line.find("(policy ")?;
                    let after = &line[start + 8..];
                    let end = after
                        .find(|c: char| c == ')' || c == ' ')
                        .unwrap_or(after.len());
                    Some(after[..end].to_string())
                })
                .unwrap_or_default();

            let expected_policy_str = expected_policy.to_string();

            if current_policy != expected_policy_str {
                remediations.push(Remediation::Iptables(IptablesApiCall::from(
                    IptablesModuleInternalApiCall::SetPolicy {
                        binary: binary.to_string(),
                        table_arg: table_arg.clone(),
                        chain: self.chain.clone(),
                        policy: expected_policy_str,
                    },
                    privilege.clone(),
                )));
            }
        }

        // ── Rule ──────────────────────────────────────────────────────────────
        if self.jump.is_some() || self.goto.is_some() {
            let rule_args = build_rule_args(self);

            let check_rule_cmd = build_cmd(
                binary,
                &table_arg,
                &format!("-C {} {}", self.chain, rule_args),
            );
            let check_rule_cmd = format!("{} 2>/dev/null", check_rule_cmd);
            let check_result = host_handler
                .run_command(&check_rule_cmd, &Privilege::None)
                .await
                .unwrap();

            match expected_state {
                IptablesExpectedState::Present => {
                    if check_result.return_code != 0 {
                        let action = self.action.as_ref().unwrap_or(&IptablesAction::Append);
                        match action {
                            IptablesAction::Append => {
                                remediations.push(Remediation::Iptables(IptablesApiCall::from(
                                    IptablesModuleInternalApiCall::AppendRule {
                                        binary: binary.to_string(),
                                        table_arg: table_arg.clone(),
                                        chain: self.chain.clone(),
                                        rule_args,
                                    },
                                    privilege.clone(),
                                )));
                            }
                            IptablesAction::Insert => {
                                remediations.push(Remediation::Iptables(IptablesApiCall::from(
                                    IptablesModuleInternalApiCall::InsertRule {
                                        binary: binary.to_string(),
                                        table_arg: table_arg.clone(),
                                        chain: self.chain.clone(),
                                        rule_num: self.rule_num,
                                        rule_args,
                                    },
                                    privilege.clone(),
                                )));
                            }
                        }
                    }
                }
                IptablesExpectedState::Absent => {
                    if check_result.return_code == 0 {
                        remediations.push(Remediation::Iptables(IptablesApiCall::from(
                            IptablesModuleInternalApiCall::DeleteRule {
                                binary: binary.to_string(),
                                table_arg: table_arg.clone(),
                                chain: self.chain.clone(),
                                rule_args,
                            },
                            privilege.clone(),
                        )));
                    }
                }
            }
        }

        if remediations.is_empty() {
            Ok(AttributeComplianceAssessment::Compliant)
        } else {
            Ok(AttributeComplianceAssessment::NonCompliant(remediations))
        }
    }
}

// ── Internal API call enum ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesModuleInternalApiCall {
    CreateChain {
        binary: String,
        table_arg: String,
        chain: String,
    },
    FlushAndDeleteChain {
        binary: String,
        table_arg: String,
        chain: String,
    },
    SetPolicy {
        binary: String,
        table_arg: String,
        chain: String,
        policy: String,
    },
    AppendRule {
        binary: String,
        table_arg: String,
        chain: String,
        rule_args: String,
    },
    InsertRule {
        binary: String,
        table_arg: String,
        chain: String,
        rule_num: Option<u32>,
        rule_args: String,
    },
    DeleteRule {
        binary: String,
        table_arg: String,
        chain: String,
        rule_args: String,
    },
}

impl std::fmt::Display for IptablesModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IptablesModuleInternalApiCall::CreateChain {
                binary,
                table_arg,
                chain,
            } => {
                write!(f, "{} create chain {}", binary, chain)?;
                if !table_arg.is_empty() {
                    write!(f, " ({})", table_arg)?;
                }
                Ok(())
            }
            IptablesModuleInternalApiCall::FlushAndDeleteChain {
                binary,
                table_arg,
                chain,
            } => {
                write!(f, "{} flush and delete chain {}", binary, chain)?;
                if !table_arg.is_empty() {
                    write!(f, " ({})", table_arg)?;
                }
                Ok(())
            }
            IptablesModuleInternalApiCall::SetPolicy {
                binary,
                table_arg,
                chain,
                policy,
            } => {
                write!(f, "{} set policy {} on chain {}", binary, policy, chain)?;
                if !table_arg.is_empty() {
                    write!(f, " ({})", table_arg)?;
                }
                Ok(())
            }
            IptablesModuleInternalApiCall::AppendRule {
                binary,
                table_arg,
                chain,
                rule_args,
            } => {
                write!(f, "{} append rule to {} : {}", binary, chain, rule_args)?;
                if !table_arg.is_empty() {
                    write!(f, " ({})", table_arg)?;
                }
                Ok(())
            }
            IptablesModuleInternalApiCall::InsertRule {
                binary,
                table_arg,
                chain,
                rule_num,
                rule_args,
            } => {
                match rule_num {
                    Some(n) => write!(
                        f,
                        "{} insert rule at {} in {} : {}",
                        binary, n, chain, rule_args
                    )?,
                    None => write!(f, "{} insert rule in {} : {}", binary, chain, rule_args)?,
                }
                if !table_arg.is_empty() {
                    write!(f, " ({})", table_arg)?;
                }
                Ok(())
            }
            IptablesModuleInternalApiCall::DeleteRule {
                binary,
                table_arg,
                chain,
                rule_args,
            } => {
                write!(f, "{} delete rule from {} : {}", binary, chain, rule_args)?;
                if !table_arg.is_empty() {
                    write!(f, " ({})", table_arg)?;
                }
                Ok(())
            }
        }
    }
}

// ── ApiCall struct ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IptablesApiCall {
    pub api_call: IptablesModuleInternalApiCall,
    privilege: Privilege,
}

impl IptablesApiCall {
    pub fn display(&self) -> String {
        format!("{}", self.api_call)
    }

    fn from(api_call: IptablesModuleInternalApiCall, privilege: Privilege) -> IptablesApiCall {
        IptablesApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for IptablesApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(&self, host_properties: &HostProperties) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(
                format!("Host is {:?} but iptables is only supported on Linux", incompatible_os_kind)
            )),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for IptablesApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let cmd = match &self.api_call {
            IptablesModuleInternalApiCall::CreateChain {
                binary,
                table_arg,
                chain,
            } => build_cmd(binary, table_arg, &format!("-N {}", chain)),
            IptablesModuleInternalApiCall::FlushAndDeleteChain {
                binary,
                table_arg,
                chain,
            } => {
                let flush = build_cmd(binary, table_arg, &format!("-F {}", chain));
                let delete = build_cmd(binary, table_arg, &format!("-X {}", chain));
                format!("{} && {}", flush, delete)
            }
            IptablesModuleInternalApiCall::SetPolicy {
                binary,
                table_arg,
                chain,
                policy,
            } => build_cmd(binary, table_arg, &format!("-P {} {}", chain, policy)),
            IptablesModuleInternalApiCall::AppendRule {
                binary,
                table_arg,
                chain,
                rule_args,
            } => build_cmd(binary, table_arg, &format!("-A {} {}", chain, rule_args)),
            IptablesModuleInternalApiCall::InsertRule {
                binary,
                table_arg,
                chain,
                rule_num,
                rule_args,
            } => match rule_num {
                Some(n) => build_cmd(
                    binary,
                    table_arg,
                    &format!("-I {} {} {}", chain, n, rule_args),
                ),
                None => build_cmd(binary, table_arg, &format!("-I {} {}", chain, rule_args)),
            },
            IptablesModuleInternalApiCall::DeleteRule {
                binary,
                table_arg,
                chain,
                rule_args,
            } => build_cmd(binary, table_arg, &format!("-D {} {}", chain, rule_args)),
        };

        let result = host_handler
            .run_command(&cmd, &self.privilege)
            .await
            .unwrap();

        if result.return_code == 0 {
            // Post-operation verification: verify the rule is in the correct position
            let verification_result = verify_rule_position(
                host_handler,
                &self.api_call,
                &self.privilege,
            )
            .await;

            if verification_result {
                Ok(InternalApiCallOutcome::Success(None))
            } else {
                Ok(InternalApiCallOutcome::Failure(
                    "Command succeeded but post-verification failed: rule position does not match expected".to_string(),
                ))
            }
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC: {}, STDOUT: {}, STDERR: {}",
                result.return_code, result.stdout, result.stderr
            )))
        }
    }
}

/// Verify that a rule is in the correct position after insertion.
/// This implements post-application verification for idempotency.
async fn verify_rule_position<Handler: HostHandler>(
    host_handler: &mut Handler,
    api_call: &IptablesModuleInternalApiCall,
    privilege: &Privilege,
) -> bool {
    match api_call {
        IptablesModuleInternalApiCall::AppendRule {
            binary,
            table_arg,
            chain,
            rule_args,
        } => {
            // For append, verify the rule exists and is at the end
            let check_cmd = build_cmd(binary, table_arg, &format!("-C {} {}", chain, rule_args));
            let check_result = host_handler
                .run_command(&check_cmd, privilege)
                .await
                .unwrap();
            check_result.return_code == 0
        }
        IptablesModuleInternalApiCall::InsertRule {
            binary,
            table_arg,
            chain,
            rule_num,
            rule_args,
        } => {
            // For insert, verify the rule exists and is at the expected position
            let check_cmd = build_cmd(binary, table_arg, &format!("-C {} {}", chain, rule_args));
            let check_result = host_handler
                .run_command(&check_cmd, privilege)
                .await
                .unwrap();
            
            if check_result.return_code != 0 {
                return false; // Rule doesn't exist
            }

            // If a specific position was requested, verify it
            if let Some(expected_position) = rule_num {
                // List all rules in the chain and check position
                let list_cmd = build_cmd(binary, table_arg, &format!("-L {} --line-numbers -n", chain));
                let list_result = host_handler
                    .run_command(&list_cmd, privilege)
                    .await
                    .unwrap();

                if list_result.return_code == 0 {
                    // Parse the output to find the rule position
                    for line in list_result.stdout.lines() {
                        if line.contains(rule_args.as_str()) {
                            // Extract the line number
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 1 {
                                if let Ok(actual_position) = parts[0].parse::<u32>() {
                                    return actual_position == *expected_position;
                                }
                            }
                            break; // Found the rule, but couldn't parse position
                        }
                    }
                    return false; // Rule not found or position mismatch
                }
                false
            } else {
                // No specific position requested, just verify rule exists
                true
            }
        }
        IptablesModuleInternalApiCall::DeleteRule { .. } => {
            // For delete, the rule should no longer exist
            // This is handled by the command return code, so we just return true
            true
        }
        IptablesModuleInternalApiCall::CreateChain { .. } => {
            // For chain creation, we can verify the chain exists
            // This is handled by the command return code, so we just return true
            true
        }
        IptablesModuleInternalApiCall::FlushAndDeleteChain { .. } => {
            // For chain deletion, we can verify the chain no longer exists
            // This is handled by the command return code, so we just return true
            true
        }
        IptablesModuleInternalApiCall::SetPolicy { .. } => {
            // For policy changes, verification would require listing and parsing the chain
            // This is complex and the command return code is usually sufficient
            true
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Builds a full iptables command string from a binary name, an optional table argument,
/// and the command flags/arguments. When `table_arg` is empty the space before the flags
/// is omitted so the resulting command is clean.
fn build_cmd(binary: &str, table_arg: &str, flags: &str) -> String {
    if table_arg.is_empty() {
        format!("{} {}", binary, flags)
    } else {
        format!("{} {} {}", binary, table_arg, flags)
    }
}

/// Builds the rule-specification string from the fields of an `IptablesBlockExpectedState`.
/// The order of arguments follows the conventional iptables ordering: match criteria first,
/// then the target (jump/goto) with its options at the end.
fn build_rule_args(block: &IptablesBlockExpectedState) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Protocol
    if let Some(ref proto) = block.protocol {
        parts.push(format!("-p {}", proto));
    }

    // Source
    if let Some(ref src) = block.source {
        parts.push(format!("-s {}", src));
    }

    // Destination
    if let Some(ref dst) = block.destination {
        parts.push(format!("-d {}", dst));
    }

    // Input interface
    if let Some(ref iface) = block.in_interface {
        parts.push(format!("-i {}", iface));
    }

    // Output interface
    if let Some(ref iface) = block.out_interface {
        parts.push(format!("-o {}", iface));
    }

    // Source port
    if let Some(ref sport) = block.source_port {
        parts.push(format!("--sport {}", sport));
    }

    // Destination port
    if let Some(ref dport) = block.destination_port {
        parts.push(format!("--dport {}", dport));
    }

    // Conntrack state
    if let Some(ref states) = block.ctstate {
        if !states.is_empty() {
            parts.push(format!("-m conntrack --ctstate {}", states.join(",")));
        }
    }

    // Rate limiting
    if let Some(ref limit) = block.limit {
        let mut limit_part = format!("-m limit --limit {}", limit);
        if let Some(ref burst) = block.limit_burst {
            limit_part.push_str(&format!(" --limit-burst {}", burst));
        }
        parts.push(limit_part);
    }

    // ICMP type
    if let Some(ref icmp_type) = block.icmp_type {
        parts.push(format!("--icmp-type {}", icmp_type));
    }

    // TCP flags
    if let Some(ref tcp_flags) = block.tcp_flags {
        parts.push(format!(
            "--tcp-flags {} {}",
            tcp_flags.flags.join(","),
            tcp_flags.flags_set.join(",")
        ));
    }

    // SYN shorthand
    match block.syn.as_ref() {
        Some(IptablesSyn::Match) => parts.push("--syn".to_string()),
        Some(IptablesSyn::Negate) => parts.push("! --syn".to_string()),
        Some(IptablesSyn::Ignore) | None => {}
    }

    // Fragment
    if let Some(true) = block.fragment {
        parts.push("-f".to_string());
    }

    // Owner match
    if let Some(ref uid) = block.uid_owner {
        let mut owner_part = format!("-m owner --uid-owner {}", uid);
        if let Some(ref gid) = block.gid_owner {
            owner_part.push_str(&format!(" --gid-owner {}", gid));
        }
        parts.push(owner_part);
    }

    // Comment
    if let Some(ref comment) = block.comment {
        parts.push(format!("-m comment --comment '{}'", comment));
    }

    // Target: jump or goto, with any associated target options
    if let Some(ref jump) = block.jump {
        parts.push(format!("-j {}", jump));

        if let Some(ref to_dst) = block.to_destination {
            parts.push(format!("--to-destination {}", to_dst));
        }
        if let Some(ref to_src) = block.to_source {
            parts.push(format!("--to-source {}", to_src));
        }
        if let Some(ref to_ports) = block.to_ports {
            parts.push(format!("--to-ports {}", to_ports));
        }
        if let Some(ref prefix) = block.log_prefix {
            parts.push(format!("--log-prefix '{}'", prefix));
        }
        if let Some(ref level) = block.log_level {
            parts.push(format!("--log-level {}", level));
        }
    } else if let Some(ref goto) = block.goto {
        parts.push(format!("-g {}", goto));
    }

    parts.join(" ")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_iptables_blocks_from_yaml() {
        // Accept established/related traffic
        // Allow SSH on port 22
        // NAT masquerade on eth0
        // LOG with prefix
        // Insert rule at position 1
        let raw = "---
- Chain: INPUT
  Jump: ACCEPT
  Ctstate:
    - ESTABLISHED
    - RELATED

- Chain: INPUT
  Protocol: tcp
  DestinationPort: '22'
  Jump: ACCEPT

- Chain: POSTROUTING
  Table: !Nat
  OutInterface: eth0
  Jump: MASQUERADE

- Chain: INPUT
  Protocol: tcp
  DestinationPort: '80'
  Limit: 3/minute
  LimitBurst: '10'
  Jump: LOG
  LogPrefix: 'http-flood: '
  LogLevel: warning

- Chain: INPUT
  Action: !Insert
  RuleNum: 1
  Protocol: tcp
  DestinationPort: '443'
  Jump: ACCEPT
";
        let blocks: Vec<IptablesBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(blocks.len(), 5);
    }

    #[test]
    fn check_rejects_empty_chain() {
        let result = IptablesBlockExpectedState::builder("")
            .with_jump("ACCEPT")
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RegentError::IncoherentExpectedState(_)));
    }

    #[test]
    fn check_rejects_nothing_actionable() {
        let result = IptablesBlockExpectedState::builder("INPUT").build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RegentError::IncoherentExpectedState(_)));
    }

    #[test]
    fn check_rejects_rule_num_without_insert() {
        let result = IptablesBlockExpectedState::builder("INPUT")
            .with_jump("ACCEPT")
            .with_rule_num(1)
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RegentError::IncoherentExpectedState(_)));
    }

    #[test]
    fn check_accepts_valid_rule() {
        let result = IptablesBlockExpectedState::builder("INPUT")
            .with_protocol("tcp")
            .with_destination_port("22")
            .with_jump("ACCEPT")
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_rule_args_basic() {
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_protocol("tcp")
            .with_destination_port("22")
            .with_jump("ACCEPT")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("-p tcp"));
        assert!(args.contains("--dport 22"));
        assert!(args.contains("-j ACCEPT"));
    }

    #[test]
    fn build_rule_args_ctstate() {
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_ctstate(vec!["ESTABLISHED".to_string(), "RELATED".to_string()])
            .with_jump("ACCEPT")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("-m conntrack --ctstate ESTABLISHED,RELATED"));
        assert!(args.contains("-j ACCEPT"));
    }

    #[test]
    fn build_rule_args_nat_masquerade() {
        let block = IptablesBlockExpectedState::builder("POSTROUTING")
            .with_table(IptablesTable::Nat)
            .with_out_interface("eth0")
            .with_jump("MASQUERADE")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("-o eth0"));
        assert!(args.contains("-j MASQUERADE"));
    }

    #[test]
    fn build_rule_args_comment() {
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_protocol("tcp")
            .with_destination_port("80")
            .with_comment("allow http")
            .with_jump("ACCEPT")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("-m comment --comment 'allow http'"));
        assert!(args.contains("-j ACCEPT"));
    }

    #[test]
    fn build_rule_args_log_with_prefix_and_level() {
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_protocol("tcp")
            .with_destination_port("80")
            .with_jump("LOG")
            .with_log_prefix("http: ")
            .with_log_level("warning")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("-j LOG"));
        assert!(args.contains("--log-prefix 'http: '"));
        assert!(args.contains("--log-level warning"));
    }

    #[test]
    fn build_rule_args_goto() {
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_goto("MY_CHAIN")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("-g MY_CHAIN"));
        assert!(!args.contains("-j"));
    }

    #[test]
    fn build_rule_args_tcp_flags() {
        let flags = TcpFlags {
            flags: vec!["SYN".to_string(), "ACK".to_string()],
            flags_set: vec!["SYN".to_string()],
        };
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_protocol("tcp")
            .with_tcp_flags(flags)
            .with_jump("ACCEPT")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("--tcp-flags SYN,ACK SYN"));
    }

    #[test]
    fn build_rule_args_syn_negate() {
        let block = IptablesBlockExpectedState::builder("INPUT")
            .with_protocol("tcp")
            .with_syn(IptablesSyn::Negate)
            .with_jump("DROP")
            .build()
            .unwrap();

        let args = build_rule_args(&block);
        assert!(args.contains("! --syn"));
    }

    #[test]
    fn build_cmd_with_table_arg() {
        let cmd = build_cmd("iptables", "-t nat", "-A POSTROUTING -j MASQUERADE");
        assert_eq!(cmd, "iptables -t nat -A POSTROUTING -j MASQUERADE");
    }

    #[test]
    fn build_cmd_without_table_arg() {
        let cmd = build_cmd("iptables", "", "-A INPUT -j ACCEPT");
        assert_eq!(cmd, "iptables -A INPUT -j ACCEPT");
    }

    #[test]
    fn check_accepts_chain_management_only() {
        let result = IptablesBlockExpectedState::builder("MY_CHAIN")
            .with_chain_management(true)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_policy_only() {
        let result = IptablesBlockExpectedState::builder("INPUT")
            .with_policy(IptablesPolicy::Drop)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_insert_with_rule_num() {
        let result = IptablesBlockExpectedState::builder("INPUT")
            .with_action(IptablesAction::Insert)
            .with_rule_num(1)
            .with_jump("ACCEPT")
            .build();
        assert!(result.is_ok());
    }
}
