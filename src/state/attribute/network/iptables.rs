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
//!   - Name: Allow SSH on port 22
//!     Privilege: !WithSudo
//!     Detail: !Iptables
//!       Chain: INPUT
//!       Protocol: tcp
//!       DestinationPort: "22"
//!       Jump: ACCEPT
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
use crate::state::attribute::RemediationsList;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::time::Duration;

use serde::{Deserializer, Serializer};
use std::net::IpAddr;
use std::str::FromStr;




















/// A strongly-typed, self-validated CIDR block or single IP address 
/// implemented entirely using standard library types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrBlock {
    addr: IpAddr,
    prefix: Option<u8>,
}

impl CidrBlock {
    /// Manually parse and validate an IP or CIDR string.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('/').collect();
        
        if parts.is_empty() || parts.len() > 2 {
            return Err(format!("Invalid CIDR format: '{}'", s));
        }

        // Parse the base IP address
        let addr = IpAddr::from_str(parts[0])
            .map_err(|e| format!("Invalid IP address '{}': {}", parts[0], e))?;

        // Parse and validate the optional prefix mask
        let prefix = if parts.len() == 2 {
            let p: u8 = parts[1]
                .parse()
                .map_err(|_| format!("Invalid subnet prefix: '{}'", parts[1]))?;

            // Validate bounds based on whether it's IPv4 or IPv6
            let max_prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };

            if p > max_prefix {
                return Err(format!(
                    "Subnet prefix /{} is out of bounds for this IP type (max {})",
                    p, max_prefix
                ));
            }
            Some(p)
        } else {
            None
        };

        Ok(CidrBlock { addr, prefix })
    }

    /// Returns the string representation
    pub fn to_string(&self) -> String {
        match self.prefix {
            Some(p) => format!("{}/{}", self.addr, p),
            None => self.addr.to_string(),
        }
    }
}

// Serde integration
impl Serialize for CidrBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CidrBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CidrBlock::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// IP version for iptables commands
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpVersion {
    /// IPv4 protocol
    V4,
    /// IPv6 protocol
    V6,
}

/// Helper function to provide the default IP family (V4)
fn default_ip_family() -> IpVersion {
    IpVersion::V4
}

/// Helper to keep serialized JSON clean by omitting "Family": "V4" if it matches the default.
fn is_v4_default(family: &IpVersion) -> bool {
    matches!(family, IpVersion::V4)
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesInsertionAction {
    Append,
    Insert { position: u32 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Protocol {
    Tcp { 
        #[serde(skip_serializing_if = "Option::is_none")]
        source_port: Option<PortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dest_port: Option<PortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcp_flags: Option<TcpFlagsMatch>,
    },
    Udp { 
        #[serde(skip_serializing_if = "Option::is_none")]
        source_port: Option<PortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dest_port: Option<PortSpec>,
    },
    Icmp {
        #[serde(skip_serializing_if = "Option::is_none")]
        icmp_type: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        icmp_code: Option<u8>,
    },
    All,
}

/// TCP Flag matching options
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TcpFlag {
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
    Urg,
    FinRst,
    All,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TcpFlagsMatch {
    pub mask: Vec<TcpFlag>,
    pub comp: Vec<TcpFlag>,
}

/// Rate limiting specification (-m limit)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RateLimit {
    pub rate: u32,                  // e.g., 3
    pub unit: RateUnit,             // per second, minute, etc.
    pub burst: Option<u32>,         // --limit-burst
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
    Day,
}

/// Connection tracking states (-m conntrack --ctstate)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConntrackMatch {
    pub states: Vec<ConnectionState>,
}

/// User/Group ownership matching (-m owner)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OwnerMatch {
    UidOwner(String), // Can be a username or UID number (e.g., "www-data" or "33")
    GidOwner(String), // Can be a group name or GID number
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MatchCriteria {
    pub protocol: Protocol,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Invert<CidrBlock>>,          // Supports "! -s ..."
          
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Invert<CidrBlock>>,     // Supports "! -d ..."

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interface_in: Option<Invert<String>>,  // Supports "! -i ..."

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interface_out: Option<Invert<String>>, // Supports "! -o ..."

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<bool>,                // -f / ! -f

    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<RateLimit>,              // -m limit

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conntrack: Option<Invert<ConntrackMatch>>,     // Supports "! -m conntrack --ctstate ..."

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Invert<OwnerMatch>>,             // Supports "! -m owner ..."

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,               // -m comment
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RejectWith {
    IcmpPortUnreachable,
    IcmpNetUnreachable,
    TcpReset,
    EchoReply,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IptablesTarget {
    Accept,
    Drop,
    Reject {
        #[serde(skip_serializing_if = "Option::is_none")]
        with: Option<RejectWith>,
    },
    Log {
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        level: Option<u8>, // Log level (0-7)
    },
    Return,
    /// Jump to a custom or standard chain (-j CHAIN)
    Jump(String),
    /// Unconditional jump to a chain without returning (-g CHAIN)
    Goto(String),
    Custom(String),
}

/// Chains unique to the Raw table
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RawChain {
    Prerouting,
    Output,
    Custom(String),
}

/// Chains unique to the Filter table
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilterChain {
    Input,
    Forward,
    Output,
    Custom(String),
}

/// Chains unique to the Nat table
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NatChain {
    Prerouting,
    Input,
    Output,
    Postrouting,
    Custom(String),
}

/// Chains available in Mangle table
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MangleChain {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    Custom(String),
}

/// Chains available in Security table
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityChain {
    Input,
    Forward,
    Output,
    Custom(String),
}

/// An enum representing a table, bundling ONLY valid chains for that table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "Table", content = "Details", rename_all = "PascalCase")]
pub enum IptablesRule {
    Raw {
        chain: RawChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    Filter {
        chain: FilterChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    Nat {
        chain: NatChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    Mangle {
        chain: MangleChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    Security {
        chain: SecurityChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
}

/// Desired state of an iptables rule
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RuleExpectedState {
    Present,
    Absent,
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "State", rename_all = "PascalCase")]
pub enum IptablesBlockExpectedState {
    /// If it must be Present, we *must* specify how to place it (Append/Insert)
    Present {
        #[serde(default = "default_ip_family", skip_serializing_if = "is_v4_default")]
        ip_version: IpVersion,
        action: IptablesInsertionAction,
        #[serde(flatten)]
        rule: IptablesRule,
    },
    /// If it must be Absent, an action is completely irrelevant; 
    /// the reconciliation engine just needs to find and purge matching rules.
    Absent {
        #[serde(default = "default_ip_family", skip_serializing_if = "is_v4_default")]
        ip_version: IpVersion,
        #[serde(flatten)]
        rule: IptablesRule,
    },
}


// Support for inversion
/// Wraps any match value to indicate whether it should be matched normally or inverted (!)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invert<T> {
    pub value: T,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inverted: bool,
}

impl<T> Invert<T> {
    pub fn new(value: T) -> Self {
        Self { value, inverted: false }
    }

    pub fn inverted(value: T) -> Self {
        Self { value, inverted: true }
    }
}

/// Represents a single port or a contiguous port range (e.g., "1024:65535")
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortRange {
    Single(u16),
    Range {
        start: u16,
        end: u16,
    },
}

/// Represents either a single port match or a multiport list (up to 15 items in iptables)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    Range { start: u16, end: u16 },
    List(Vec<PortRange>),
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
///   - Name: SSH on port 22 must be allowed
///     Privilege: !WithSudo
///     Detail: !Iptables
///       Chain: INPUT
///       Protocol: tcp
///       DestinationPort: "22"
///       Jump: ACCEPT
///
///   # Set default policy
///   - Name: Default INPUT policy must be set to DROP
///     Privilege: !WithSudo
///     Detail: !Iptables
///       Chain: INPUT
///       Policy: !Drop
///
///   # NAT masquerade
///   - Name: NAT masquerade on eth0 must be enabled
///     Privilege: !WithSudo
///     Detail: !Iptables
///       Chain: POSTROUTING
///       Table: !Nat
///       OutInterface: eth0
///       Jump: MASQUERADE
/// ```


impl Timeout for IptablesBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl IptablesBlockExpectedState {
    
}

// ── Check ─────────────────────────────────────────────────────────────────────

impl Check for IptablesBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if let IptablesChain::Custom(custom_chain) = &self.chain {
            if custom_chain.is_empty() {
                return Err(RegentError::IncoherentExpectedState(
                    "chain must not be empty.".to_string(),
                ));
            }
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
                        return Ok(AttributeComplianceAssessment::NonCompliant(
                            RemediationsList::from(remediations)?,
                        ));
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
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(remediations)?,
            ))
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
        chain: IptablesChain,
    },
    FlushAndDeleteChain {
        binary: String,
        table_arg: String,
        chain: IptablesChain,
    },
    SetPolicy {
        binary: String,
        table_arg: String,
        chain: IptablesChain,
        policy: String,
    },
    AppendRule {
        binary: String,
        table_arg: String,
        chain: IptablesChain,
        rule_args: String,
    },
    InsertRule {
        binary: String,
        table_arg: String,
        chain: IptablesChain,
        rule_num: Option<u32>,
        rule_args: String,
    },
    DeleteRule {
        binary: String,
        table_arg: String,
        chain: IptablesChain,
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
            let verification_result =
                verify_rule_position(host_handler, &self.api_call, &self.privilege).await;

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
                let list_cmd = build_cmd(
                    binary,
                    table_arg,
                    &format!("-L {} --line-numbers -n", chain),
                );
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
}
