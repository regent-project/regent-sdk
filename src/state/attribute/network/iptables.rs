//! Iptables attribute for firewall rule management
//!
//! This module provides the `IptablesBlockExpectedState` type for managing iptables/ip6tables
//! firewall rules and chains. It supports creating, modifying, and deleting rules across
//! different tables (filter, nat, mangle, raw, security) using a strongly-typed API.
//!
//! **Compatible OS:** Linux (all distributions)
//!
//! # Serialization Behavior
//!
//! All enums in this module use `#[serde(rename_all = "PascalCase")]` for YAML serialization,
//! producing human-readable PascalCase format (e.g., `Input`, `Tcp`, `Output`).
//! However, they implement `std::fmt::Display` to output iptables-native format when generating
//! shell commands (e.g., `INPUT`, `tcp`, `OUTPUT`, `tcp-reset`). This ensures YAML remains
//! user-friendly while generated iptables commands use the correct syntax.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::network::iptables::{IptablesBlockExpectedState, IpVersion};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Allow SSH on port 22 using convenience method (defaults to IPv4)
//! let ssh_rule = IptablesBlockExpectedState::allow_ssh(None);
//!
//! // Allow HTTP on port 80 at position 1
//! let http_rule = IptablesBlockExpectedState::allow_tcp_port(80, Some(1));
//!
//! // Allow DNS on port 53 (UDP)
//! let dns_rule = IptablesBlockExpectedState::allow_udp_port(53, None);
//!
//! // Drop all incoming traffic (default deny)
//! let deny_all = IptablesBlockExpectedState::drop_all_incoming(None);
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::iptables(ssh_rule, Privilege::WithSudo, None))
//!     .with_attribute(Attribute::iptables(http_rule, Privilege::WithSudo, None))
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
//!       State: Present
//!       IpVersion: V4
//!       Action: Append
//!       Table: Filter
//!       Chain: INPUT
//!       Criteria:
//!         Protocol: Tcp
//!         DestinationPort: 22
//!       Target: Accept
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

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;
use std::str::FromStr;

/// A Self-validated CIDR block or single IP address
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

        let addr = IpAddr::from_str(parts[0])
            .map_err(|e| format!("Invalid IP address '{}': {}", parts[0], e))?;

        let prefix = if parts.len() == 2 {
            let p: u8 = parts[1]
                .parse()
                .map_err(|_| format!("Invalid subnet prefix: '{}'", parts[1]))?;

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

    pub fn to_string(&self) -> String {
        match self.prefix {
            Some(p) => format!("{}/{}", self.addr, p),
            None => self.addr.to_string(),
        }
    }
}

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
///
/// Serializes to YAML as `V4` or `V6`.
/// Displays as `iptables` or `ip6tables` for command generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpVersion {
    V4,
    V6,
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpVersion::V4 => write!(f, "iptables"),
            IpVersion::V6 => write!(f, "ip6tables"),
        }
    }
}

fn default_ip_family() -> IpVersion {
    IpVersion::V4
}

fn is_v4_default(family: &IpVersion) -> bool {
    matches!(family, IpVersion::V4)
}

/// Action for inserting a rule into a chain
///
/// Serializes to YAML as `Append` or `Insert` with a `Position` field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesInsertionAction {
    Append,
    #[serde(rename_all = "PascalCase")]
    Insert {
        position: u32,
    },
}

/// Network protocol for iptables rule matching
///
/// Serializes to YAML as `Tcp`, `Udp`, `Icmp`, or `All`.
/// Displays as `tcp`, `udp`, `icmp`, or `all` for command generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Protocol {
    #[serde(rename_all = "PascalCase")]
    Tcp {
        #[serde(skip_serializing_if = "Option::is_none")]
        source_port: Option<PortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dest_port: Option<PortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcp_flags: Option<TcpFlagsMatch>,
    },
    #[serde(rename_all = "PascalCase")]
    Udp {
        #[serde(skip_serializing_if = "Option::is_none")]
        source_port: Option<PortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dest_port: Option<PortSpec>,
    },
    #[serde(rename_all = "PascalCase")]
    Icmp {
        #[serde(skip_serializing_if = "Option::is_none")]
        icmp_type: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        icmp_code: Option<u8>,
    },
    All,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp { .. } => write!(f, "tcp"),
            Protocol::Udp { .. } => write!(f, "udp"),
            Protocol::Icmp { .. } => write!(f, "icmp"),
            Protocol::All => write!(f, "all"),
        }
    }
}

/// TCP Flag matching options
///
/// Serializes to YAML as `Syn`, `Ack`, `Fin`, `Rst`, `Psh`, `Urg`, `FinRst`, `All`, or `None`.
/// Displays as `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `FIN,RST`, `ALL`, or `NONE` for command
/// generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
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

impl std::fmt::Display for TcpFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpFlag::Syn => write!(f, "SYN"),
            TcpFlag::Ack => write!(f, "ACK"),
            TcpFlag::Fin => write!(f, "FIN"),
            TcpFlag::Rst => write!(f, "RST"),
            TcpFlag::Psh => write!(f, "PSH"),
            TcpFlag::Urg => write!(f, "URG"),
            TcpFlag::FinRst => write!(f, "FIN,RST"),
            TcpFlag::All => write!(f, "ALL"),
            TcpFlag::None => write!(f, "NONE"),
        }
    }
}

/// TCP flags match specification (-m tcp --tcp-flags)
///
/// `mask` specifies which flags to check, and `comp` specifies which of those must be set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TcpFlagsMatch {
    pub mask: Vec<TcpFlag>,
    pub comp: Vec<TcpFlag>,
}

/// Rate limiting specification (-m limit)
///
/// Serializes to YAML with `Rate`, `Unit`, and optional `Burst` fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RateLimit {
    pub rate: u32,
    pub unit: RateUnit,
    pub burst: Option<u32>,
}

/// Rate unit for limit matching (-m limit)
///
/// Serializes to YAML as `Second`, `Minute`, `Hour`, or `Day`.
/// Displays as `/second`, `/minute`, `/hour`, or `/day` for command generation via
/// `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
    Day,
}

impl std::fmt::Display for RateUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateUnit::Second => write!(f, "/second"),
            RateUnit::Minute => write!(f, "/minute"),
            RateUnit::Hour => write!(f, "/hour"),
            RateUnit::Day => write!(f, "/day"),
        }
    }
}

/// Connection tracking states (-m conntrack --ctstate)
///
/// Serializes to YAML as `New`, `Established`, `Related`, `Invalid`, or `Untracked`.
/// Displays as `NEW`, `ESTABLISHED`, `RELATED`, `INVALID`, or `UNTRACKED` for command
/// generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::New => write!(f, "NEW"),
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::Related => write!(f, "RELATED"),
            ConnectionState::Invalid => write!(f, "INVALID"),
            ConnectionState::Untracked => write!(f, "UNTRACKED"),
        }
    }
}

/// Connection tracking match specification (-m conntrack --ctstate)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConntrackMatch {
    pub states: Vec<ConnectionState>,
}

/// User/Group ownership matching (-m owner)
///
/// Serializes to YAML as `UidOwner("username")` or `GidOwner("groupname")`.
/// Displays as `--uid-owner username` or `--gid-owner groupname` for command generation via
/// `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OwnerMatch {
    UidOwner(String),
    GidOwner(String),
}

impl std::fmt::Display for OwnerMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnerMatch::UidOwner(uid) => write!(f, "--uid-owner {}", uid),
            OwnerMatch::GidOwner(gid) => write!(f, "--gid-owner {}", gid),
        }
    }
}

/// Match criteria for iptables rules
///
/// Contains all possible matching criteria for an iptables rule. All fields are optional
/// and use `Invert` wrapper for fields that support negation with `!` in iptables syntax.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MatchCriteria {
    pub protocol: Protocol,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Invert<CidrBlock>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Invert<CidrBlock>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interface_in: Option<Invert<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interface_out: Option<Invert<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<RateLimit>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conntrack: Option<Invert<ConntrackMatch>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Invert<OwnerMatch>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Rejection types for the REJECT target (--reject-with)
///
/// Serializes to YAML as `IcmpPortUnreachable`, `IcmpNetUnreachable`, `TcpReset`, or `EchoReply`.
/// Displays as `icmp-port-unreachable`, `icmp-net-unreachable`, `tcp-reset`, or `echo-reply`
/// for command generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RejectWith {
    IcmpPortUnreachable,
    IcmpNetUnreachable,
    TcpReset,
    EchoReply,
}

impl std::fmt::Display for RejectWith {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectWith::IcmpPortUnreachable => write!(f, "icmp-port-unreachable"),
            RejectWith::IcmpNetUnreachable => write!(f, "icmp-net-unreachable"),
            RejectWith::TcpReset => write!(f, "tcp-reset"),
            RejectWith::EchoReply => write!(f, "echo-reply"),
        }
    }
}

/// Target action for an iptables rule (-j, -g)
///
/// Serializes to YAML as `Accept`, `Drop`, `Reject`, `Log`, `Return`, `Jump`, `Goto`, or `Custom`.
/// The `Reject` and `Log` variants support additional options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IptablesTarget {
    Accept,
    Drop,
    #[serde(rename_all = "PascalCase")]
    Reject {
        #[serde(skip_serializing_if = "Option::is_none")]
        with: Option<RejectWith>,
    },
    #[serde(rename_all = "PascalCase")]
    Log {
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        level: Option<u8>,
    },
    Return,
    Jump(String),
    Goto(String),
    Custom(String),
}

/// Chains unique to the Raw table
///
/// Serializes to YAML as `Prerouting`, `Output`, or `Custom("name")`.
/// Displays as `PREROUTING`, `OUTPUT`, or custom name for command generation via
/// `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RawChain {
    Prerouting,
    Output,
    Custom(String),
}

impl std::fmt::Display for RawChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawChain::Prerouting => write!(f, "PREROUTING"),
            RawChain::Output => write!(f, "OUTPUT"),
            RawChain::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Chains unique to the Filter table
///
/// Serializes to YAML as `Input`, `Forward`, `Output`, or `Custom("name")`.
/// Displays as `INPUT`, `FORWARD`, `OUTPUT`, or custom name for command generation via
/// `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FilterChain {
    Input,
    Forward,
    Output,
    Custom(String),
}

impl std::fmt::Display for FilterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterChain::Input => write!(f, "INPUT"),
            FilterChain::Forward => write!(f, "FORWARD"),
            FilterChain::Output => write!(f, "OUTPUT"),
            FilterChain::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Chains unique to the Nat table
///
/// Serializes to YAML as `Prerouting`, `Input`, `Output`, `Postrouting`, or `Custom("name")`.
/// Displays as `PREROUTING`, `INPUT`, `OUTPUT`, `POSTROUTING`, or custom name for command
/// generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NatChain {
    Prerouting,
    Input,
    Output,
    Postrouting,
    Custom(String),
}

impl std::fmt::Display for NatChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatChain::Prerouting => write!(f, "PREROUTING"),
            NatChain::Input => write!(f, "INPUT"),
            NatChain::Output => write!(f, "OUTPUT"),
            NatChain::Postrouting => write!(f, "POSTROUTING"),
            NatChain::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Chains available in Mangle table
///
/// Serializes to YAML as `Prerouting`, `Input`, `Forward`, `Output`, `Postrouting`, or
/// `Custom("name")`.
/// Displays as `PREROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, `POSTROUTING`, or custom name
/// for command generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum MangleChain {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    Custom(String),
}

impl std::fmt::Display for MangleChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MangleChain::Prerouting => write!(f, "PREROUTING"),
            MangleChain::Input => write!(f, "INPUT"),
            MangleChain::Forward => write!(f, "FORWARD"),
            MangleChain::Output => write!(f, "OUTPUT"),
            MangleChain::Postrouting => write!(f, "POSTROUTING"),
            MangleChain::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Chains available in Security table
///
/// Serializes to YAML as `Input`, `Forward`, `Output`, or `Custom("name")`.
/// Displays as `INPUT`, `FORWARD`, `OUTPUT`, or custom name for command generation via
/// `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SecurityChain {
    Input,
    Forward,
    Output,
    Custom(String),
}

impl std::fmt::Display for SecurityChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityChain::Input => write!(f, "INPUT"),
            SecurityChain::Forward => write!(f, "FORWARD"),
            SecurityChain::Output => write!(f, "OUTPUT"),
            SecurityChain::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// An enum representing a table, bundling ONLY valid chains for that table.
///
/// Serializes to YAML with a `Table` tag and `Details` content using PascalCase for all fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "Table", content = "Details", rename_all = "PascalCase")]
pub enum IptablesRule {
    #[serde(rename_all = "PascalCase")]
    Raw {
        chain: RawChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    #[serde(rename_all = "PascalCase")]
    Filter {
        chain: FilterChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    #[serde(rename_all = "PascalCase")]
    Nat {
        chain: NatChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    #[serde(rename_all = "PascalCase")]
    Mangle {
        chain: MangleChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
    #[serde(rename_all = "PascalCase")]
    Security {
        chain: SecurityChain,
        criteria: MatchCriteria,
        target: IptablesTarget,
    },
}

/// Desired state of an iptables rule
///
/// Serializes to YAML as `Present` or `Absent`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RuleExpectedState {
    Present,
    Absent,
}

/// Wraps any match value to indicate whether it should be matched normally or inverted (!)
///
/// Serializes to YAML as `{ Value: ..., Inverted: true/false }` when inverted is true,
/// or just the inner value when inverted is false (due to `skip_serializing_if`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Invert<T> {
    pub value: T,
    #[serde(
        rename = "Inverted",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub inverted: bool,
}

impl<T> Invert<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            inverted: false,
        }
    }

    pub fn inverted(value: T) -> Self {
        Self {
            value,
            inverted: true,
        }
    }
}

/// Represents a single port or a contiguous port range (e.g., "1024:65535")
///
/// Serializes to YAML as a single number or `{ Start: ..., End: ... }`.
/// Displays as `port` or `start:end` for command generation via `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", untagged)]
pub enum PortRange {
    Single(u16),
    Range {
        #[serde(rename = "Start")]
        start: u16,
        #[serde(rename = "End")]
        end: u16,
    },
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortRange::Single(port) => write!(f, "{}", port),
            PortRange::Range { start, end } => write!(f, "{}:{}", start, end),
        }
    }
}

/// Represents either a single port match or a multiport list
///
/// Serializes to YAML as a single number, a range object, or a list of port ranges.
/// Displays as a comma-separated list of ports/ranges for command generation via
/// `std::fmt::Display`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", untagged)]
pub enum PortSpec {
    Single(u16),
    Range {
        #[serde(rename = "Start")]
        start: u16,
        #[serde(rename = "End")]
        end: u16,
    },
    List(Vec<PortRange>),
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortSpec::Single(port) => write!(f, "{}", port),
            PortSpec::Range { start, end } => write!(f, "{}:{}", start, end),
            PortSpec::List(ports) => {
                let port_strs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{}", port_strs.join(","))
            }
        }
    }
}

/// Desired state for an iptables/ip6tables rule
///
/// Serializes to YAML with a `State` tag (`Present` or `Absent`) and uses PascalCase for all
/// fields. The `IpVersion` defaults to V4 and is omitted when V4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "State", rename_all = "PascalCase")]
pub enum IptablesBlockExpectedState {
    #[serde(rename_all = "PascalCase")]
    Present {
        #[serde(default = "default_ip_family", skip_serializing_if = "is_v4_default")]
        ip_version: IpVersion,
        action: IptablesInsertionAction,
        #[serde(flatten)]
        rule: IptablesRule,
    },
    #[serde(rename_all = "PascalCase")]
    Absent {
        #[serde(default = "default_ip_family")]
        ip_version: IpVersion,
        #[serde(flatten)]
        rule: IptablesRule,
    },
}

// ── Block expected state ──────────────────────────────────────────────────────

/// Configuration for an iptables/ip6tables rule or chain
///
/// Use the new strongly-typed API to create firewall rules with various matching criteria
/// and actions.
///
/// All types in this module serialize to YAML using PascalCase naming convention for
/// user-friendliness, while implementing `Display` to output the correct iptables command
/// syntax (e.g., chain names in UPPERCASE, reject types in lowercase-with-hyphens).
///
/// # Examples
///
/// ## Rust API
///
/// ```no_run
/// use regent_sdk::state::attribute::network::iptables::{
///     IptablesBlockExpectedState, IpVersion, IptablesInsertionAction,
///     IptablesRule, FilterChain, Protocol, MatchCriteria, IptablesTarget
/// };
/// use regent_sdk::state::attribute::network::iptables::PortSpec;
/// use regent_sdk::{Attribute, ExpectedState, Privilege};
///
/// // Allow SSH on port 22 using convenience method (defaults to IPv4)
/// let ssh_rule = IptablesBlockExpectedState::allow_ssh(None);
///
/// // Or use the full API for more complex rules
impl IptablesBlockExpectedState {
    pub fn present(
        ip_version: IpVersion,
        action: IptablesInsertionAction,
        rule: IptablesRule,
    ) -> IptablesBlockExpectedState {
        IptablesBlockExpectedState::Present {
            ip_version,
            action,
            rule,
        }
    }

    pub fn absent(ip_version: IpVersion, rule: IptablesRule) -> IptablesBlockExpectedState {
        IptablesBlockExpectedState::Absent { ip_version, rule }
    }

    /// Allow incoming TCP traffic on a specific port in the INPUT chain.
    /// This is a convenience method for the common use case of opening a TCP port.
    ///
    /// # Arguments
    /// * `port` - The TCP port number to allow
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn allow_tcp_port(port: u16, position: Option<u32>) -> IptablesBlockExpectedState {
        Self::allow_tcp_port_with_ip(port, IpVersion::V4, position)
    }

    /// Allow incoming TCP traffic on a specific port in the INPUT chain with custom IP version.
    ///
    /// # Arguments
    /// * `port` - The TCP port number to allow
    /// * `ip_version` - IP version (V4 or V6)
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn allow_tcp_port_with_ip(
        port: u16,
        ip_version: IpVersion,
        position: Option<u32>,
    ) -> IptablesBlockExpectedState {
        let action = match position {
            Some(pos) => IptablesInsertionAction::Insert { position: pos },
            None => IptablesInsertionAction::Append,
        };
        IptablesBlockExpectedState::Present {
            ip_version,
            action,
            rule: IptablesRule::Filter {
                chain: FilterChain::Input,
                criteria: MatchCriteria {
                    protocol: Protocol::Tcp {
                        source_port: None,
                        dest_port: Some(PortSpec::Single(port)),
                        tcp_flags: None,
                    },
                    source: None,
                    destination: None,
                    network_interface_in: None,
                    network_interface_out: None,
                    fragment: None,
                    limit: None,
                    conntrack: None,
                    owner: None,
                    comment: None,
                },
                target: IptablesTarget::Accept,
            },
        }
    }

    /// Allow incoming UDP traffic on a specific port in the INPUT chain.
    /// This is a convenience method for the common use case of opening a UDP port.
    ///
    /// # Arguments
    /// * `port` - The UDP port number to allow
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn allow_udp_port(port: u16, position: Option<u32>) -> IptablesBlockExpectedState {
        Self::allow_udp_port_with_ip(port, IpVersion::V4, position)
    }

    /// Allow incoming UDP traffic on a specific port in the INPUT chain with custom IP version.
    ///
    /// # Arguments
    /// * `port` - The UDP port number to allow
    /// * `ip_version` - IP version (V4 or V6)
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn allow_udp_port_with_ip(
        port: u16,
        ip_version: IpVersion,
        position: Option<u32>,
    ) -> IptablesBlockExpectedState {
        let action = match position {
            Some(pos) => IptablesInsertionAction::Insert { position: pos },
            None => IptablesInsertionAction::Append,
        };
        IptablesBlockExpectedState::Present {
            ip_version,
            action,
            rule: IptablesRule::Filter {
                chain: FilterChain::Input,
                criteria: MatchCriteria {
                    protocol: Protocol::Udp {
                        source_port: None,
                        dest_port: Some(PortSpec::Single(port)),
                    },
                    source: None,
                    destination: None,
                    network_interface_in: None,
                    network_interface_out: None,
                    fragment: None,
                    limit: None,
                    conntrack: None,
                    owner: None,
                    comment: None,
                },
                target: IptablesTarget::Accept,
            },
        }
    }

    /// Allow incoming SSH traffic on port 22 in the INPUT chain.
    /// This is a convenience method for the common use case of enabling SSH access.
    ///
    /// # Arguments
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn allow_ssh(position: Option<u32>) -> IptablesBlockExpectedState {
        Self::allow_ssh_with_ip(IpVersion::V4, position)
    }

    /// Allow incoming SSH traffic on port 22 in the INPUT chain with custom IP version.
    ///
    /// # Arguments
    /// * `ip_version` - IP version (V4 or V6)
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn allow_ssh_with_ip(
        ip_version: IpVersion,
        position: Option<u32>,
    ) -> IptablesBlockExpectedState {
        Self::allow_tcp_port_with_ip(22, ip_version, position)
    }

    /// Drop all incoming traffic on the INPUT chain.
    /// This is a convenience method for creating a default deny policy.
    ///
    /// # Arguments
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn drop_all_incoming(position: Option<u32>) -> IptablesBlockExpectedState {
        Self::drop_all_incoming_with_ip(IpVersion::V4, position)
    }

    /// Drop all incoming traffic on the INPUT chain with custom IP version.
    ///
    /// # Arguments
    /// * `ip_version` - IP version (V4 or V6)
    /// * `position` - Optional rule position for insertion (uses Append if None)
    pub fn drop_all_incoming_with_ip(
        ip_version: IpVersion,
        position: Option<u32>,
    ) -> IptablesBlockExpectedState {
        let action = match position {
            Some(pos) => IptablesInsertionAction::Insert { position: pos },
            None => IptablesInsertionAction::Append,
        };
        IptablesBlockExpectedState::Present {
            ip_version,
            action,
            rule: IptablesRule::Filter {
                chain: FilterChain::Input,
                criteria: MatchCriteria {
                    protocol: Protocol::All,
                    source: None,
                    destination: None,
                    network_interface_in: None,
                    network_interface_out: None,
                    fragment: None,
                    limit: None,
                    conntrack: None,
                    owner: None,
                    comment: None,
                },
                target: IptablesTarget::Drop,
            },
        }
    }
}

impl Timeout for IptablesBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

// ── Check ─────────────────────────────────────────────────────────────────────

impl Check for IptablesBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        // Extract the rule which is present in both Present and Absent variants
        let rule = match self {
            IptablesBlockExpectedState::Present { rule, .. }
            | IptablesBlockExpectedState::Absent { rule, .. } => rule,
        };

        // Check that custom chain names are not empty
        match rule {
            IptablesRule::Raw {
                chain: RawChain::Custom(c),
                ..
            }
            | IptablesRule::Filter {
                chain: FilterChain::Custom(c),
                ..
            }
            | IptablesRule::Nat {
                chain: NatChain::Custom(c),
                ..
            }
            | IptablesRule::Mangle {
                chain: MangleChain::Custom(c),
                ..
            }
            | IptablesRule::Security {
                chain: SecurityChain::Custom(c),
                ..
            } => {
                if c.is_empty() {
                    return Err(RegentError::IncoherentExpectedState(
                        "custom chain name must not be empty.".to_string(),
                    ));
                }
            }
            _ => {}
        }

        // In the new structure, the target is always present in IptablesRule
        // so we don't need to check for at least one actionable

        // For Present variant, check that if action is Insert, it has a position
        if let IptablesBlockExpectedState::Present { action, .. } = self {
            if let IptablesInsertionAction::Insert { position: _ } = action {
                // Position is required in the Insert variant, so it's always valid
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

/// Helper function to get the table argument from an IptablesRule
fn get_table_arg(rule: &IptablesRule) -> String {
    match rule {
        IptablesRule::Raw {
            chain: _,
            criteria: _,
            target: _,
        } => "-t raw",
        IptablesRule::Filter {
            chain: _,
            criteria: _,
            target: _,
        } => "-t filter",
        IptablesRule::Nat {
            chain: _,
            criteria: _,
            target: _,
        } => "-t nat",
        IptablesRule::Mangle {
            chain: _,
            criteria: _,
            target: _,
        } => "-t mangle",
        IptablesRule::Security {
            chain: _,
            criteria: _,
            target: _,
        } => "-t security",
    }
    .to_string()
}

/// Helper function to get the chain name from an IptablesRule
fn get_chain_name(rule: &IptablesRule) -> String {
    match rule {
        IptablesRule::Raw { chain, .. } => chain.to_string(),
        IptablesRule::Filter { chain, .. } => chain.to_string(),
        IptablesRule::Nat { chain, .. } => chain.to_string(),
        IptablesRule::Mangle { chain, .. } => chain.to_string(),
        IptablesRule::Security { chain, .. } => chain.to_string(),
    }
}

/// Helper function to convert IpVersion to a string for Display
fn ip_version_to_str(ip_version: &IpVersion) -> String {
    ip_version.to_string()
}

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

        // Extract ip_version, action, and rule from the IptablesBlockExpectedState
        let (ip_version, expected_state, action, rule) = match self {
            IptablesBlockExpectedState::Present {
                ip_version,
                action,
                rule,
            } => (
                ip_version,
                RuleExpectedState::Present,
                Some(action.clone()),
                rule,
            ),
            IptablesBlockExpectedState::Absent { ip_version, rule } => {
                (ip_version, RuleExpectedState::Absent, None, rule)
            }
        };

        let binary = ip_version_to_str(&ip_version);
        let table_arg = get_table_arg(rule);
        let chain_name = get_chain_name(rule);

        let mut remediations: Vec<Remediation> = Vec::new();

        // Build the rule arguments from the MatchCriteria and IptablesTarget
        let rule_args = build_rule_args_from_new_structures(rule);

        // Check if the rule exists
        let check_rule_cmd = build_cmd(
            &binary,
            &table_arg,
            &format!("-C {} {}", chain_name, rule_args),
        );
        let check_rule_cmd = format!("{} 2>/dev/null", check_rule_cmd);
        let check_result = host_handler
            .run_command(&check_rule_cmd, &Privilege::None)
            .await
            .unwrap();

        match expected_state {
            RuleExpectedState::Present => {
                if check_result.return_code != 0 {
                    // Rule doesn't exist, need to add it
                    let insertion_action = action.unwrap_or(IptablesInsertionAction::Append);
                    match insertion_action {
                        IptablesInsertionAction::Append => {
                            remediations.push(Remediation::Iptables(IptablesApiCall::from(
                                IptablesModuleInternalApiCall::AppendRule {
                                    binary: binary.to_string(),
                                    table_arg: table_arg.clone(),
                                    chain: chain_name.clone(),
                                    rule_args: rule_args.clone(),
                                },
                                privilege.clone(),
                            )));
                        }
                        IptablesInsertionAction::Insert { position } => {
                            remediations.push(Remediation::Iptables(IptablesApiCall::from(
                                IptablesModuleInternalApiCall::InsertRule {
                                    binary: binary.to_string(),
                                    table_arg: table_arg.clone(),
                                    chain: chain_name.clone(),
                                    rule_num: Some(position),
                                    rule_args: rule_args.clone(),
                                },
                                privilege.clone(),
                            )));
                        }
                    }
                }
            }
            RuleExpectedState::Absent => {
                if check_result.return_code == 0 {
                    // Rule exists but should be absent, need to delete it
                    remediations.push(Remediation::Iptables(IptablesApiCall::from(
                        IptablesModuleInternalApiCall::DeleteRule {
                            binary: binary.to_string(),
                            table_arg: table_arg.clone(),
                            chain: chain_name.clone(),
                            rule_args: rule_args.clone(),
                        },
                        privilege.clone(),
                    )));
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
/// Helper function to convert Protocol to iptables protocol string
fn protocol_to_str(proto: &Protocol) -> String {
    proto.to_string()
}

/// Helper function to convert PortSpec to iptables port string
fn port_spec_to_str(port: &PortSpec) -> String {
    port.to_string()
}

/// Helper function to convert TcpFlag to iptables flag string
fn tcp_flag_to_str(flag: &TcpFlag) -> &'static str {
    match flag {
        TcpFlag::Syn => "SYN",
        TcpFlag::Ack => "ACK",
        TcpFlag::Fin => "FIN",
        TcpFlag::Rst => "RST",
        TcpFlag::Psh => "PSH",
        TcpFlag::Urg => "URG",
        TcpFlag::FinRst => "FIN,RST",
        TcpFlag::All => "ALL",
        TcpFlag::None => "NONE",
    }
}

/// Helper function to convert RateUnit to iptables rate unit string
fn rate_unit_to_str(unit: &RateUnit) -> &'static str {
    match unit {
        RateUnit::Second => "/second",
        RateUnit::Minute => "/minute",
        RateUnit::Hour => "/hour",
        RateUnit::Day => "/day",
    }
}

/// Helper function to convert ConnectionState to iptables conntrack state string
fn connection_state_to_str(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::New => "NEW",
        ConnectionState::Established => "ESTABLISHED",
        ConnectionState::Related => "RELATED",
        ConnectionState::Invalid => "INVALID",
        ConnectionState::Untracked => "UNTRACKED",
    }
}

/// Helper function to convert OwnerMatch to iptables owner match string
fn owner_match_to_str(owner: &OwnerMatch) -> String {
    match owner {
        OwnerMatch::UidOwner(uid) => format!("--uid-owner {}", uid),
        OwnerMatch::GidOwner(gid) => format!("--gid-owner {}", gid),
    }
}

/// Builds the rule-specification string from the new strongly-typed structures.
fn build_rule_args_from_new_structures(rule: &IptablesRule) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Extract criteria and target from the rule
    let (criteria, target) = match rule {
        IptablesRule::Raw {
            criteria, target, ..
        }
        | IptablesRule::Filter {
            criteria, target, ..
        }
        | IptablesRule::Nat {
            criteria, target, ..
        }
        | IptablesRule::Mangle {
            criteria, target, ..
        }
        | IptablesRule::Security {
            criteria, target, ..
        } => (criteria, target),
    };

    // Protocol
    parts.push(format!("-p {}", protocol_to_str(&criteria.protocol)));

    // Source (with inversion support)
    if let Some(ref src) = criteria.source {
        let prefix = if src.inverted { "! -s " } else { "-s " };
        parts.push(format!("{} {}", prefix, src.value.to_string()));
    }

    // Destination (with inversion support)
    if let Some(ref dst) = criteria.destination {
        let prefix = if dst.inverted { "! -d " } else { "-d " };
        parts.push(format!("{} {}", prefix, dst.value.to_string()));
    }

    // Input interface (with inversion support)
    if let Some(ref iface) = criteria.network_interface_in {
        let prefix = if iface.inverted { "! -i " } else { "-i " };
        parts.push(format!("{} {}", prefix, iface.value));
    }

    // Output interface (with inversion support)
    if let Some(ref iface) = criteria.network_interface_out {
        let prefix = if iface.inverted { "! -o " } else { "-o " };
        parts.push(format!("{} {}", prefix, iface.value));
    }

    // Source port
    if let Some(ref sport) = get_source_port(&criteria.protocol) {
        parts.push(format!("--sport {}", port_spec_to_str(sport)));
    }

    // Destination port
    if let Some(ref dport) = get_dest_port(&criteria.protocol) {
        parts.push(format!("--dport {}", port_spec_to_str(dport)));
    }

    // TCP flags
    if let Some(ref tcp_flags) = get_tcp_flags(&criteria.protocol) {
        let mask_strs: Vec<&str> = tcp_flags.mask.iter().map(|f| tcp_flag_to_str(f)).collect();
        let comp_strs: Vec<&str> = tcp_flags.comp.iter().map(|f| tcp_flag_to_str(f)).collect();
        parts.push(format!(
            "-m tcp --tcp-flags {} {}",
            mask_strs.join(","),
            comp_strs.join(",")
        ));
    }

    // Connection tracking state (with inversion support)
    if let Some(ref conntrack) = criteria.conntrack {
        let prefix = if conntrack.inverted {
            "! -m conntrack --ctstate "
        } else {
            "-m conntrack --ctstate "
        };
        let states: Vec<&str> = conntrack
            .value
            .states
            .iter()
            .map(|s| connection_state_to_str(s))
            .collect();
        parts.push(format!("{} {}", prefix, states.join(",")));
    }

    // Rate limiting
    if let Some(ref limit) = criteria.limit {
        let rate_str = format!("{} {}", limit.rate, rate_unit_to_str(&limit.unit));
        let mut limit_part = format!("-m limit --limit {}", rate_str);
        if let Some(ref burst) = limit.burst {
            limit_part.push_str(&format!(" --limit-burst {}", burst));
        }
        parts.push(limit_part);
    }

    // Fragment (with inversion support)
    if let Some(ref fragment) = criteria.fragment {
        if *fragment {
            parts.push("-f".to_string());
        }
        // Note: For inverted fragment (! -f), we would need to track it differently
        // For now, we assume fragment is not inverted in the new structure
    }

    // ICMP type and code
    if let Some(ref icmp_type) = get_icmp_type(&criteria.protocol) {
        parts.push(format!("--icmp-type {}", icmp_type));
    }
    if let Some(ref icmp_code) = get_icmp_code(&criteria.protocol) {
        parts.push(format!("--icmp-code {}", icmp_code));
    }

    // Owner match (with inversion support)
    if let Some(ref owner) = criteria.owner {
        let prefix = if owner.inverted {
            "! -m owner "
        } else {
            "-m owner "
        };
        parts.push(format!("{} {}", prefix, owner_match_to_str(&owner.value)));
    }

    // Comment
    if let Some(ref comment) = criteria.comment {
        parts.push(format!("-m comment --comment '{}'", comment));
    }

    // Target
    parts.push(target_to_str(target));

    parts.join(" ")
}

/// Helper functions to extract protocol-specific fields
fn get_source_port(proto: &Protocol) -> Option<&PortSpec> {
    match proto {
        Protocol::Tcp {
            source_port: Some(p),
            ..
        }
        | Protocol::Udp {
            source_port: Some(p),
            ..
        } => Some(p),
        _ => None,
    }
}

fn get_dest_port(proto: &Protocol) -> Option<&PortSpec> {
    match proto {
        Protocol::Tcp {
            dest_port: Some(p), ..
        }
        | Protocol::Udp {
            dest_port: Some(p), ..
        } => Some(p),
        _ => None,
    }
}

fn get_tcp_flags(proto: &Protocol) -> Option<&TcpFlagsMatch> {
    match proto {
        Protocol::Tcp {
            tcp_flags: Some(f), ..
        } => Some(f),
        _ => None,
    }
}

fn get_icmp_type(proto: &Protocol) -> Option<u8> {
    match proto {
        Protocol::Icmp {
            icmp_type: Some(t), ..
        } => Some(*t),
        _ => None,
    }
}

fn get_icmp_code(proto: &Protocol) -> Option<u8> {
    match proto {
        Protocol::Icmp {
            icmp_code: Some(c), ..
        } => Some(*c),
        _ => None,
    }
}

/// Helper function to convert IptablesTarget to iptables target string
fn target_to_str(target: &IptablesTarget) -> String {
    match target {
        IptablesTarget::Accept => "-j ACCEPT".to_string(),
        IptablesTarget::Drop => "-j DROP".to_string(),
        IptablesTarget::Reject {
            with: Some(reject_with),
        } => {
            format!("-j REJECT --reject-with {}", reject_with)
        }
        IptablesTarget::Reject { with: None } => "-j REJECT".to_string(),
        IptablesTarget::Log {
            prefix: Some(p),
            level: Some(l),
        } => {
            format!("-j LOG --log-prefix '{}' --log-level {}", p, l)
        }
        IptablesTarget::Log {
            prefix: Some(p),
            level: None,
        } => {
            format!("-j LOG --log-prefix '{}'", p)
        }
        IptablesTarget::Log {
            prefix: None,
            level: Some(l),
        } => {
            format!("-j LOG --log-level {}", l)
        }
        IptablesTarget::Log {
            prefix: None,
            level: None,
        } => "-j LOG".to_string(),
        IptablesTarget::Return => "-j RETURN".to_string(),
        IptablesTarget::Jump(target) => format!("-j {}", target),
        IptablesTarget::Goto(target) => format!("-g {}", target),
        IptablesTarget::Custom(target) => format!("-j {}", target),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_filter_tcp_present_append() {
        let yaml = r#"
IpVersion: V4
State: Present
Action: Append
Table: Filter
Details:
    Target: Accept
    Chain: Input
    Criteria:
        Protocol:
            Tcp:
                SourcePort: 80
                DestPort: 443
                TcpFlags:
                    Mask: [Syn, Ack]
                    Comp: [Syn]
        Source:
            Value: "192.168.1.0/24"
            Inverted: false
        Comment: "Allow HTTPS web traffic"
    "#;

        let state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        match state {
            IptablesBlockExpectedState::Present {
                ip_version,
                action,
                rule,
            } => {
                assert_eq!(ip_version, IpVersion::V4);
                assert_eq!(action, IptablesInsertionAction::Append);
                match rule {
                    IptablesRule::Filter {
                        chain,
                        criteria,
                        target,
                    } => {
                        assert_eq!(chain, FilterChain::Input);
                        assert_eq!(target, IptablesTarget::Accept);
                        assert!(criteria.comment.is_some());
                    }
                    _ => panic!("Expected Filter rule"),
                }
            }
            _ => panic!("Expected Present state"),
        }
    }

    #[test]
    fn test_deserialize_nat_udp_absent() {
        let yaml = r#"
State: Absent
IpVersion: V6
Table: Nat
Details:
    Chain: Postrouting
    Criteria:
        Protocol:
            Udp:
                SourcePort: 53
                DestPort:
                    Start: 1024
                    End: 65535
        Destination:
            Value: "2001:db8::/32"
            Inverted: true
    Target: 
        Reject:
            With: IcmpPortUnreachable
        "#;

        let state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        match state {
            IptablesBlockExpectedState::Absent { ip_version, rule } => {
                assert_eq!(ip_version, IpVersion::V6);
                match rule {
                    IptablesRule::Nat {
                        chain,
                        criteria,
                        target,
                    } => {
                        assert_eq!(chain, NatChain::Postrouting);
                        assert_eq!(
                            target,
                            IptablesTarget::Reject {
                                with: Some(RejectWith::IcmpPortUnreachable)
                            }
                        );
                        if let Protocol::Udp { dest_port, .. } = criteria.protocol {
                            assert_eq!(
                                dest_port,
                                Some(PortSpec::Range {
                                    start: 1024,
                                    end: 65535
                                })
                            );
                        } else {
                            panic!("Expected UDP protocol");
                        }
                    }
                    _ => panic!("Expected Nat rule"),
                }
            }
            _ => panic!("Expected Absent state"),
        }
    }

    #[test]
    fn test_deserialize_mangle_conntrack_owner() {
        let yaml = r#"
State: Present
Action: Append
Table: Mangle
Details:
    Chain: Output
    Criteria:
        Protocol: All
        Conntrack:
            Value:
                States: [New, Established]
            Inverted: false
        Owner:
            Value:
                UidOwner: "www-data"
            Inverted: true
    Target:
        Log:
            Prefix: "LOG_MARK: "
            Level: 4
        "#;

        let state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        match state {
            IptablesBlockExpectedState::Present { rule, .. } => match rule {
                IptablesRule::Mangle { chain, target, .. } => {
                    assert_eq!(chain, MangleChain::Output);
                    assert_eq!(
                        target,
                        IptablesTarget::Log {
                            prefix: Some("LOG_MARK: ".to_string()),
                            level: Some(4),
                        }
                    );
                }
                _ => panic!("Expected Mangle rule"),
            },
            _ => panic!("Expected Present state"),
        }
    }

    #[test]
    fn test_yaml_vs_rust_api_equivalence_ssh() {
        // YAML representation
        let yaml = r#"
State: Present
IpVersion: V4
Action: Append
Table: Filter
Details:
    Chain: Input
    Criteria:
        Protocol:
            Tcp:
                DestPort: 22
    Target: Accept
"#;
        let yaml_state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        // Rust API representation
        let rust_state = IptablesBlockExpectedState::allow_ssh(None);

        assert_eq!(yaml_state, rust_state);
    }

    #[test]
    fn test_yaml_vs_rust_api_equivalence_http() {
        // YAML representation
        let yaml = r#"
State: Present
IpVersion: V4
Action: Append
Table: Filter
Details:
    Chain: Input
    Criteria:
        Protocol:
            Tcp:
                DestPort: 80
    Target: Accept
"#;
        let yaml_state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        // Rust API representation
        let rust_state = IptablesBlockExpectedState::allow_tcp_port(80, None);

        assert_eq!(yaml_state, rust_state);
    }

    #[test]
    fn test_yaml_vs_rust_api_equivalence_drop_all() {
        // YAML representation
        let yaml = r#"
State: Present
IpVersion: V4
Action: Append
Table: Filter
Details:
    Chain: Input
    Criteria:
        Protocol: All
    Target: Drop
"#;
        let yaml_state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        // Rust API representation
        let rust_state = IptablesBlockExpectedState::drop_all_incoming(None);

        assert_eq!(yaml_state, rust_state);
    }

    #[test]
    fn test_yaml_vs_rust_api_equivalence_udp() {
        // YAML representation
        let yaml = r#"
State: Present
IpVersion: V4
Action: Append
Table: Filter
Details:
    Chain: Input
    Criteria:
        Protocol:
            Udp:
                DestPort: 53
    Target: Accept
"#;
        let yaml_state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        // Rust API representation
        let rust_state = IptablesBlockExpectedState::allow_udp_port(53, None);

        assert_eq!(yaml_state, rust_state);
    }

    #[test]
    fn test_yaml_vs_rust_api_equivalence_complex_rule() {
        // YAML representation of a more complex rule
        let yaml = r#"
State: Present
IpVersion: V4
Action:
    Insert:
        Position: 1
Table: Filter
Details:
    Chain: Input
    Criteria:
        Protocol:
            Tcp:
                DestPort: 443
        Source:
            Value: "192.168.1.0/24"
            Inverted: false
    Target: Accept
"#;
        let yaml_state: IptablesBlockExpectedState = yaml_serde::from_str(yaml).unwrap();

        // Rust API representation
        let rust_state = IptablesBlockExpectedState::present(
            IpVersion::V4,
            IptablesInsertionAction::Insert { position: 1 },
            IptablesRule::Filter {
                chain: FilterChain::Input,
                criteria: MatchCriteria {
                    protocol: Protocol::Tcp {
                        source_port: None,
                        dest_port: Some(PortSpec::Single(443)),
                        tcp_flags: None,
                    },
                    source: Some(Invert::new(CidrBlock::parse("192.168.1.0/24").unwrap())),
                    destination: None,
                    network_interface_in: None,
                    network_interface_out: None,
                    fragment: None,
                    limit: None,
                    conntrack: None,
                    owner: None,
                    comment: None,
                },
                target: IptablesTarget::Accept,
            },
        );

        assert_eq!(yaml_state, rust_state);
    }
}
