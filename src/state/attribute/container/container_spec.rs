//! Value types shared by the container attributes ([`docker`](super::docker),
//! [`podman`](super::podman), [`apptainer`](super::apptainer) and [`enroot`](super::enroot))
//!
//! The Docker and Podman CLIs share the same syntax for ports, volumes, devices, memory sizes... Each type below
//! can only hold a valid value: it is (de)serialized through its string form (`try_from`/`into`),
//! so YAML/JSON input is validated while parsing, and Rust users build it with `FromStr`
//! (`"...".parse()`) or `TryFrom`.

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PullPolicy {
    #[default]
    Missing,
    /// Never pull: a missing image makes the attribute non-compliant (fatal)
    Never,
}

/// `--restart`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RestartPolicy {
    /// `no`
    No,
    /// `always`
    Always,
    /// `unless-stopped`
    UnlessStopped,
    /// `on-failure[:max-retries]` (0 means unlimited retries)
    OnFailure(u32),
}

impl RestartPolicy {
    pub(super) fn as_cli_arg(&self) -> String {
        match self {
            RestartPolicy::No => "no".to_string(),
            RestartPolicy::Always => "always".to_string(),
            RestartPolicy::UnlessStopped => "unless-stopped".to_string(),
            RestartPolicy::OnFailure(0) => "on-failure".to_string(),
            RestartPolicy::OnFailure(max_retries) => format!("on-failure:{}", max_retries),
        }
    }

    pub(super) fn matches(&self, name: &str, max_retries: u64) -> bool {
        match self {
            RestartPolicy::No => name.is_empty() || name == "no",
            RestartPolicy::Always => name == "always",
            RestartPolicy::UnlessStopped => name == "unless-stopped",
            RestartPolicy::OnFailure(expected_retries) => {
                name == "on-failure" && max_retries == *expected_retries as u64
            }
        }
    }
}

pub(crate) fn quoted_command(args: &[&str]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<String>>()
        .join(" ")
}

pub(super) fn pointer<'a>(value: &'a Value, path: &str) -> &'a Value {
    value.pointer(path).unwrap_or(&Value::Null)
}

pub(super) fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn to_strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

pub(super) fn compare_sets(
    reasons: &mut Vec<String>,
    option_name: &str,
    expected: BTreeSet<String>,
    current: BTreeSet<String>,
) {
    if expected != current {
        reasons.push(format!(
            "{} are {:?}, expected {:?}",
            option_name, current, expected
        ));
    }
}

/// Docker and Podman accept capabilities with or without the `CAP_` prefix, in any case
pub(super) fn normalize_capability(capability: &str) -> String {
    let capability = capability.to_uppercase();
    match capability.trim_start_matches("CAP_") {
        "ALL" => "ALL".to_string(),
        name => format!("CAP_{}", name),
    }
}

pub(crate) fn invalid(what: &str, value: &str, details: &str) -> RegentError {
    RegentError::IncoherentExpectedState(format!("Invalid {} {:?}: {}", what, value, details))
}

/// Implements `FromStr`, `Display` and `From<Self> for String` for a type implementing
/// `TryFrom<String>` and `as_string()`
macro_rules! string_backed_type {
    ($($type:ty),* $(,)?) => {$(
        impl FromStr for $type {
            type Err = RegentError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_string())
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.as_string())
            }
        }

        impl From<$type> for String {
            fn from(value: $type) -> String {
                value.as_string()
            }
        }
    )*};
}

string_backed_type!(
    ContainerName,
    ContainerImage,
    EnvVarName,
    NetworkName,
    PublishedPort,
    ContainerVolume,
    Capability,
    MemorySize,
    ExtraHost,
    HostDevice,
    GpuId,
);

/// Container name: `[a-zA-Z0-9][a-zA-Z0-9_.-]*`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerName(String);

impl TryFrom<String> for ContainerName {
    type Error = RegentError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if is_valid_object_name(&name) {
            Ok(Self(name))
        } else {
            Err(invalid(
                "container name",
                &name,
                "allowed characters are [a-zA-Z0-9][a-zA-Z0-9_.-]*",
            ))
        }
    }
}

/// Container (and pod) names: `[a-zA-Z0-9][a-zA-Z0-9_.-]*`
pub(super) fn is_valid_object_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

impl ContainerName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn as_string(&self) -> String {
        self.0.clone()
    }
}

/// Image reference (`[registry/]repository[:tag][@digest]`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerImage(String);

impl TryFrom<String> for ContainerImage {
    type Error = RegentError;

    fn try_from(image: String) -> Result<Self, Self::Error> {
        if image.is_empty() || image.chars().any(char::is_whitespace) {
            Err(invalid(
                "image",
                &image,
                "must be non-empty and without whitespace",
            ))
        } else {
            Ok(Self(image))
        }
    }
}

impl ContainerImage {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn as_string(&self) -> String {
        self.0.clone()
    }
}

/// Omit the command to use the image default
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct ContainerCommand(Vec<String>);

impl TryFrom<Vec<String>> for ContainerCommand {
    type Error = RegentError;

    fn try_from(command: Vec<String>) -> Result<Self, Self::Error> {
        if command.is_empty() {
            Err(RegentError::IncoherentExpectedState(
                "Command can't be empty, omit it to use the image default command".to_string(),
            ))
        } else {
            Ok(Self(command))
        }
    }
}

impl From<ContainerCommand> for Vec<String> {
    fn from(command: ContainerCommand) -> Vec<String> {
        command.0
    }
}

impl ContainerCommand {
    pub fn new(command: &[&str]) -> Result<Self, RegentError> {
        Self::try_from(to_strings(command))
    }

    pub fn args(&self) -> &[String] {
        &self.0
    }
}

/// Environment variable name (non-empty, without `=`)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EnvVarName(String);

impl TryFrom<String> for EnvVarName {
    type Error = RegentError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.is_empty() || name.contains('=') {
            Err(invalid(
                "environment variable name",
                &name,
                "must be non-empty and without '='",
            ))
        } else {
            Ok(Self(name))
        }
    }
}

impl EnvVarName {
    fn as_string(&self) -> String {
        self.0.clone()
    }
}

/// Name of a network to attach the container to.
///
/// Network modes (`host`, `none`, `container:...`, and Podman's `slirp4netns`, `pasta`,
/// `private`, `ns:...`) are not network names: `host` and `none` are expressed with the `Host`
/// and `Isolated` networking variants of each attribute, the others are not supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NetworkName(String);

impl TryFrom<String> for NetworkName {
    type Error = RegentError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.is_empty() {
            Err(invalid("network name", &name, "must be non-empty"))
        } else if name == "host" || name == "none" {
            Err(invalid(
                "network name",
                &name,
                "use the Host or Isolated networking instead",
            ))
        } else if ["slirp4netns", "pasta", "private"].contains(&name.as_str())
            || name.starts_with("slirp4netns:")
            || name.starts_with("pasta:")
            || name.starts_with("ns:")
            || name.starts_with("container:")
        {
            Err(invalid(
                "network name",
                &name,
                "this is a network mode, not a network, and is not supported",
            ))
        } else {
            Ok(Self(name))
        }
    }
}

impl NetworkName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn as_string(&self) -> String {
        self.0.clone()
    }
}

/// Non-empty list of networks (the first one is used at creation, the others are connected afterwards)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<NetworkName>", into = "Vec<NetworkName>")]
pub struct NetworkList(Vec<NetworkName>);

impl TryFrom<Vec<NetworkName>> for NetworkList {
    type Error = RegentError;

    fn try_from(networks: Vec<NetworkName>) -> Result<Self, Self::Error> {
        if networks.is_empty() {
            Err(RegentError::IncoherentExpectedState(
                "Networks can't be empty, omit it to keep the default network".to_string(),
            ))
        } else {
            Ok(Self(networks))
        }
    }
}

impl From<NetworkList> for Vec<NetworkName> {
    fn from(networks: NetworkList) -> Vec<NetworkName> {
        networks.0
    }
}

impl NetworkList {
    pub fn networks(&self) -> &[NetworkName] {
        &self.0
    }

    /// Appends a network to a list, which is created if needed
    pub(super) fn add(networks: Option<NetworkList>, network: NetworkName) -> NetworkList {
        let mut networks = networks.map(Vec::from).unwrap_or_default();
        networks.push(network);
        NetworkList(networks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PortBinding {
    /// As found in `HostConfig.PortBindings` keys, e.g. `80/tcp`
    pub(super) container_port: String,
    pub(super) host_ip: String,
    /// Empty when the engine picks a random port
    pub(super) host_port: String,
}

/// Published port(s), CLI syntax: `[ip:][host_port:]container_port[/protocol]`.
/// Port ranges (`8000-8010:8000-8010`) are supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublishedPort {
    spec: String,
    /// Bindings as the engines store them (ranges expanded)
    bindings: Vec<PortBinding>,
}

impl TryFrom<String> for PublishedPort {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let error = |details: &str| invalid("port", &spec, details);

        let (mapping, protocol) = match spec.rsplit_once('/') {
            Some((mapping, protocol)) => (mapping, protocol.to_lowercase()),
            None => (spec.as_str(), "tcp".to_string()),
        };
        if !["tcp", "udp", "sctp"].contains(&protocol.as_str()) {
            return Err(error("protocol must be tcp, udp or sctp"));
        }

        let (host_part, container_part) = match mapping.rsplit_once(':') {
            Some((host_part, container_part)) => (Some(host_part), container_part),
            None => (None, mapping),
        };
        let (host_ip, host_port_part) = match host_part {
            Some(host_part) => match host_part.rsplit_once(':') {
                Some((host_ip, host_port)) => (
                    host_ip.trim_start_matches('[').trim_end_matches(']'),
                    host_port,
                ),
                None => ("", host_part),
            },
            None => ("", ""),
        };
        if !host_ip.is_empty() && host_ip.parse::<IpAddr>().is_err() {
            return Err(error("invalid host IP address"));
        }

        let parse_range = |range: &str| -> Result<(u16, u16), RegentError> {
            let (start, end) = range.split_once('-').unwrap_or((range, range));
            let start: u16 = start.parse().map_err(|_| error("invalid port number"))?;
            let end: u16 = end.parse().map_err(|_| error("invalid port number"))?;
            if start == 0 || end < start {
                return Err(error("invalid port range"));
            }
            Ok((start, end))
        };

        let (container_start, container_end) = parse_range(container_part)?;
        let container_ports: Vec<u16> = (container_start..=container_end).collect();

        let host_ports: Vec<String> = if host_port_part.is_empty() {
            vec![String::new(); container_ports.len()]
        } else {
            let (host_start, host_end) = parse_range(host_port_part)?;
            if host_end - host_start != container_end - container_start {
                return Err(error(
                    "host and container port ranges must have the same size",
                ));
            }
            (host_start..=host_end)
                .map(|port| port.to_string())
                .collect()
        };

        let bindings = container_ports
            .into_iter()
            .zip(host_ports)
            .map(|(container_port, host_port)| PortBinding {
                container_port: format!("{}/{}", container_port, protocol),
                host_ip: host_ip.to_string(),
                host_port,
            })
            .collect();

        Ok(Self { spec, bindings })
    }
}

impl PublishedPort {
    pub(super) fn bindings(&self) -> &[PortBinding] {
        &self.bindings
    }

    fn as_string(&self) -> String {
        self.spec.clone()
    }
}

/// Volume, CLI syntax: `source:target[:options]` (bind mount or named volume) or
/// `target` (anonymous volume). The target must be an absolute path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ContainerVolume {
    Bind {
        source: String,
        target: String,
        options: Option<String>,
    },
    Anonymous {
        target: String,
    },
}

impl TryFrom<String> for ContainerVolume {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = spec.split(':').collect();
        let volume = match parts.as_slice() {
            [target] => ContainerVolume::Anonymous {
                target: target.to_string(),
            },
            [source, target] => ContainerVolume::Bind {
                source: source.to_string(),
                target: target.to_string(),
                options: None,
            },
            [source, target, options] if !options.is_empty() => ContainerVolume::Bind {
                source: source.to_string(),
                target: target.to_string(),
                options: Some(options.to_string()),
            },
            _ => {
                return Err(invalid(
                    "volume",
                    &spec,
                    "expected source:target[:options] or target",
                ));
            }
        };

        let (source, target) = match &volume {
            ContainerVolume::Bind { source, target, .. } => (Some(source), target),
            ContainerVolume::Anonymous { target } => (None, target),
        };
        if source.is_some_and(|source| source.is_empty()) {
            return Err(invalid("volume", &spec, "source can't be empty"));
        }
        if !target.starts_with('/') {
            return Err(invalid("volume", &spec, "target must be an absolute path"));
        }

        Ok(volume)
    }
}

impl ContainerVolume {
    fn as_string(&self) -> String {
        match self {
            ContainerVolume::Bind {
                source,
                target,
                options: Some(options),
            } => format!("{}:{}:{}", source, target, options),
            ContainerVolume::Bind {
                source,
                target,
                options: None,
            } => format!("{}:{}", source, target),
            ContainerVolume::Anonymous { target } => target.clone(),
        }
    }
}

/// Linux capability, normalized with the `CAP_` prefix (`CAP_NET_ADMIN`, `ALL`).
/// `net_admin`, `NET_ADMIN` and `CAP_NET_ADMIN` are all accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Capability(String);

impl TryFrom<String> for Capability {
    type Error = RegentError;

    fn try_from(capability: String) -> Result<Self, Self::Error> {
        let normalized = normalize_capability(&capability);
        let name = normalized.trim_start_matches("CAP_");
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            Err(invalid(
                "capability",
                &capability,
                "expected a name like NET_ADMIN",
            ))
        } else {
            Ok(Self(normalized))
        }
    }
}

impl Capability {
    fn as_string(&self) -> String {
        self.0.clone()
    }
}

/// Memory size, CLI syntax (binary units, case-insensitive): `512m`, `1.5g`, `1048576`...
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MemorySize {
    spec: String,
    bytes: i64,
}

impl TryFrom<String> for MemorySize {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let error = || invalid("memory size", &spec, "expected e.g. 512m, 2g");
        let lowercase = spec.trim().to_lowercase();
        let unit_start = lowercase
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(lowercase.len());
        let (number, unit) = lowercase.split_at(unit_start);
        let number: f64 = number.parse().map_err(|_| error())?;
        if unit.len() > 2 {
            return Err(error());
        }
        let multiplier: f64 = match unit.trim_end_matches('b') {
            "" => 1.0,
            "k" => 1024.0,
            "m" => 1024.0_f64.powi(2),
            "g" => 1024.0_f64.powi(3),
            "t" => 1024.0_f64.powi(4),
            "p" => 1024.0_f64.powi(5),
            _ => return Err(error()),
        };
        let bytes = (number * multiplier) as i64;
        if bytes <= 0 {
            return Err(error());
        }
        Ok(Self { spec, bytes })
    }
}

impl MemorySize {
    pub fn bytes(&self) -> i64 {
        self.bytes
    }

    fn as_string(&self) -> String {
        self.spec.clone()
    }
}

/// Number of CPUs, strictly positive (e.g. `1.5`)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct CpuCount(f64);

impl TryFrom<f64> for CpuCount {
    type Error = RegentError;

    fn try_from(cpus: f64) -> Result<Self, Self::Error> {
        if cpus.is_finite() && cpus > 0.0 {
            Ok(Self(cpus))
        } else {
            Err(invalid(
                "number of CPUs",
                &cpus.to_string(),
                "must be strictly positive",
            ))
        }
    }
}

impl From<CpuCount> for f64 {
    fn from(cpus: CpuCount) -> f64 {
        cpus.0
    }
}

impl fmt::Display for CpuCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CpuCount {
    pub(super) fn nano_cpus(&self) -> i64 {
        (self.0 * 1e9).round() as i64
    }
}

/// Requires the NVIDIA Container Toolkit on the host
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum GpuSelection {
    All,
    Devices(GpuList),
}

impl GpuSelection {
    /// GPU identifiers, `all` included, sorted and deduplicated
    pub(super) fn ids(&self) -> BTreeSet<String> {
        match self {
            GpuSelection::All => BTreeSet::from(["all".to_string()]),
            GpuSelection::Devices(gpus) => gpus.0.iter().map(|gpu| gpu.0.clone()).collect(),
        }
    }

    /// Appends a device to a selection: `All` (or no selection) is replaced by this device
    pub(super) fn add_device(selection: Option<GpuSelection>, gpu: GpuId) -> GpuSelection {
        let mut gpus = match selection {
            Some(GpuSelection::Devices(gpus)) => gpus.0,
            Some(GpuSelection::All) | None => Vec::new(),
        };
        gpus.push(gpu);
        GpuSelection::Devices(GpuList(gpus))
    }
}

/// GPU identifier: an index (`0`), a GPU UUID (`GPU-<uuid>`) or a MIG device (`MIG-<uuid>`)
///
/// Indexes can be written as YAML integers (`Devices: [0, 1]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GpuIdRepr", into = "String")]
pub struct GpuId(String);

#[derive(Deserialize)]
#[serde(untagged)]
enum GpuIdRepr {
    Index(u32),
    Id(String),
}

impl TryFrom<GpuIdRepr> for GpuId {
    type Error = RegentError;

    fn try_from(repr: GpuIdRepr) -> Result<Self, Self::Error> {
        match repr {
            GpuIdRepr::Index(index) => Ok(Self(index.to_string())),
            GpuIdRepr::Id(id) => Self::try_from(id),
        }
    }
}

impl TryFrom<String> for GpuId {
    type Error = RegentError;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        let is_index = !id.is_empty() && id.chars().all(|c| c.is_ascii_digit());
        let is_uuid = ["GPU-", "MIG-"].iter().any(|prefix| {
            id.strip_prefix(prefix).is_some_and(|uuid| {
                !uuid.is_empty()
                    && uuid
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '/')
            })
        });
        if is_index || is_uuid {
            Ok(Self(id))
        } else {
            Err(invalid(
                "GPU",
                &id,
                "expected an index (0), GPU-<uuid> or MIG-<uuid>",
            ))
        }
    }
}

impl GpuId {
    fn as_string(&self) -> String {
        self.0.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Vec<GpuId>", into = "Vec<GpuId>")]
pub struct GpuList(Vec<GpuId>);

impl TryFrom<Vec<GpuId>> for GpuList {
    type Error = RegentError;

    fn try_from(gpus: Vec<GpuId>) -> Result<Self, Self::Error> {
        if gpus.is_empty() {
            Err(RegentError::IncoherentExpectedState(
                "GPU list can't be empty, use All or remove the option".to_string(),
            ))
        } else {
            Ok(Self(gpus))
        }
    }
}

impl From<GpuList> for Vec<GpuId> {
    fn from(gpus: GpuList) -> Vec<GpuId> {
        gpus.0
    }
}

impl GpuList {
    pub fn gpus(&self) -> &[GpuId] {
        &self.0
    }
}

/// IPC namespace of the container (`--ipc`)
///
/// Inference servers (vLLM, PyTorch dataloaders, Triton) exchange tensors through shared
/// memory: either share the host IPC namespace, or give the container a bigger `/dev/shm`
/// (64 MiB by default). The size of `/dev/shm` can only be set on a private namespace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpcNamespace {
    /// Share the host IPC namespace and `/dev/shm` (`--ipc host`)
    Host,
    /// Own IPC namespace (`--ipc private`)
    Private(PrivateIpc),
    /// Own IPC namespace which other containers can join (`--ipc shareable`)
    Shareable(PrivateIpc),
}

impl IpcNamespace {
    pub(super) fn mode(&self) -> &'static str {
        match self {
            IpcNamespace::Host => "host",
            IpcNamespace::Private(_) => "private",
            IpcNamespace::Shareable(_) => "shareable",
        }
    }

    pub(super) fn shm_size(&self) -> Option<&MemorySize> {
        match self {
            IpcNamespace::Host => None,
            IpcNamespace::Private(ipc) | IpcNamespace::Shareable(ipc) => ipc.shm_size.as_ref(),
        }
    }

    /// Settings of the container's own namespace, kept when switching between `Private` and
    /// `Shareable` (default settings when the namespace was `Host` or not set)
    fn own_settings(ipc: Option<IpcNamespace>) -> PrivateIpc {
        match ipc {
            Some(IpcNamespace::Private(ipc) | IpcNamespace::Shareable(ipc)) => ipc,
            Some(IpcNamespace::Host) | None => PrivateIpc::new(),
        }
    }

    pub(super) fn private(ipc: Option<IpcNamespace>) -> IpcNamespace {
        IpcNamespace::Private(Self::own_settings(ipc))
    }

    pub(super) fn shareable(ipc: Option<IpcNamespace>) -> IpcNamespace {
        IpcNamespace::Shareable(Self::own_settings(ipc))
    }

    /// Sets the size of `/dev/shm`, keeping a `Shareable` namespace shareable: `Host` (or no
    /// namespace) is replaced by a `Private` namespace
    pub(super) fn with_shm_size(ipc: Option<IpcNamespace>, shm_size: MemorySize) -> IpcNamespace {
        match ipc {
            Some(IpcNamespace::Shareable(ipc)) => {
                IpcNamespace::Shareable(ipc.with_shm_size(shm_size))
            }
            other => IpcNamespace::Private(Self::own_settings(other).with_shm_size(shm_size)),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct PrivateIpc {
    /// Size of `/dev/shm` (`--shm-size`, not managed if omitted)
    shm_size: Option<MemorySize>,
}

impl PrivateIpc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_shm_size(mut self, shm_size: MemorySize) -> Self {
        self.shm_size = Some(shm_size);
        self
    }
}

/// Custom host-to-IP mapping: `hostname:ip` (`ip` can also be `host-gateway`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExtraHost {
    hostname: String,
    /// IP address in canonical form, or `host-gateway`
    address: String,
}

impl TryFrom<String> for ExtraHost {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let error = || invalid("extra host", &spec, "expected hostname:ip");
        let (hostname, address) = spec.split_once(':').ok_or_else(error)?;
        let address = if address == "host-gateway" {
            address.to_string()
        } else {
            address
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .map_err(|_| error())?
                .to_string()
        };
        if hostname.is_empty() {
            return Err(error());
        }
        Ok(Self {
            hostname: hostname.to_string(),
            address,
        })
    }
}

impl ExtraHost {
    fn as_string(&self) -> String {
        format!("{}:{}", self.hostname, self.address)
    }
}

/// Host device, CLI syntax: `host_path[:container_path[:permissions]]`
/// (container path defaults to the host path, permissions to `rwm`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostDevice {
    host_path: String,
    container_path: String,
    permissions: String,
}

impl TryFrom<String> for HostDevice {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = spec.split(':').collect();
        let (host_path, container_path, permissions) = match parts.as_slice() {
            [host_path] => (*host_path, *host_path, "rwm"),
            [host_path, container_path] => (*host_path, *container_path, "rwm"),
            [host_path, container_path, permissions] => (*host_path, *container_path, *permissions),
            _ => ("", "", ""),
        };
        if !host_path.starts_with('/')
            || !container_path.starts_with('/')
            || permissions.is_empty()
            || !permissions.chars().all(|c| "rwm".contains(c))
        {
            return Err(invalid(
                "device",
                &spec,
                "expected /host/path[:/container/path[:permissions]]",
            ));
        }
        Ok(Self {
            host_path: host_path.to_string(),
            container_path: container_path.to_string(),
            permissions: permissions.to_string(),
        })
    }
}

impl HostDevice {
    fn as_string(&self) -> String {
        format!(
            "{}:{}:{}",
            self.host_path, self.container_path, self.permissions
        )
    }
}

/// `docker|podman container inspect` returns a JSON array. Anything before it (warnings) is skipped.
pub(super) fn parse_inspect_output(output: &str) -> Option<Value> {
    let start = output.find('[')?;
    let array: Value = serde_json::Deserializer::from_str(&output[start..])
        .into_iter::<Value>()
        .next()?
        .ok()?;
    array.as_array()?.first().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_are_parsed_like_the_cli() {
        let bindings = |spec: &str| spec.parse::<PublishedPort>().map(|port| port.bindings);
        let binding = |container_port: &str, host_ip: &str, host_port: &str| PortBinding {
            container_port: container_port.to_string(),
            host_ip: host_ip.to_string(),
            host_port: host_port.to_string(),
        };
        assert_eq!(bindings("80").unwrap(), vec![binding("80/tcp", "", "")]);
        assert_eq!(
            bindings("8080:80/udp").unwrap(),
            vec![binding("80/udp", "", "8080")]
        );
        assert_eq!(
            bindings("127.0.0.1::80").unwrap(),
            vec![binding("80/tcp", "127.0.0.1", "")]
        );
        assert_eq!(
            bindings("[::1]:8080:80").unwrap(),
            vec![binding("80/tcp", "::1", "8080")]
        );
        assert_eq!(
            bindings("8000-8001:9000-9001").unwrap(),
            vec![
                binding("9000/tcp", "", "8000"),
                binding("9001/tcp", "", "8001")
            ]
        );
        assert!(bindings("8000-8002:9000-9001").is_err());
        assert!(bindings("80:80/icmp").is_err());
        assert!(bindings("http").is_err());
        assert!(bindings("localhost:8080:80").is_err());
    }

    #[test]
    fn value_types_are_normalized() {
        let bytes = |spec: &str| spec.parse::<MemorySize>().map(|memory| memory.bytes());
        assert_eq!(bytes("1024").unwrap(), 1024);
        assert_eq!(bytes("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(bytes("512MB").unwrap(), 512 * 1024 * 1024);
        assert_eq!(bytes("1.5g").unwrap(), 1536 * 1024 * 1024);
        assert!(bytes("12x").is_err());
        assert!(bytes("").is_err());

        let capability = |spec: &str| spec.parse::<Capability>().unwrap().to_string();
        assert_eq!(capability("net_admin"), "CAP_NET_ADMIN");
        assert_eq!(capability("CAP_NET_ADMIN"), "CAP_NET_ADMIN");
        assert_eq!(capability("all"), "ALL");

        let device = |spec: &str| spec.parse::<HostDevice>().unwrap().to_string();
        assert_eq!(device("/dev/snd"), "/dev/snd:/dev/snd:rwm");
        assert_eq!(device("/dev/sda:/dev/xvda:r"), "/dev/sda:/dev/xvda:r");
    }

    #[test]
    fn inspect_output_is_parsed_despite_warnings() {
        let output = "WARNING: something\n[{\"Name\": \"/web\"}]\n";
        assert_eq!(
            parse_inspect_output(output).unwrap(),
            serde_json::json!({ "Name": "/web" })
        );
        assert!(parse_inspect_output("[]").is_none());
    }
}
