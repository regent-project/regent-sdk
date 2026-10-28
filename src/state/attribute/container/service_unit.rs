//! Systemd service units running a container in the foreground
//!
//! Shared by the [`apptainer`](super::apptainer) and [`enroot`](super::enroot) attributes:
//! these engines have no daemon keeping containers alive, so a long-running container is
//! managed as a systemd service unit running it in the foreground. Systemd then provides the
//! restart policy, the start at boot and the logs (journald).
//!
//! # Unit scope
//!
//! The scope is decided at assessment time by running `id -u` with the attribute's privilege:
//!
//! - uid 0: **system unit** in `/etc/systemd/system/`, managed with `systemctl`.
//! - any other uid: **user unit** in `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/`, managed
//!   with `systemctl --user`. Lingering is required so that the service runs without an open
//!   session and starts at boot: it is enabled (`loginctl enable-linger`) when the service must
//!   be running.
//!
//! # Files
//!
//! - The unit: `regent-<engine>-<name>.service`. It holds no environment variable value, as unit
//!   files are world-readable and exposed by `systemctl show`.
//! - The environment file, mode 0600, referenced by `EnvironmentFile=`:
//!   `/etc/regent-sdk/<engine>/<name>.env` (system) or
//!   `${XDG_CONFIG_HOME:-$HOME/.config}/regent-sdk/<engine>/<name>.env` (user).
//!
//! Drift is detected by comparing both files with their expected content, rendered
//! deterministically. Values of environment variables never appear in remediation messages.

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use super::container_spec::{ContainerName, invalid, quoted_command};

/// Seconds systemd waits for the container to stop before killing it
const TIMEOUT_STOP_SEC: u32 = 60;
/// Seconds systemd waits before restarting a failed container
const RESTART_SEC: u32 = 5;

const HEADER: &str = "# Managed by regent-sdk: manual changes will be overwritten";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceEngine {
    Apptainer,
    Enroot,
}

impl ServiceEngine {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceEngine::Apptainer => "apptainer",
            ServiceEngine::Enroot => "enroot",
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            ServiceEngine::Apptainer => "Apptainer",
            ServiceEngine::Enroot => "Enroot",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum UnitScope {
    /// System manager (`systemctl`), when running as root
    System,
    /// User manager of the connected user (`systemctl --user`)
    User,
}

/// `Restart=`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum UnitRestartPolicy {
    No,
    #[default]
    OnFailure,
    Always,
}

impl UnitRestartPolicy {
    fn as_directive(&self) -> &'static str {
        match self {
            UnitRestartPolicy::No => "no",
            UnitRestartPolicy::OnFailure => "on-failure",
            UnitRestartPolicy::Always => "always",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceUnitId {
    engine: ServiceEngine,
    name: ContainerName,
    scope: UnitScope,
}

/// As a shell expression
const USER_CONFIG_ROOT: &str = "\"${XDG_CONFIG_HOME:-$HOME/.config}\"";

impl ServiceUnitId {
    pub fn new(engine: ServiceEngine, name: ContainerName, scope: UnitScope) -> Self {
        Self {
            engine,
            name,
            scope,
        }
    }

    pub fn name(&self) -> &ContainerName {
        &self.name
    }

    pub fn scope(&self) -> UnitScope {
        self.scope
    }

    /// `regent-<engine>-<name>.service`
    pub fn unit_name(&self) -> String {
        format!("regent-{}-{}.service", self.engine.as_str(), self.name)
    }

    fn config_root(&self) -> &'static str {
        match self.scope {
            UnitScope::System => "/etc",
            UnitScope::User => USER_CONFIG_ROOT,
        }
    }

    /// As a shell expression
    pub(super) fn unit_path(&self) -> String {
        let directory = match self.scope {
            UnitScope::System => "/etc/systemd/system".to_string(),
            UnitScope::User => format!("{}/systemd/user", USER_CONFIG_ROOT),
        };
        format!("{}/{}", directory, shell_quote(&self.unit_name()))
    }

    /// As a shell expression
    pub(super) fn regent_dir(&self) -> String {
        format!("{}/regent-sdk/{}", self.config_root(), self.engine.as_str())
    }

    /// As a shell expression
    pub(super) fn regent_file(&self, extension: &str) -> String {
        format!(
            "{}/{}",
            self.regent_dir(),
            shell_quote(&format!("{}.{}", self.name, extension))
        )
    }

    /// As a shell expression
    pub(super) fn env_path(&self) -> String {
        self.regent_file("env")
    }

    /// As written in the unit (`%E` is the configuration directory of the user manager)
    fn env_path_in_unit(&self) -> String {
        let root = match self.scope {
            UnitScope::System => "/etc",
            UnitScope::User => "%E",
        };
        format!(
            "{}/regent-sdk/{}/{}.env",
            root,
            self.engine.as_str(),
            self.name
        )
    }

    /// `systemctl [--user] <args>` as a shell command
    pub(super) fn systemctl(&self, args: &[&str]) -> String {
        match self.scope {
            UnitScope::System => {
                let mut command = vec!["systemctl"];
                command.extend_from_slice(args);
                quoted_command(&command)
            }
            UnitScope::User => {
                let mut command = vec!["systemctl", "--user"];
                command.extend_from_slice(args);
                // The user manager is found through XDG_RUNTIME_DIR, which is not set in every
                // kind of session (su, sudo)
                format!(
                    "XDG_RUNTIME_DIR=\"${{XDG_RUNTIME_DIR:-/run/user/$(id -u)}}\" {}",
                    quoted_command(&command)
                )
            }
        }
    }
}

impl fmt::Display for ServiceUnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            UnitScope::System => write!(f, "{}", self.unit_name()),
            UnitScope::User => write!(f, "{} (user unit)", self.unit_name()),
        }
    }
}

pub(super) struct UnitSpec {
    /// Command line run in the foreground (absolute executable path first)
    pub(super) exec_start: Vec<String>,
    /// Variables set with `Environment=` (never secrets: the unit is world-readable)
    pub(super) environment: Vec<(String, String)>,
    pub(super) restart: UnitRestartPolicy,
}

/// Deterministic: the same spec always gives the same content
pub(super) fn render_unit(id: &ServiceUnitId, spec: &UnitSpec) -> String {
    let mut unit = String::new();
    let mut line = |text: String| {
        unit.push_str(&text);
        unit.push('\n');
    };

    line(HEADER.to_string());
    line("[Unit]".to_string());
    line(format!(
        "Description={} container {} (regent-sdk)",
        id.engine.display_name(),
        id.name
    ));
    // network-online.target only exists in the system manager
    if id.scope == UnitScope::System {
        line("Wants=network-online.target".to_string());
        line("After=network-online.target".to_string());
    }
    line(String::new());
    line("[Service]".to_string());
    line("Type=simple".to_string());
    for (key, value) in &spec.environment {
        line(format!(
            "Environment={}",
            systemd_quote(&format!("{}={}", key, value))
        ));
    }
    line(format!("EnvironmentFile={}", id.env_path_in_unit()));
    line(format!(
        "ExecStart={}",
        spec.exec_start
            .iter()
            .map(|arg| systemd_quote(arg))
            .collect::<Vec<String>>()
            .join(" ")
    ));
    line(format!("Restart={}", spec.restart.as_directive()));
    line(format!("RestartSec={}", RESTART_SEC));
    line(format!("TimeoutStopSec={}", TIMEOUT_STOP_SEC));
    line(String::new());
    line("[Install]".to_string());
    line(format!(
        "WantedBy={}",
        match id.scope {
            UnitScope::System => "multi-user.target",
            UnitScope::User => "default.target",
        }
    ));

    unit
}

/// Quote a word of a systemd command line (`ExecStart=`, `Environment=`).
///
/// Words made of safe characters are left as is, the others are double-quoted with `\` and `"`
/// escaped. Specifiers (`%`) and variable expansion (`$`) are disabled by doubling them.
pub(super) fn systemd_quote(arg: &str) -> String {
    let escaped = arg.replace('%', "%%").replace('$', "$$");
    let is_safe = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+=:,@".contains(c));
    if is_safe {
        return escaped;
    }
    let mut quoted = String::with_capacity(escaped.len() + 2);
    quoted.push('"');
    for c in escaped.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// Render the environment file read through `EnvironmentFile=` (values double-quoted, with
/// `\`, `"`, `$` and `` ` `` escaped so they are taken literally)
pub(super) fn render_env_file(entries: &[(String, String)]) -> String {
    let mut content = format!("{}\n", HEADER);
    for (key, value) in entries {
        content.push_str(&format!("{}={}\n", key, env_file_quote(value)));
    }
    content
}

fn env_file_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// Name of an environment variable passed to a service: `[A-Za-z_][A-Za-z0-9_]*`.
///
/// Stricter than the container engines' variable names, as it must be valid in a systemd
/// environment file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceEnvVarName(String);

impl TryFrom<String> for ServiceEnvVarName {
    type Error = RegentError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        let is_valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if is_valid {
            Ok(Self(name))
        } else {
            Err(invalid(
                "environment variable name",
                &name,
                "allowed characters are [A-Za-z_][A-Za-z0-9_]*",
            ))
        }
    }
}

impl FromStr for ServiceEnvVarName {
    type Err = RegentError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::try_from(name.to_string())
    }
}

impl From<ServiceEnvVarName> for String {
    fn from(name: ServiceEnvVarName) -> String {
        name.0
    }
}

impl fmt::Display for ServiceEnvVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ServiceEnvVarName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Absolute path on the host (no trailing `/`, no line break)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AbsolutePath(String);

impl TryFrom<String> for AbsolutePath {
    type Error = RegentError;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        if !path.starts_with('/') {
            Err(invalid("path", &path, "must be absolute"))
        } else if path.len() > 1 && path.ends_with('/') {
            Err(invalid("path", &path, "must not end with '/'"))
        } else if path.chars().any(char::is_control) {
            Err(invalid(
                "path",
                &path,
                "must not contain control characters",
            ))
        } else {
            Ok(Self(path))
        }
    }
}

impl FromStr for AbsolutePath {
    type Err = RegentError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::try_from(path.to_string())
    }
}

impl From<AbsolutePath> for String {
    fn from(path: AbsolutePath) -> String {
        path.0
    }
}

impl fmt::Display for AbsolutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AbsolutePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parent directory (`/` for a file at the root)
    pub(super) fn parent(&self) -> &str {
        match self.0.rfind('/') {
            Some(0) | None => "/",
            Some(index) => &self.0[..index],
        }
    }
}

/// Host directory or file mounted in the container: `source[:target[:ro|rw]]`.
///
/// Both paths are absolute, the target defaults to the source and the mount is read-write
/// unless `ro` is given. Paths can't contain `:`, `,` or whitespace, as the engines use them as
/// separators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BindMount {
    source: String,
    target: String,
    read_only: bool,
}

impl TryFrom<String> for BindMount {
    type Error = RegentError;

    fn try_from(spec: String) -> Result<Self, Self::Error> {
        let error = |details: &str| invalid("bind mount", &spec, details);
        let parts: Vec<&str> = spec.split(':').collect();
        let (source, target, read_only) = match parts.as_slice() {
            [source] => (*source, *source, false),
            [source, target] => (*source, *target, false),
            [source, target, "ro"] => (*source, *target, true),
            [source, target, "rw"] => (*source, *target, false),
            [_, _, _] => return Err(error("options must be ro or rw")),
            _ => return Err(error("expected source[:target[:ro|rw]]")),
        };
        for path in [source, target] {
            if !path.starts_with('/') {
                return Err(error("paths must be absolute"));
            }
            if path.chars().any(|c| c == ',' || c.is_whitespace()) {
                return Err(error("paths can't contain ',' or whitespace"));
            }
        }
        Ok(Self {
            source: source.to_string(),
            target: target.to_string(),
            read_only,
        })
    }
}

impl FromStr for BindMount {
    type Err = RegentError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        Self::try_from(spec.to_string())
    }
}

impl From<BindMount> for String {
    fn from(mount: BindMount) -> String {
        mount.to_string()
    }
}

impl fmt::Display for BindMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.source,
            self.target,
            if self.read_only { "ro" } else { "rw" }
        )
    }
}

impl BindMount {
    /// `--bind` value of Apptainer: `src:dest:ro|rw`
    pub(super) fn apptainer_arg(&self) -> String {
        self.to_string()
    }

    /// `--mount` value of Enroot: an fstab entry with colon-separated fields
    pub(super) fn enroot_arg(&self) -> String {
        format!(
            "{}:{}:none:x-create=auto,rbind{}",
            self.source,
            self.target,
            if self.read_only { ",ro" } else { "" }
        )
    }
}

/// State of the unit, from `systemctl show`
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct UnitStatus {
    pub(super) load_state: String,
    pub(super) active_state: String,
    pub(super) unit_file_state: String,
    pub(super) need_daemon_reload: bool,
}

impl UnitStatus {
    /// Running, or about to
    pub(super) fn is_active(&self) -> bool {
        matches!(
            self.active_state.as_str(),
            "active" | "activating" | "reloading"
        )
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.unit_file_state == "enabled"
    }

    /// Parse `Key=Value` lines (other lines, such as warnings, are ignored)
    pub(super) fn parse(output: &str) -> Self {
        let mut status = UnitStatus::default();
        for line in output.lines() {
            match line.trim().split_once('=') {
                Some(("LoadState", value)) => status.load_state = value.to_string(),
                Some(("ActiveState", value)) => status.active_state = value.to_string(),
                Some(("UnitFileState", value)) => status.unit_file_state = value.to_string(),
                Some(("NeedDaemonReload", value)) => status.need_daemon_reload = value == "yes",
                _ => {}
            }
        }
        status
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct ObservedService {
    pub(super) unit_file: Option<String>,
    pub(super) env_file: Option<String>,
    pub(super) status: UnitStatus,
    /// Lingering of the user (`None` for system units, or when not needed)
    pub(super) linger: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceUnitAction {
    /// Let the user manager run without an open session and start at boot
    EnableLinger,
    DaemonReload,
    Enable,
    Disable,
    Start,
    Stop,
    Restart,
    Remove,
}

impl ServiceUnitAction {
    pub(super) fn command(&self, id: &ServiceUnitId) -> String {
        let unit_name = id.unit_name();
        let unit = unit_name.as_str();
        match self {
            ServiceUnitAction::EnableLinger => "loginctl enable-linger \"$(id -un)\"".to_string(),
            ServiceUnitAction::DaemonReload => id.systemctl(&["daemon-reload"]),
            ServiceUnitAction::Enable => id.systemctl(&["enable", unit]),
            ServiceUnitAction::Disable => id.systemctl(&["disable", unit]),
            ServiceUnitAction::Start => id.systemctl(&["start", unit]),
            ServiceUnitAction::Stop => id.systemctl(&["stop", unit]),
            ServiceUnitAction::Restart => id.systemctl(&["restart", unit]),
            ServiceUnitAction::Remove => format!(
                // Stopping or disabling a unit which is not loaded fails: ignored
                "{{ {} >/dev/null 2>&1; {} >/dev/null 2>&1; rm -f {} {} && {}; }}",
                id.systemctl(&["stop", unit]),
                id.systemctl(&["disable", unit]),
                id.unit_path(),
                id.env_path(),
                id.systemctl(&["daemon-reload"]),
            ),
        }
    }

    pub(super) fn display(&self, id: &ServiceUnitId) -> String {
        match self {
            ServiceUnitAction::EnableLinger => {
                format!("Enable lingering of the user running {}", id)
            }
            ServiceUnitAction::DaemonReload => format!("Reload systemd units for {}", id),
            ServiceUnitAction::Enable => format!("Enable {}", id),
            ServiceUnitAction::Disable => format!("Disable {}", id),
            ServiceUnitAction::Start => format!("Start {}", id),
            ServiceUnitAction::Stop => format!("Stop {}", id),
            ServiceUnitAction::Restart => format!("Restart {}", id),
            ServiceUnitAction::Remove => {
                format!("Remove {} and its environment file", id)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum ServiceStep {
    WriteFiles(Vec<String>),
    Action(ServiceUnitAction),
}

/// Plan the steps bringing a unit which must exist to its expected state.
///
/// `container_changed` tells that the container behind the unit is being replaced (new image,
/// recreated container), which requires a restart when it must run.
pub(super) fn plan_service(
    should_run: bool,
    expected_unit: &str,
    expected_env: &str,
    observed: &ObservedService,
    container_changed: bool,
) -> Vec<ServiceStep> {
    let mut steps = Vec::new();

    if should_run && observed.linger == Some(false) {
        steps.push(ServiceStep::Action(ServiceUnitAction::EnableLinger));
    }

    let mut reasons = Vec::new();
    for (file, current, expected) in [
        ("unit file", &observed.unit_file, expected_unit),
        ("environment file", &observed.env_file, expected_env),
    ] {
        match current {
            None => reasons.push(format!("{} is missing", file)),
            // Never show the content: the environment file holds secrets
            Some(current) if current != expected => reasons.push(format!("{} differs", file)),
            Some(_) => {}
        }
    }
    let files_changed = !reasons.is_empty();
    if files_changed {
        steps.push(ServiceStep::WriteFiles(reasons));
    } else if observed.status.need_daemon_reload {
        steps.push(ServiceStep::Action(ServiceUnitAction::DaemonReload));
    }

    let is_active = observed.status.is_active();
    let is_enabled = observed.status.is_enabled();
    if should_run {
        if !is_enabled {
            steps.push(ServiceStep::Action(ServiceUnitAction::Enable));
        }
        if !is_active {
            steps.push(ServiceStep::Action(ServiceUnitAction::Start));
        } else if files_changed || container_changed {
            steps.push(ServiceStep::Action(ServiceUnitAction::Restart));
        }
    } else {
        if is_enabled {
            steps.push(ServiceStep::Action(ServiceUnitAction::Disable));
        }
        if is_active {
            steps.push(ServiceStep::Action(ServiceUnitAction::Stop));
        }
    }

    steps
}

/// A unit which must not exist only needs removing if one of its files is still there
pub(super) fn needs_removal(observed: &ObservedService) -> bool {
    observed.unit_file.is_some() || observed.env_file.is_some()
}

pub(super) async fn detect_scope<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<(UnitScope, String), RegentError> {
    let result = host_handler
        .run_command(
            "printf 'regent-uid=%s\\nregent-home=%s\\n' \"$(id -u)\" \"$HOME\"",
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to get the user id: {:?}", e))
        })?;
    parse_scope_probe(&result.stdout).ok_or_else(|| {
        RegentError::FailedDryRunEvaluation(format!("Unable to get the user id: {:?}", result))
    })
}

fn parse_scope_probe(output: &str) -> Option<(UnitScope, String)> {
    let mut uid = None;
    let mut home = String::new();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("regent-uid=") {
            uid = value.trim().parse::<u32>().ok();
        } else if let Some(value) = line.strip_prefix("regent-home=") {
            home = value.to_string();
        }
    }
    let scope = match uid? {
        0 => UnitScope::System,
        _ => UnitScope::User,
    };
    Some((scope, home))
}

/// Whether lingering is enabled for the connected user (a user unknown to logind has none)
pub(super) async fn is_linger_enabled<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<bool, RegentError> {
    let result = host_handler
        .run_command(
            "loginctl show-user \"$(id -un)\" -p Linger --value",
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to check lingering: {:?}", e))
        })?;
    Ok(parse_linger(&result.stdout))
}

fn parse_linger(output: &str) -> bool {
    output.lines().any(|line| line.trim() == "yes")
}

const FILE_PRESENT: &str = "regent-file-present\n";
const FILE_MISSING: &str = "regent-file-missing";
const FILE_END: &str = "\nregent-file-end";

/// Read a file given as a shell expression. Returns `None` if it doesn't exist.
///
/// Error messages never contain the file content (environment files hold secrets).
pub(super) async fn read_optional_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
    description: &str,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let command = format!(
        "if [ -e {path} ]; then printf 'regent-file-present\\n' && cat {path} && printf '\\nregent-file-end\\n'; else printf 'regent-file-missing\\n'; fi",
        path = path
    );
    let result = host_handler
        .run_command(&command, privilege)
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!(
                "Unable to read the {}: {:?}",
                description, e
            ))
        })?;
    if result.return_code != 0 {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unable to read the {} (return code {})",
            description, result.return_code
        )));
    }
    parse_file_probe(&result.stdout).ok_or_else(|| {
        RegentError::FailureToParseContent(format!(
            "Unexpected output while reading the {}",
            description
        ))
    })
}

fn parse_file_probe(output: &str) -> Option<Option<String>> {
    match output.find(FILE_PRESENT) {
        Some(start) => {
            let content = &output[start + FILE_PRESENT.len()..];
            let end = content.rfind(FILE_END)?;
            Some(Some(content[..end].to_string()))
        }
        None if output.contains(FILE_MISSING) => Some(None),
        None => None,
    }
}

/// `systemctl [--user] show` the unit
pub(super) async fn unit_status<Handler: HostHandler>(
    host_handler: &mut Handler,
    id: &ServiceUnitId,
    privilege: &Privilege,
) -> Result<UnitStatus, RegentError> {
    let unit = id.unit_name();
    let command = id.systemctl(&[
        "show",
        &unit,
        "-p",
        "LoadState",
        "-p",
        "ActiveState",
        "-p",
        "UnitFileState",
        "-p",
        "NeedDaemonReload",
    ]);
    let result = host_handler
        .run_command(&command, privilege)
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to query {}: {:?}", id, e))
        })?;
    if result.return_code != 0 {
        return Err(RegentError::FailedDryRunEvaluation(format!(
            "Unable to query {}: {:?}",
            id, result
        )));
    }
    Ok(UnitStatus::parse(&result.stdout))
}

pub(super) async fn observe_service<Handler: HostHandler>(
    host_handler: &mut Handler,
    id: &ServiceUnitId,
    check_linger: bool,
    privilege: &Privilege,
) -> Result<ObservedService, RegentError> {
    let unit_file =
        read_optional_file(host_handler, &id.unit_path(), "unit file", privilege).await?;
    let env_file =
        read_optional_file(host_handler, &id.env_path(), "environment file", privilege).await?;
    let status = unit_status(host_handler, id, privilege).await?;
    let linger = if check_linger && id.scope == UnitScope::User {
        Some(is_linger_enabled(host_handler, privilege).await?)
    } else {
        None
    };
    Ok(ObservedService {
        unit_file,
        env_file,
        status,
        linger,
    })
}

/// Shell command writing the unit and environment files, then reloading systemd.
///
/// The environment file is created with mode 0600 in a 0700 directory.
pub(super) fn write_files_command(id: &ServiceUnitId, unit: &str, env: &str) -> String {
    let unit_path = id.unit_path();
    let unit_dir = match id.scope {
        UnitScope::System => "/etc/systemd/system".to_string(),
        UnitScope::User => format!("{}/systemd/user", USER_CONFIG_ROOT),
    };
    format!(
        "(umask 077 && mkdir -p {regent_dir} && printf '%s' {env} > {env_path} && chmod 600 {env_path}) && \
mkdir -p {unit_dir} && printf '%s' {unit} > {unit_path} && chmod 644 {unit_path} && {reload}",
        regent_dir = id.regent_dir(),
        env = shell_quote(env),
        env_path = id.env_path(),
        unit_dir = unit_dir,
        unit = shell_quote(unit),
        unit_path = unit_path,
        reload = id.systemctl(&["daemon-reload"]),
    )
}

/// Resolve the absolute path of an executable (systemd needs it in `ExecStart=`)
pub(super) async fn resolve_executable<Handler: HostHandler>(
    host_handler: &mut Handler,
    executable: &str,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let result = host_handler
        .run_command(
            &format!("command -v {}", shell_quote(executable)),
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!(
                "Unable to look for {}: {:?}",
                executable, e
            ))
        })?;
    if result.return_code != 0 {
        return Ok(None);
    }
    Ok(result
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with('/'))
        .map(String::from))
}

pub(super) async fn file_exists<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &AbsolutePath,
    privilege: &Privilege,
) -> Result<bool, RegentError> {
    let result = host_handler
        .run_command(
            &format!("test -f {}", shell_quote(path.as_str())),
            privilege,
        )
        .await
        .map_err(|e| {
            RegentError::FailedDryRunEvaluation(format!("Unable to check {}: {:?}", path, e))
        })?;
    Ok(result.return_code == 0)
}

/// Run a remediation command. `show_output` must be false when the command may print secrets.
pub(super) async fn run_remediation<Handler: HostHandler>(
    host_handler: &mut Handler,
    command: &str,
    privilege: &Privilege,
    show_output: bool,
) -> Result<InternalApiCallOutcome, RegentError> {
    match host_handler.run_command(command, privilege).await {
        Ok(result) if result.return_code == 0 => Ok(InternalApiCallOutcome::Success(None)),
        Ok(result) if show_output => Ok(InternalApiCallOutcome::Failure(format!(
            "RC: {}, STDOUT: {}, STDERR: {}",
            result.return_code, result.stdout, result.stderr
        ))),
        Ok(result) => Ok(InternalApiCallOutcome::Failure(format!(
            "RC: {} (output hidden as it may contain secrets)",
            result.return_code
        ))),
        Err(e) if show_output => Ok(InternalApiCallOutcome::Failure(format!(
            "Command execution failed: {:?}",
            e
        ))),
        Err(_) => Ok(InternalApiCallOutcome::Failure(
            "Command execution failed (details hidden as they may contain secrets)".to_string(),
        )),
    }
}

pub(super) async fn run_action<Handler: HostHandler>(
    host_handler: &mut Handler,
    id: &ServiceUnitId,
    action: ServiceUnitAction,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    run_remediation(host_handler, &action.command(id), privilege, true).await
}

/// Write the unit and environment files. Failures don't show the command output.
pub(super) async fn write_files<Handler: HostHandler>(
    host_handler: &mut Handler,
    id: &ServiceUnitId,
    unit: &str,
    env: &str,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    run_remediation(
        host_handler,
        &write_files_command(id, unit, env),
        privilege,
        false,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(scope: UnitScope) -> ServiceUnitId {
        ServiceUnitId::new(ServiceEngine::Apptainer, "vllm".parse().unwrap(), scope)
    }

    fn spec() -> UnitSpec {
        UnitSpec {
            exec_start: vec![
                "/usr/bin/apptainer".to_string(),
                "run".to_string(),
                "--nv".to_string(),
                "/opt/images/vllm 0.6.sif".to_string(),
            ],
            environment: vec![("HOME".to_string(), "/root".to_string())],
            restart: UnitRestartPolicy::OnFailure,
        }
    }

    #[test]
    fn system_unit_is_rendered_deterministically() {
        assert_eq!(
            render_unit(&id(UnitScope::System), &spec()),
            "# Managed by regent-sdk: manual changes will be overwritten
[Unit]
Description=Apptainer container vllm (regent-sdk)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=HOME=/root
EnvironmentFile=/etc/regent-sdk/apptainer/vllm.env
ExecStart=/usr/bin/apptainer run --nv \"/opt/images/vllm 0.6.sif\"
Restart=on-failure
RestartSec=5
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
"
        );
    }

    #[test]
    fn user_unit_uses_the_user_manager_paths() {
        let unit = render_unit(&id(UnitScope::User), &spec());
        assert!(unit.contains("EnvironmentFile=%E/regent-sdk/apptainer/vllm.env\n"));
        assert!(unit.contains("WantedBy=default.target\n"));
        assert!(!unit.contains("network-online.target"));

        let user = id(UnitScope::User);
        assert_eq!(
            user.unit_path(),
            "\"${XDG_CONFIG_HOME:-$HOME/.config}\"/systemd/user/'regent-apptainer-vllm.service'"
        );
        assert_eq!(
            user.env_path(),
            "\"${XDG_CONFIG_HOME:-$HOME/.config}\"/regent-sdk/apptainer/'vllm.env'"
        );
        assert_eq!(
            user.systemctl(&["start", "x.service"]),
            "XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR:-/run/user/$(id -u)}\" 'systemctl' '--user' 'start' 'x.service'"
        );
        assert_eq!(
            id(UnitScope::System).unit_path(),
            "/etc/systemd/system/'regent-apptainer-vllm.service'"
        );
    }

    #[test]
    fn exec_start_arguments_are_escaped_for_systemd() {
        assert_eq!(systemd_quote("--port=8000"), "--port=8000");
        assert_eq!(systemd_quote("a b"), "\"a b\"");
        assert_eq!(systemd_quote("100%"), "\"100%%\"");
        assert_eq!(systemd_quote("$HOME"), "\"$$HOME\"");
        assert_eq!(systemd_quote("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(systemd_quote("C:\\dir"), "\"C:\\\\dir\"");
        assert_eq!(systemd_quote("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(systemd_quote(""), "\"\"");
        assert_eq!(systemd_quote("{\"a\": 1}"), "\"{\\\"a\\\": 1}\"");
    }

    #[test]
    fn env_file_values_are_taken_literally() {
        let env = render_env_file(&[
            ("HF_TOKEN".to_string(), "hf_$abc\"`x`\\".to_string()),
            ("EMPTY".to_string(), String::new()),
        ]);
        assert_eq!(
            env,
            "# Managed by regent-sdk: manual changes will be overwritten
HF_TOKEN=\"hf_\\$abc\\\"\\`x\\`\\\\\"
EMPTY=\"\"
"
        );
    }

    #[test]
    fn value_types_are_validated() {
        assert!("HF_TOKEN".parse::<ServiceEnvVarName>().is_ok());
        assert!("_x1".parse::<ServiceEnvVarName>().is_ok());
        for name in ["", "1X", "A-B", "A B", "A=B"] {
            assert!(name.parse::<ServiceEnvVarName>().is_err(), "{}", name);
        }

        assert!("/opt/x.sif".parse::<AbsolutePath>().is_ok());
        assert_eq!(
            "/opt/x.sif".parse::<AbsolutePath>().unwrap().parent(),
            "/opt"
        );
        assert_eq!("/x.sif".parse::<AbsolutePath>().unwrap().parent(), "/");
        for path in ["x.sif", "/opt/", "/opt/a\nb", ""] {
            assert!(path.parse::<AbsolutePath>().is_err(), "{:?}", path);
        }

        let mount = |spec: &str| spec.parse::<BindMount>();
        assert_eq!(mount("/data").unwrap().to_string(), "/data:/data:rw");
        assert_eq!(
            mount("/models:/root/.cache:ro").unwrap().apptainer_arg(),
            "/models:/root/.cache:ro"
        );
        assert_eq!(
            mount("/models:/models:ro").unwrap().enroot_arg(),
            "/models:/models:none:x-create=auto,rbind,ro"
        );
        assert_eq!(
            mount("/data:/data").unwrap().enroot_arg(),
            "/data:/data:none:x-create=auto,rbind"
        );
        for spec in [
            "data:/data",
            "/data:data",
            "/data:/data:Z",
            "/a,b:/c",
            "/a b:/c",
            "/a:/b:ro:x",
        ] {
            assert!(mount(spec).is_err(), "{}", spec);
        }
    }

    #[test]
    fn probes_are_parsed_despite_noise() {
        assert_eq!(
            parse_scope_probe("sudo: warning\nregent-uid=0\nregent-home=/root\n"),
            Some((UnitScope::System, "/root".to_string()))
        );
        assert_eq!(
            parse_scope_probe("regent-uid=1000\nregent-home=/home/ai\n"),
            Some((UnitScope::User, "/home/ai".to_string()))
        );
        assert_eq!(parse_scope_probe("garbage"), None);

        assert!(parse_linger("yes\n"));
        assert!(!parse_linger("no\n"));
        assert!(!parse_linger(
            "Failed to get user: User ID 1000 is not logged in or lingering\n"
        ));

        assert_eq!(
            parse_file_probe("warning\nregent-file-present\nline\n\nregent-file-end\n"),
            Some(Some("line\n".to_string()))
        );
        assert_eq!(
            parse_file_probe("regent-file-present\n\nregent-file-end\n"),
            Some(Some(String::new()))
        );
        assert_eq!(parse_file_probe("regent-file-missing\n"), Some(None));
        assert_eq!(parse_file_probe("weird"), None);

        let status = UnitStatus::parse(
            "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nNeedDaemonReload=no\n",
        );
        assert!(status.is_active() && status.is_enabled() && !status.need_daemon_reload);
        let status = UnitStatus::parse(
            "LoadState=not-found\nActiveState=inactive\nUnitFileState=\nNeedDaemonReload=no\n",
        );
        assert!(!status.is_active() && !status.is_enabled());
    }

    fn observed(unit: &str, env: &str, active: bool, enabled: bool) -> ObservedService {
        ObservedService {
            unit_file: Some(unit.to_string()),
            env_file: Some(env.to_string()),
            status: UnitStatus {
                load_state: "loaded".to_string(),
                active_state: if active { "active" } else { "inactive" }.to_string(),
                unit_file_state: if enabled { "enabled" } else { "disabled" }.to_string(),
                need_daemon_reload: false,
            },
            linger: None,
        }
    }

    #[test]
    fn service_plan_reaches_the_expected_state() {
        use ServiceUnitAction::*;
        let act = ServiceStep::Action;

        // Nothing installed yet, rootless
        let fresh = ObservedService {
            linger: Some(false),
            ..ObservedService::default()
        };
        assert_eq!(
            plan_service(true, "U", "E", &fresh, false),
            vec![
                act(EnableLinger),
                ServiceStep::WriteFiles(vec![
                    "unit file is missing".to_string(),
                    "environment file is missing".to_string()
                ]),
                act(Enable),
                act(Start),
            ]
        );

        // Compliant
        assert!(plan_service(true, "U", "E", &observed("U", "E", true, true), false).is_empty());
        assert!(plan_service(false, "U", "E", &observed("U", "E", false, false), false).is_empty());

        // A secret changed while running: rewrite then restart, without showing the value
        assert_eq!(
            plan_service(true, "U", "E2", &observed("U", "E", true, true), false),
            vec![
                ServiceStep::WriteFiles(vec!["environment file differs".to_string()]),
                act(Restart),
            ]
        );

        // New container behind an unchanged unit
        assert_eq!(
            plan_service(true, "U", "E", &observed("U", "E", true, true), true),
            vec![act(Restart)]
        );

        // Must be stopped
        assert_eq!(
            plan_service(false, "U", "E", &observed("U", "E", true, true), true),
            vec![act(Disable), act(Stop)]
        );

        // Daemon reload needed
        let mut stale = observed("U", "E", false, true);
        stale.status.need_daemon_reload = true;
        assert_eq!(
            plan_service(true, "U", "E", &stale, false),
            vec![act(DaemonReload), act(Start)]
        );

        assert!(needs_removal(&observed("U", "E", false, false)));
        assert!(!needs_removal(&ObservedService::default()));
    }

    #[test]
    fn write_command_protects_the_environment_file() {
        let command = write_files_command(&id(UnitScope::System), "UNIT", "A=\"it's\"\n");
        assert_eq!(
            command,
            "(umask 077 && mkdir -p /etc/regent-sdk/apptainer && printf '%s' 'A=\"it'\\''s\"\n' > /etc/regent-sdk/apptainer/'vllm.env' && chmod 600 /etc/regent-sdk/apptainer/'vllm.env') && \
mkdir -p /etc/systemd/system && printf '%s' 'UNIT' > /etc/systemd/system/'regent-apptainer-vllm.service' && chmod 644 /etc/systemd/system/'regent-apptainer-vllm.service' && 'systemctl' 'daemon-reload'"
        );
        assert_eq!(
            ServiceUnitAction::Remove.command(&id(UnitScope::System)),
            "{ 'systemctl' 'stop' 'regent-apptainer-vllm.service' >/dev/null 2>&1; 'systemctl' 'disable' 'regent-apptainer-vllm.service' >/dev/null 2>&1; rm -f /etc/systemd/system/'regent-apptainer-vllm.service' /etc/regent-sdk/apptainer/'vllm.env' && 'systemctl' 'daemon-reload'; }"
        );
    }
}
