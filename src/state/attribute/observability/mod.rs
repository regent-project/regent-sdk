//! Observability attributes: the agents shipping the host's telemetry (logs, metrics, traces)
//!
//! - `fluentbit.rs`: [Fluent Bit](https://fluentbit.io), log collector and forwarder
//! - `node_exporter.rs`: [Prometheus Node Exporter](https://github.com/prometheus/node_exporter),
//!   host metrics scraped by Prometheus
//! - `otel_collector.rs`: [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/),
//!   vendor-neutral pipeline for traces, metrics and logs
//! - `alloy.rs`: [Grafana Alloy](https://grafana.com/docs/alloy/), Grafana's OpenTelemetry
//!   Collector distribution feeding Prometheus, Loki, Tempo and Pyroscope
//!
//! Each attribute installs its agent and writes its configuration. Whether the agent runs is
//! managed by the `Service` attribute, placed after the agent attribute: a configuration change
//! is applied to an agent already running (reloaded or restarted), a stopped agent is left alone.
//!
//! Configurations are given verbatim and compared byte for byte with the files on the host. Like
//! every attribute, they go through the Tera template engine first: host and global variables can
//! be used in them (`{{ my_var }}`), and literal `{{`, `{%` or `{#` must be escaped. They are
//! written world-readable (the agents run as dedicated users): pass credentials through
//! environment variables, which every agent can expand in its configuration.
//!
//! Values with the same semantics across the attributes of this category are defined here.

pub mod alloy;
pub mod fluentbit;
pub mod node_exporter;
pub mod otel_collector;

pub use alloy::{AlloyApiCall, AlloyExpectedState};
pub use fluentbit::{FluentBitApiCall, FluentBitExpectedState};
pub use node_exporter::{NodeExporterApiCall, NodeExporterExpectedState};
pub use otel_collector::{OtelCollectorApiCall, OtelCollectorExpectedState};

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::properties::{HostProperties, OsKind};
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::container::container_spec::quoted_command;
use crate::state::attribute::shared::{
    PackageFamily, download, installed_packages, is_success, make_temp_dir, query, query_output,
    remove_temp_dir, run_step, run_steps, unit_state,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// Release of an agent: dot-separated numbers, e.g. `4.0.3` (quote it in YAML: `'1.10'` would
/// otherwise be read as a number)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentVersion(Vec<u32>);

impl TryFrom<String> for AgentVersion {
    type Error = RegentError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        match version_numbers(&text) {
            Some(numbers) if (2..=4).contains(&numbers.len()) => Ok(Self(numbers)),
            _ => Err(RegentError::IncoherentExpectedState(format!(
                "Invalid agent version {:?}: expected dot-separated numbers such as 4.0.3",
                text
            ))),
        }
    }
}

impl FromStr for AgentVersion {
    type Err = RegentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(text.to_string())
    }
}

impl From<AgentVersion> for String {
    fn from(version: AgentVersion) -> String {
        version.to_string()
    }
}

impl fmt::Display for AgentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let numbers: Vec<String> = self.0.iter().map(u32::to_string).collect();
        write!(f, "{}", numbers.join("."))
    }
}

impl AgentVersion {
    /// Order with an installed version (`4.0.3`, `v4.0.3`, or a package version such as
    /// `1:4.0.3-1`), `None` when it can't be read. Missing components count as zero.
    pub(crate) fn compare_with_installed(&self, installed: &str) -> Option<Ordering> {
        let mut installed = version_numbers(upstream(installed))?;
        let mut expected = self.0.clone();
        let length = installed.len().max(expected.len());
        installed.resize(length, 0);
        expected.resize(length, 0);
        Some(expected.cmp(&installed))
    }

    pub(crate) fn matches(&self, installed: &str) -> bool {
        self.compare_with_installed(installed) == Some(Ordering::Equal)
    }
}

fn version_numbers(text: &str) -> Option<Vec<u32>> {
    text.trim()
        .trim_start_matches('v')
        .split('.')
        .map(|part| {
            (!part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
                .then(|| part.parse().ok())
                .flatten()
        })
        .collect()
}

/// `1:4.0.3-1` -> `4.0.3`
fn upstream(version: &str) -> &str {
    let without_epoch = version.split_once(':').map_or(version, |(_, rest)| rest);
    without_epoch
        .split_once(['-', '~', '+'])
        .map_or(without_epoch, |(upstream, _)| upstream)
}

/// How an agent goes from its installed version to the expected one
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum VersionChange {
    Install,
    Upgrade,
    Downgrade,
}

impl fmt::Display for VersionChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionChange::Install => write!(f, "Install"),
            VersionChange::Upgrade => write!(f, "Upgrade"),
            VersionChange::Downgrade => write!(f, "Downgrade"),
        }
    }
}

/// `None` when the installed agent is compliant: installed in the expected version, or in any
/// version when none is expected (an unknown installed version is upgraded)
pub(crate) fn version_change(
    installed: Option<&str>,
    expected: Option<&AgentVersion>,
) -> Option<VersionChange> {
    match (installed, expected) {
        (None, _) => Some(VersionChange::Install),
        (Some(_), None) => None,
        (Some(installed), Some(expected)) => match expected.compare_with_installed(installed) {
            Some(Ordering::Equal) => None,
            Some(Ordering::Less) => Some(VersionChange::Downgrade),
            Some(Ordering::Greater) | None => Some(VersionChange::Upgrade),
        },
    }
}

/// Package repository of an agent vendor
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum AgentRepository {
    Apt {
        key_url: String,
        keyring: String,
        /// The key is published armored and must be converted to a binary keyring
        dearmor: bool,
        list_file: String,
        source_line: String,
    },
    /// dnf repository described by a `.repo` file
    RpmFile {
        repo_file: String,
        content: String,
    },
    Zypper {
        url: String,
        alias: String,
    },
}

impl fmt::Display for AgentRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentRepository::Apt { source_line, .. } => write!(f, "apt: {}", source_line),
            AgentRepository::RpmFile { repo_file, .. } => write!(f, "dnf: {}", repo_file),
            AgentRepository::Zypper { url, alias } => write!(f, "zypper: {} ({})", alias, url),
        }
    }
}

impl AgentRepository {
    pub(crate) async fn setup<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
        privilege: &Privilege,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        match self {
            AgentRepository::Apt {
                key_url,
                keyring,
                dearmor,
                list_file,
                source_line,
            } => {
                let tmp = match make_temp_dir(host_handler, privilege)
                    .await
                    .map_err(as_remediation_error)?
                {
                    Ok(tmp) => tmp,
                    Err(failure) => return Ok(failure),
                };
                let key = format!("{}/key", tmp);
                let mut outcome = download(host_handler, key_url, &key, privilege).await;
                if is_success(&outcome) {
                    let mut commands = vec![quoted_command(&["mkdir", "-p", parent(keyring)])];
                    commands.push(if *dearmor {
                        quoted_command(&[
                            "gpg",
                            "--batch",
                            "--yes",
                            "--dearmor",
                            "-o",
                            keyring,
                            &key,
                        ])
                    } else {
                        quoted_command(&["install", "-m", "0644", &key, keyring])
                    });
                    commands.extend(write_file_commands(
                        list_file,
                        &with_trailing_newline(source_line),
                    ));
                    commands.push(quoted_command(&["apt-get", "update"]));
                    outcome = run_steps(host_handler, &commands, privilege).await;
                }
                remove_temp_dir(host_handler, &tmp, privilege).await;
                Ok(outcome)
            }
            AgentRepository::RpmFile { repo_file, content } => {
                let mut commands = write_file_commands(repo_file, content);
                commands.push(quoted_command(&["dnf", "clean", "expire-cache"]));
                Ok(run_steps(host_handler, &commands, privilege).await)
            }
            AgentRepository::Zypper { url, alias } => Ok(run_steps(
                host_handler,
                &[
                    quoted_command(&["zypper", "--non-interactive", "addrepo", url, alias]),
                    quoted_command(&[
                        "zypper",
                        "--non-interactive",
                        "--gpg-auto-import-keys",
                        "refresh",
                        alias,
                    ]),
                ],
                privilege,
            )
            .await),
        }
    }
}

/// Install, upgrade or downgrade `package` from the configured repositories, then check the
/// installed version
pub(crate) async fn install_package<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    package: &str,
    version: Option<&AgentVersion>,
    change: VersionChange,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    if family == PackageFamily::Apt {
        let outcome = run_step(
            host_handler,
            &quoted_command(&["apt-get", "update"]),
            privilege,
        )
        .await;
        if !is_success(&outcome) {
            return Ok(outcome);
        }
    }
    let spec = match version {
        None => package.to_string(),
        Some(version) => match package_spec(host_handler, family, package, version, privilege)
            .await
            .map_err(as_remediation_error)?
        {
            Ok(spec) => spec,
            Err(failure) => return Ok(failure),
        },
    };
    let outcome = run_step(
        host_handler,
        &family.install_command(&[spec], change == VersionChange::Downgrade),
        privilege,
    )
    .await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }
    verify_installed_package(host_handler, family, package, version, privilege).await
}

/// Install a downloaded `.deb` or `.rpm` file, whatever the installed version
pub(crate) fn install_package_file_command(family: PackageFamily, file: &str) -> String {
    match family {
        PackageFamily::Apt => quoted_command(&["dpkg", "-i", file]),
        PackageFamily::Dnf | PackageFamily::Zypper => {
            quoted_command(&["rpm", "-U", "--oldpackage", "--replacepkgs", file])
        }
    }
}

pub(crate) async fn verify_installed_package<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    package: &str,
    version: Option<&AgentVersion>,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let installed = installed_packages(host_handler, family, &[package], privilege)
        .await
        .map_err(as_remediation_error)?;
    Ok(match (installed.get(package), version) {
        (None, _) => InternalApiCallOutcome::Failure(format!(
            "{} is not installed after its installation",
            package
        )),
        (Some(installed), Some(expected)) if !expected.matches(installed) => {
            InternalApiCallOutcome::Failure(format!(
                "{} {} is installed but version {} was requested",
                package, installed, expected
            ))
        }
        (Some(installed), _) => {
            InternalApiCallOutcome::Success(Some(format!("{} {} installed", package, installed)))
        }
    })
}

/// Package specification pinning `package` to `version`. apt needs the full package version
/// (with its revision), looked up in the repositories: the failure outcome when it is missing.
async fn package_spec<Handler: HostHandler>(
    host_handler: &mut Handler,
    family: PackageFamily,
    package: &str,
    version: &AgentVersion,
    privilege: &Privilege,
) -> Result<Result<String, InternalApiCallOutcome>, RegentError> {
    match family {
        PackageFamily::Dnf => Ok(Ok(format!("{}-{}", package, version))),
        PackageFamily::Zypper => Ok(Ok(format!("{}={}", package, version))),
        PackageFamily::Apt => {
            let madison = query_output(
                host_handler,
                &quoted_command(&["apt-cache", "madison", package]),
                privilege,
            )
            .await?;
            Ok(
                match parse_apt_madison(&madison)
                    .into_iter()
                    .find(|available| version.matches(available))
                {
                    Some(available) => Ok(format!("{}={}", package, available)),
                    None => Err(InternalApiCallOutcome::Failure(format!(
                        "Version {} of {} is not available in the configured apt repositories",
                        version, package
                    ))),
                },
            )
        }
    }
}

/// Versions listed by `apt-cache madison <package>`: `<package> | <version> | <source>`
pub(crate) fn parse_apt_madison(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut columns = line.split('|').map(str::trim);
            let (_package, version, _source) = (columns.next()?, columns.next()?, columns.next()?);
            (!version.is_empty()).then(|| version.to_string())
        })
        .collect()
}

/// CPU architecture as named in the release artifacts of the agents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReleaseArch {
    Amd64,
    Arm64,
}

impl fmt::Display for ReleaseArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseArch::Amd64 => write!(f, "amd64"),
            ReleaseArch::Arm64 => write!(f, "arm64"),
        }
    }
}

/// From `uname -m`
pub(crate) fn parse_release_arch(uname_m: &str) -> Result<ReleaseArch, String> {
    match uname_m.trim() {
        "x86_64" | "amd64" => Ok(ReleaseArch::Amd64),
        "aarch64" | "arm64" => Ok(ReleaseArch::Arm64),
        other => Err(format!(
            "unsupported CPU architecture {:?}: only x86_64 and aarch64 releases are managed",
            other
        )),
    }
}

/// Architecture of the host, or why it isn't supported
pub(crate) async fn host_release_arch<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Result<ReleaseArch, String>, RegentError> {
    let uname_m = query_output(host_handler, &quoted_command(&["uname", "-m"]), privilege).await?;
    Ok(parse_release_arch(&uname_m))
}

/// Content of a file, `None` when it can't be read (missing)
pub(crate) async fn file_content<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let result = query(host_handler, &quoted_command(&["cat", path]), privilege).await?;
    Ok((result.return_code == 0).then_some(result.stdout))
}

pub(crate) async fn path_exists<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
    privilege: &Privilege,
) -> Result<bool, RegentError> {
    Ok(query(
        host_handler,
        &quoted_command(&["test", "-e", path]),
        privilege,
    )
    .await?
    .return_code
        == 0)
}

/// Files are written with a final newline: the assessment compares this exact content
pub(crate) fn with_trailing_newline(content: &str) -> String {
    if content.ends_with('\n') {
        content.to_string()
    } else {
        format!("{}\n", content)
    }
}

fn parent(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((directory, _)) => directory,
    }
}

/// Write `content` (already ending with a newline) to `path`, readable by everyone
pub(crate) fn write_file_commands(path: &str, content: &str) -> Vec<String> {
    vec![
        quoted_command(&["mkdir", "-p", parent(path)]),
        format!(
            "printf '%s' {} > {}",
            shell_quote(content),
            shell_quote(path)
        ),
        quoted_command(&["chmod", "0644", path]),
    ]
}

pub(crate) fn systemctl(args: &[&str]) -> String {
    let mut words = vec!["systemctl"];
    words.extend(args);
    quoted_command(&words)
}

/// `systemctl <action> <unit>` when the unit is running: a stopped unit picks up its new
/// configuration when the `Service` attribute starts it
pub(crate) async fn apply_to_running_unit<Handler: HostHandler>(
    host_handler: &mut Handler,
    unit: &str,
    action: &str,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let state = unit_state(host_handler, unit, privilege)
        .await
        .map_err(as_remediation_error)?;
    if !state.active {
        return Ok(InternalApiCallOutcome::Success(None));
    }
    Ok(run_step(host_handler, &systemctl(&[action, unit]), privilege).await)
}

/// Write files, reload systemd, then apply them to the unit if it is running
pub(crate) async fn write_unit_files<Handler: HostHandler>(
    host_handler: &mut Handler,
    files: &[(&str, &str)],
    unit: &str,
    action: &str,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let mut commands: Vec<String> = files
        .iter()
        .flat_map(|(path, content)| write_file_commands(path, content))
        .collect();
    commands.push(systemctl(&["daemon-reload"]));
    let outcome = run_steps(host_handler, &commands, privilege).await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }
    apply_to_running_unit(host_handler, unit, action, privilege).await
}

pub(crate) fn check_linux_host(
    host_properties: &HostProperties,
    attribute: &str,
) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(_) => Ok(()),
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but {} is only supported on Linux",
            incompatible_os_kind, attribute
        ))),
    }
}

/// The query helpers report a command that could not be run as an assessment error: during a
/// remediation, it is a failure to run it.
pub(crate) fn as_remediation_error(error: RegentError) -> RegentError {
    match error {
        RegentError::FailedDryRunEvaluation(details) => RegentError::FailureToRunCommand(details),
        other => other,
    }
}

/// Rejects empty configurations: an agent can't start without one
pub(crate) fn check_config_content(attribute: &str, content: &str) -> Result<(), RegentError> {
    if content.trim().is_empty() {
        return Err(RegentError::IncoherentExpectedState(format!(
            "{}: the configuration content is empty",
            attribute
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_parsed_and_rejected() {
        assert_eq!(
            "4.0.3".parse::<AgentVersion>().unwrap(),
            AgentVersion(vec![4, 0, 3])
        );
        assert_eq!("v1.12".parse::<AgentVersion>().unwrap().to_string(), "1.12");
        for invalid in ["", "4", "4.0.3.1.2", "4..3", "4.0.x", "latest", "4.0.3-1"] {
            assert!(invalid.parse::<AgentVersion>().is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn versions_are_compared_with_installed_package_versions() {
        let version: AgentVersion = "4.0.3".parse().unwrap();
        assert!(version.matches("4.0.3"));
        assert!(version.matches("4.0.3-1"));
        assert!(version.matches("1:4.0.3-1ubuntu2"));
        assert!(version.matches("v4.0.3"));
        assert!("1.10".parse::<AgentVersion>().unwrap().matches("1.10.0-1"));
        assert_eq!(
            version.compare_with_installed("4.1.0"),
            Some(Ordering::Less)
        );
        assert_eq!(
            version.compare_with_installed("4.0.2"),
            Some(Ordering::Greater)
        );
        assert_eq!(version.compare_with_installed("garbage"), None);
    }

    #[test]
    fn version_changes_follow_the_installed_version() {
        let version: AgentVersion = "4.0.3".parse().unwrap();
        assert_eq!(version_change(None, None), Some(VersionChange::Install));
        assert_eq!(
            version_change(None, Some(&version)),
            Some(VersionChange::Install)
        );
        assert_eq!(version_change(Some("3.2.1"), None), None);
        assert_eq!(version_change(Some("4.0.3-1"), Some(&version)), None);
        assert_eq!(
            version_change(Some("4.0.2"), Some(&version)),
            Some(VersionChange::Upgrade)
        );
        assert_eq!(
            version_change(Some("4.1.0"), Some(&version)),
            Some(VersionChange::Downgrade)
        );
        assert_eq!(
            version_change(Some("unknown"), Some(&version)),
            Some(VersionChange::Upgrade)
        );
    }

    #[test]
    fn apt_madison_output_is_parsed() {
        let output = "\
alloy |   1.10.2 | https://apt.grafana.com stable/main amd64 Packages
alloy |   1.10.1 | https://apt.grafana.com stable/main amd64 Packages
W: some warning
";
        assert_eq!(parse_apt_madison(output), vec!["1.10.2", "1.10.1"]);
    }

    #[test]
    fn architectures_are_mapped_to_release_names() {
        assert_eq!(parse_release_arch("x86_64\n"), Ok(ReleaseArch::Amd64));
        assert_eq!(parse_release_arch("aarch64"), Ok(ReleaseArch::Arm64));
        assert!(parse_release_arch("armv7l").is_err());
    }

    #[test]
    fn files_are_written_quoted_with_their_directory() {
        assert_eq!(
            write_file_commands("/etc/alloy/config.alloy", "a 'b'\n"),
            vec![
                "'mkdir' '-p' '/etc/alloy'".to_string(),
                "printf '%s' 'a '\\''b'\\''\n' > '/etc/alloy/config.alloy'".to_string(),
                "'chmod' '0644' '/etc/alloy/config.alloy'".to_string(),
            ]
        );
        assert_eq!(with_trailing_newline("x"), "x\n");
        assert_eq!(with_trailing_newline("x\n"), "x\n");
    }
}
