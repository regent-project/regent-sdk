//! Prometheus Node Exporter attribute
//!
//! This module provides the `NodeExporterExpectedState` type for installing the
//! [Prometheus Node Exporter](https://github.com/prometheus/node_exporter), which exposes the
//! hardware and kernel metrics of the host to Prometheus, from its GitHub releases.
//!
//! **Compatible OS:** Linux with systemd, on x86_64 or aarch64.
//!
//! **Privilege:** installing the binary and the unit needs root, use `!WithSudo`.
//!
//! # How compliance is assessed
//!
//! 1. The `node_exporter` system user must exist (it runs the exporter).
//! 2. `/usr/local/bin/node_exporter` must be installed in `Version` (`node_exporter --version`).
//!    Another version is upgraded or downgraded with the release tarball, then a running service
//!    is restarted.
//! 3. `TextfileDirectory`, if set, must exist: the `textfile` collector exposes the metrics of
//!    the `*.prom` files written there (e.g. by cron jobs or training pipelines).
//! 4. The unit `/etc/systemd/system/node_exporter.service` must run the exporter with these
//!    flags: `ListenAddress` (`:9100` by default), `EnabledCollectors` (off by default, e.g.
//!    `systemd`, `processes`) and `DisabledCollectors` (on by default, e.g. `wifi`). A running
//!    service is restarted when the unit changes.
//!
//! `Absent` stops and disables the service, removes the binary and the unit, and deletes the
//! `node_exporter` user. The textfile directory is kept.
//!
//! Whether the exporter runs is managed by the `Service` attribute (unit `node_exporter`). The
//! `prometheus-node-exporter` package of Debian and Ubuntu listens on the same port: remove it
//! (`Apt` attribute) when using this attribute.
//!
//! **Prerequisites:** `curl` (or `wget`), `tar` and access to `github.com`.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::observability::node_exporter::NodeExporterExpectedState;
//! use regent_sdk::state::attribute::system::service::ServiceExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege, RegentError};
//!
//! fn host_metrics() -> Result<ExpectedState, RegentError> {
//!     let node_exporter = NodeExporterExpectedState::present("1.12.1".parse()?)
//!         .with_listen_address("0.0.0.0:9100")
//!         .with_enabled_collectors(&["systemd", "processes"])
//!         .with_disabled_collectors(&["wifi"])
//!         .with_textfile_directory("/var/lib/node_exporter/textfile");
//!
//!     Ok(ExpectedState::new()
//!         .with_attribute(Attribute::node_exporter(node_exporter, Privilege::WithSudo, None))
//!         .with_attribute(Attribute::service(
//!             ServiceExpectedState::started_and_enabled("node_exporter"),
//!             Privilege::WithSudo,
//!             None,
//!         ))
//!         .build())
//! }
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Node Exporter exposes the host metrics
//!     Privilege: !WithSudo
//!     Detail: !NodeExporter
//!       State: Present
//!       Version: '1.12.1'
//!       ListenAddress: 0.0.0.0:9100          # optional, :9100 by default
//!       EnabledCollectors: [systemd, processes]
//!       DisabledCollectors: [wifi]
//!       TextfileDirectory: /var/lib/node_exporter/textfile
//!   - Name: Node Exporter runs
//!     Privilege: !WithSudo
//!     Detail: !Service
//!       Name: node_exporter
//!       State: Started
//!       Enabled: true
//! ```
//!
//! To remove the Node Exporter:
//!
//! ```yaml
//! Attributes:
//!   - Name: Node Exporter must be removed
//!     Privilege: !WithSudo
//!     Detail: !NodeExporter
//!       State: Absent
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::attribute::container::container_spec::quoted_command;
use crate::state::attribute::observability::{
    AgentVersion, ReleaseArch, VersionChange, apply_to_running_unit, as_remediation_error,
    check_linux_host, file_content, host_release_arch, path_exists, systemctl, version_change,
    write_unit_files,
};
use crate::state::attribute::shared::{
    UnitEnablement, download, is_success, make_temp_dir, query, remove_temp_dir, run_step,
    run_steps, unit_state,
};
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

const ATTRIBUTE: &str = "NodeExporter";
const USER: &str = "node_exporter";
const UNIT: &str = "node_exporter";
const BINARY: &str = "/usr/local/bin/node_exporter";
const UNIT_FILE: &str = "/etc/systemd/system/node_exporter.service";
const RELEASES_URL: &str = "https://github.com/prometheus/node_exporter/releases/download";
const DEFAULT_LISTEN_ADDRESS: &str = ":9100";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "State",
    rename_all = "PascalCase",
    rename_all_fields = "PascalCase",
    deny_unknown_fields
)]
pub enum NodeExporterExpectedState {
    Present {
        version: AgentVersion,
        /// `--web.listen-address`, `:9100` when `None`
        listen_address: Option<String>,
        /// Collectors disabled by default to enable (`--collector.<name>`)
        #[serde(default)]
        enabled_collectors: BTreeSet<String>,
        /// Collectors enabled by default to disable (`--no-collector.<name>`)
        #[serde(default)]
        disabled_collectors: BTreeSet<String>,
        /// `--collector.textfile.directory`, created if missing
        textfile_directory: Option<String>,
    },
    Absent,
}

impl Timeout for NodeExporterExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(300)
    }
}

impl NodeExporterExpectedState {
    /// Node Exporter installed in `version`, with its default flags
    pub fn present(version: AgentVersion) -> Self {
        NodeExporterExpectedState::Present {
            version,
            listen_address: None,
            enabled_collectors: BTreeSet::new(),
            disabled_collectors: BTreeSet::new(),
            textfile_directory: None,
        }
    }

    pub fn absent() -> Self {
        NodeExporterExpectedState::Absent
    }

    /// `--web.listen-address`, e.g. `0.0.0.0:9100` (no effect on `Absent`)
    pub fn with_listen_address(mut self, address: &str) -> Self {
        if let NodeExporterExpectedState::Present { listen_address, .. } = &mut self {
            *listen_address = Some(address.to_string());
        }
        self
    }

    /// Enable collectors that are off by default (no effect on `Absent`)
    pub fn with_enabled_collectors(mut self, collectors: &[&str]) -> Self {
        if let NodeExporterExpectedState::Present {
            enabled_collectors, ..
        } = &mut self
        {
            enabled_collectors.extend(collectors.iter().map(|name| name.to_string()));
        }
        self
    }

    /// Disable collectors that are on by default (no effect on `Absent`)
    pub fn with_disabled_collectors(mut self, collectors: &[&str]) -> Self {
        if let NodeExporterExpectedState::Present {
            disabled_collectors,
            ..
        } = &mut self
        {
            disabled_collectors.extend(collectors.iter().map(|name| name.to_string()));
        }
        self
    }

    /// Expose the `*.prom` files of `directory` (no effect on `Absent`)
    pub fn with_textfile_directory(mut self, directory: &str) -> Self {
        if let NodeExporterExpectedState::Present {
            textfile_directory, ..
        } = &mut self
        {
            *textfile_directory = Some(directory.to_string());
        }
        self
    }

    /// `None` for `Absent`
    fn unit_content(&self) -> Option<String> {
        let NodeExporterExpectedState::Present {
            listen_address,
            enabled_collectors,
            disabled_collectors,
            textfile_directory,
            ..
        } = self
        else {
            return None;
        };
        let mut command = vec![
            BINARY.to_string(),
            format!(
                "--web.listen-address={}",
                listen_address.as_deref().unwrap_or(DEFAULT_LISTEN_ADDRESS)
            ),
        ];
        command.extend(
            enabled_collectors
                .iter()
                .map(|name| format!("--collector.{}", name)),
        );
        command.extend(
            disabled_collectors
                .iter()
                .map(|name| format!("--no-collector.{}", name)),
        );
        if let Some(directory) = textfile_directory {
            command.push(format!("--collector.textfile.directory={}", directory));
        }
        Some(format!(
            "[Unit]
Description=Prometheus Node Exporter
Documentation=https://github.com/prometheus/node_exporter
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={user}
Group={user}
ExecStart={command}
Restart=on-failure

[Install]
WantedBy=multi-user.target
",
            user = USER,
            command = command.join(" ")
        ))
    }
}

/// Version printed by `node_exporter --version`: `node_exporter, version 1.12.1 (branch: ...)`
fn parse_node_exporter_version(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("node_exporter, version ")
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_string)
    })
}

fn tarball_url(version: &AgentVersion, arch: ReleaseArch) -> String {
    format!(
        "{}/v{}/node_exporter-{}.linux-{}.tar.gz",
        RELEASES_URL, version, version, arch
    )
}

fn is_collector_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

impl Check for NodeExporterExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        let NodeExporterExpectedState::Present {
            listen_address,
            enabled_collectors,
            disabled_collectors,
            textfile_directory,
            ..
        } = self
        else {
            return Ok(());
        };
        let incoherent = |details: String| {
            Err(RegentError::IncoherentExpectedState(format!(
                "NodeExporter: {}",
                details
            )))
        };
        // Flags are written unquoted in ExecStart
        if let Some(address) = listen_address
            && (address.is_empty() || address.contains(char::is_whitespace))
        {
            return incoherent(format!("invalid listen address {:?}", address));
        }
        if let Some(name) = enabled_collectors
            .iter()
            .chain(disabled_collectors)
            .find(|name| !is_collector_name(name))
        {
            return incoherent(format!(
                "invalid collector name {:?} (lowercase letters, digits, _ and .)",
                name
            ));
        }
        if let Some(name) = enabled_collectors.intersection(disabled_collectors).next() {
            return incoherent(format!(
                "collector {:?} can't be both enabled and disabled",
                name
            ));
        }
        if let Some(directory) = textfile_directory
            && (!directory.starts_with('/') || directory.contains(char::is_whitespace))
        {
            return incoherent(format!(
                "the textfile directory {:?} must be an absolute path without whitespace",
                directory
            ));
        }
        if textfile_directory.is_some() && disabled_collectors.contains("textfile") {
            return incoherent(
                "a textfile directory is set but the textfile collector is disabled".to_string(),
            );
        }
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

async fn user_exists<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<bool, RegentError> {
    Ok(query(
        host_handler,
        &quoted_command(&["id", "-u", USER]),
        privilege,
    )
    .await?
    .return_code
        == 0)
}

async fn installed_version<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<Option<String>, RegentError> {
    let result = query(
        host_handler,
        &quoted_command(&[BINARY, "--version"]),
        privilege,
    )
    .await?;
    if result.return_code != 0 {
        return Ok(None);
    }
    Ok(parse_node_exporter_version(&result.stdout))
}

impl<Handler: HostHandler> AssessCompliance<Handler> for NodeExporterExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let has_user = user_exists(host_handler, privilege).await?;
        let has_binary = path_exists(host_handler, BINARY, privilege).await?;
        let current_unit = file_content(host_handler, UNIT_FILE, privilege).await?;

        let mut api_calls = Vec::new();
        match self {
            NodeExporterExpectedState::Absent => {
                if has_user || has_binary || current_unit.is_some() {
                    api_calls.push(NodeExporterInternalApiCall::Uninstall);
                }
            }
            NodeExporterExpectedState::Present {
                version,
                textfile_directory,
                ..
            } => {
                if !has_user {
                    api_calls.push(NodeExporterInternalApiCall::CreateUser);
                }

                let installed = match has_binary {
                    true => installed_version(host_handler, privilege)
                        .await?
                        .or(Some(String::new())),
                    false => None,
                };
                if let Some(change) = version_change(installed.as_deref(), Some(version)) {
                    let arch = match host_release_arch(host_handler, privilege).await? {
                        Ok(arch) => arch,
                        Err(reason) => {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(reason));
                        }
                    };
                    api_calls.push(NodeExporterInternalApiCall::Install {
                        version: version.clone(),
                        arch,
                        change,
                    });
                }

                if let Some(directory) = textfile_directory
                    && !path_exists(host_handler, directory, privilege).await?
                {
                    api_calls.push(NodeExporterInternalApiCall::CreateTextfileDirectory(
                        directory.clone(),
                    ));
                }

                let expected_unit = self.unit_content().unwrap_or_default();
                if current_unit.as_deref() != Some(expected_unit.as_str()) {
                    api_calls.push(NodeExporterInternalApiCall::WriteUnit {
                        content: expected_unit,
                    });
                }
            }
        }

        if api_calls.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        let remediations = api_calls
            .into_iter()
            .map(|api_call| {
                Remediation::NodeExporter(NodeExporterApiCall::from(api_call, privilege.clone()))
            })
            .collect();
        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(remediations)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", rename_all_fields = "PascalCase")]
pub enum NodeExporterInternalApiCall {
    CreateUser,
    /// Install, upgrade or downgrade the binary from the release tarball, restart the service if
    /// running
    Install {
        version: AgentVersion,
        arch: ReleaseArch,
        change: VersionChange,
    },
    CreateTextfileDirectory(String),
    /// Write the systemd unit, restart the service if running
    WriteUnit {
        content: String,
    },
    Uninstall,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeExporterApiCall {
    pub api_call: NodeExporterInternalApiCall,
    privilege: Privilege,
}

impl NodeExporterApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            NodeExporterInternalApiCall::CreateUser => {
                format!("Create the {} system user", USER)
            }
            NodeExporterInternalApiCall::Install {
                version,
                arch,
                change,
            } => format!("{} Node Exporter {} ({})", change, version, arch),
            NodeExporterInternalApiCall::CreateTextfileDirectory(directory) => {
                format!("Create the textfile collector directory {}", directory)
            }
            NodeExporterInternalApiCall::WriteUnit { .. } => format!(
                "Write the Node Exporter unit {} and restart it if running",
                UNIT_FILE
            ),
            NodeExporterInternalApiCall::Uninstall => "Uninstall Node Exporter".to_string(),
        }
    }

    fn from(api_call: NodeExporterInternalApiCall, privilege: Privilege) -> NodeExporterApiCall {
        NodeExporterApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for NodeExporterApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties, ATTRIBUTE)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for NodeExporterApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let privilege = &self.privilege;
        match &self.api_call {
            NodeExporterInternalApiCall::CreateUser => Ok(run_step(
                host_handler,
                &quoted_command(&[
                    "useradd",
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--shell",
                    "/bin/false",
                    USER,
                ]),
                privilege,
            )
            .await),
            NodeExporterInternalApiCall::Install { version, arch, .. } => {
                install(host_handler, version, *arch, privilege).await
            }
            NodeExporterInternalApiCall::CreateTextfileDirectory(directory) => Ok(run_step(
                host_handler,
                &quoted_command(&["install", "-d", "-m", "0755", directory]),
                privilege,
            )
            .await),
            NodeExporterInternalApiCall::WriteUnit { content } => {
                write_unit_files(
                    host_handler,
                    &[(UNIT_FILE, content)],
                    UNIT,
                    "restart",
                    privilege,
                )
                .await
            }
            NodeExporterInternalApiCall::Uninstall => uninstall(host_handler, privilege).await,
        }
    }
}

async fn install<Handler: HostHandler>(
    host_handler: &mut Handler,
    version: &AgentVersion,
    arch: ReleaseArch,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let tmp = match make_temp_dir(host_handler, privilege)
        .await
        .map_err(as_remediation_error)?
    {
        Ok(tmp) => tmp,
        Err(failure) => return Ok(failure),
    };
    let tarball = format!("{}/node_exporter.tar.gz", tmp);
    let mut outcome = download(
        host_handler,
        &tarball_url(version, arch),
        &tarball,
        privilege,
    )
    .await;
    if is_success(&outcome) {
        outcome = run_steps(
            host_handler,
            &[
                // The tarball holds node_exporter-<version>.linux-<arch>/node_exporter
                quoted_command(&["tar", "-xzf", &tarball, "-C", &tmp, "--strip-components=1"]),
                quoted_command(&[
                    "install",
                    "-m",
                    "0755",
                    &format!("{}/node_exporter", tmp),
                    BINARY,
                ]),
            ],
            privilege,
        )
        .await;
    }
    remove_temp_dir(host_handler, &tmp, privilege).await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }

    match installed_version(host_handler, privilege)
        .await
        .map_err(as_remediation_error)?
    {
        Some(installed) if version.matches(&installed) => {
            let restart = apply_to_running_unit(host_handler, UNIT, "restart", privilege).await?;
            if is_success(&restart) {
                Ok(InternalApiCallOutcome::Success(Some(format!(
                    "Node Exporter {} installed",
                    installed
                ))))
            } else {
                Ok(restart)
            }
        }
        Some(installed) => Ok(InternalApiCallOutcome::Failure(format!(
            "Node Exporter {} is installed but version {} was requested",
            installed, version
        ))),
        None => Ok(InternalApiCallOutcome::Failure(format!(
            "Unable to read the version of {} after its installation",
            BINARY
        ))),
    }
}

async fn uninstall<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let unit = unit_state(host_handler, UNIT, privilege)
        .await
        .map_err(as_remediation_error)?;
    let mut commands = Vec::new();
    if unit.active {
        commands.push(systemctl(&["stop", UNIT]));
    }
    if unit.enablement == UnitEnablement::Enabled {
        commands.push(systemctl(&["disable", UNIT]));
    }
    commands.push(quoted_command(&["rm", "-f", BINARY, UNIT_FILE]));
    commands.push(systemctl(&["daemon-reload"]));
    let outcome = run_steps(host_handler, &commands, privilege).await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }
    // userdel removes the group created along with the user
    if user_exists(host_handler, privilege)
        .await
        .map_err(as_remediation_error)?
    {
        return Ok(run_step(host_handler, &quoted_command(&["userdel", USER]), privilege).await);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::attribute::Attribute;

    fn full_state() -> NodeExporterExpectedState {
        NodeExporterExpectedState::present("1.12.1".parse().unwrap())
            .with_listen_address("0.0.0.0:9100")
            .with_enabled_collectors(&["systemd", "processes"])
            .with_disabled_collectors(&["wifi"])
            .with_textfile_directory("/var/lib/node_exporter/textfile")
    }

    #[test]
    fn parsing_node_exporter_module_block_from_yaml_str() {
        let raw = "---
State: Present
Version: '1.12.1'
ListenAddress: 0.0.0.0:9100
EnabledCollectors: [systemd, processes]
DisabledCollectors: [wifi]
TextfileDirectory: /var/lib/node_exporter/textfile
";
        let block: NodeExporterExpectedState = yaml_serde::from_str(raw).unwrap();
        assert!(block.check().is_ok());
        assert_eq!(block, full_state());

        let block: NodeExporterExpectedState =
            yaml_serde::from_str("---\nState: Present\nVersion: '1.12.1'\n").unwrap();
        assert_eq!(
            block,
            NodeExporterExpectedState::present("1.12.1".parse().unwrap())
        );

        let block: NodeExporterExpectedState =
            yaml_serde::from_str("---\nState: Absent\n").unwrap();
        assert_eq!(block, NodeExporterExpectedState::absent());
    }

    #[test]
    fn rejecting_incorrect_node_exporter_module_block_from_yaml_str() {
        for raw in [
            "---\nState: Present\n",
            "---\nState: Present\nVersion: '1.12.1'\nCollectors: [systemd]\n",
            "---\nState: Present\nVersion: '1.12.1'\nEnabledCollectors: systemd\n",
        ] {
            assert!(
                yaml_serde::from_str::<NodeExporterExpectedState>(raw).is_err(),
                "{raw}"
            );
        }

        let version: AgentVersion = "1.12.1".parse().unwrap();
        let incoherent_states = [
            NodeExporterExpectedState::present(version.clone()).with_listen_address("0.0.0.0 9100"),
            NodeExporterExpectedState::present(version.clone())
                .with_enabled_collectors(&["System D"]),
            NodeExporterExpectedState::present(version.clone())
                .with_enabled_collectors(&["systemd"])
                .with_disabled_collectors(&["systemd"]),
            NodeExporterExpectedState::present(version.clone())
                .with_textfile_directory("relative/path"),
            NodeExporterExpectedState::present(version)
                .with_textfile_directory("/var/lib/textfile")
                .with_disabled_collectors(&["textfile"]),
        ];
        for state in incoherent_states {
            assert!(state.check().is_err(), "{state:?}");
        }
    }

    #[test]
    fn parsing_full_node_exporter_attribute_envelope_from_yaml_str() {
        let raw_attribute = "---
Name: Node Exporter must be installed
Privilege: !WithSudo
Detail: !NodeExporter
  State: Present
  Version: '1.12.1'
  EnabledCollectors: [systemd]
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
    }

    #[test]
    fn the_unit_runs_the_exporter_with_its_flags() {
        let unit = full_state().unit_content().unwrap();
        assert!(unit.contains(
            "\nExecStart=/usr/local/bin/node_exporter --web.listen-address=0.0.0.0:9100 --collector.processes --collector.systemd --no-collector.wifi --collector.textfile.directory=/var/lib/node_exporter/textfile\n"
        ));
        assert!(unit.contains("\nUser=node_exporter\nGroup=node_exporter\n"));

        let default_unit = NodeExporterExpectedState::present("1.12.1".parse().unwrap())
            .unit_content()
            .unwrap();
        assert!(
            default_unit
                .contains("\nExecStart=/usr/local/bin/node_exporter --web.listen-address=:9100\n")
        );
        assert_eq!(NodeExporterExpectedState::absent().unit_content(), None);
    }

    #[test]
    fn versions_and_tarballs_are_located() {
        assert_eq!(
            parse_node_exporter_version(
                "node_exporter, version 1.12.1 (branch: HEAD, revision: 1234abcd)\n  build user: root@host\n"
            ),
            Some("1.12.1".to_string())
        );
        assert_eq!(
            parse_node_exporter_version("sh: node_exporter: not found"),
            None
        );
        assert_eq!(
            tarball_url(&"1.12.1".parse().unwrap(), ReleaseArch::Arm64),
            "https://github.com/prometheus/node_exporter/releases/download/v1.12.1/node_exporter-1.12.1.linux-arm64.tar.gz"
        );
    }
}
