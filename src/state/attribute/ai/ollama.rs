//! Ollama AI management attribute
//!
//! This module provides the `OllamaExpectedState` type for managing the Ollama
//! AI inference engine, including installation, service management, model pulling,
//! and API configuration.
//!
//! **Compatible OS:** Linux, macOS
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::ai::ollama::{
//!     OllamaApiConfig, OllamaExpectedState, OllamaModel,
//! };
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install Ollama, expose the API on all interfaces, and pull a model
//! let ollama = OllamaExpectedState::present_with_default_config()
//!     .with_api_config(OllamaApiConfig::new().with_listening_endpoint("0.0.0.0:11434"))
//!     .with_models(vec![OllamaModel::present("llama3")]);
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::ollama(ollama, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Ollama with the llama3 model must be installed
//!     Privilege: !WithSudo
//!     Timeout: 10m
//!     Detail: !Ollama
//!       State: Present
//!       ApiConfig:
//!         Host: '0.0.0.0:11434'
//!         Origins:
//!           - '*'
//!       Models:
//!         - Name: llama3
//!           State: Present
//! ```
//!
//! To remove Ollama:
//!
//! ```yaml
//! Attributes:
//!   - Name: Ollama must be removed
//!     Privilege: !WithSudo
//!     Timeout: 10m
//!     Detail: !Ollama
//!       State: Absent
//! ```
//!
//! The API configuration is written to
//! `/etc/systemd/system/ollama.service.d/override.conf` and applied to the
//! running service: writing it restarts the service when it is active, and a
//! running daemon that does not listen on the expected address yet is
//! reported as non-compliant until it is restarted.
//!
//! Ollama is installed when `command -v ollama` finds it. A missing Ollama is
//! installed, configured and gets its `Present` models pulled in a single run.
//!
//! Models are listed and managed through the API (`ollama list`, `ollama pull`,
//! `ollama rm`, run with `OLLAMA_HOST` set to the configured `Host`): the
//! ollama service must be running and reachable, otherwise the assessment is
//! `NonCompliantFatal`.
//!
//! `Absent` follows Ollama's Linux uninstall instructions: the `ollama` unit is
//! stopped and disabled, then the binary, `/usr/local/lib/ollama`,
//! `/usr/lib/ollama`, `/usr/share/ollama` (home of the `ollama` user, holding
//! the downloaded models), the unit file and its override directory are
//! removed, and the `ollama` user and group are deleted. Models stored in a
//! custom `ModelsPath` are kept.

use crate::error::RegentError;
use crate::hosts::handlers::shell_quote;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::attribute::RemediationsList;
use crate::state::attribute::container::container_spec::quoted_command;
use crate::state::attribute::shared::{
    UnitEnablement, download, is_success, make_temp_dir, query, remove_temp_dir, run_step,
    run_steps, unit_state,
};
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaModelState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaModel {
    /// Name of the model (e.g., "llama3", "mistral:7b")
    pub name: String,
    pub state: OllamaModelState,
}

impl OllamaModel {
    pub fn present(name: &str) -> OllamaModel {
        OllamaModel {
            name: name.to_string(),
            state: OllamaModelState::Present,
        }
    }

    pub fn absent(name: &str) -> OllamaModel {
        OllamaModel {
            name: name.to_string(),
            state: OllamaModelState::Absent,
        }
    }
}

/// REST API and environment configuration for Ollama
///
/// These settings are written to `/etc/systemd/system/ollama.service.d/override.conf`
/// and control the Ollama service behavior.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaApiConfig {
    /// OLLAMA_HOST env var - the address the server listens on, e.g. "0.0.0.0:11434"
    pub host: Option<String>,
    /// OLLAMA_ORIGINS - allowed origins for CORS, e.g. ["*"] or specific URLs
    pub origins: Option<Vec<String>>,
    /// OLLAMA_MODELS - custom model storage path
    pub models_path: Option<String>,
    /// OLLAMA_KEEP_ALIVE - how long to keep models in memory, e.g. "5m", "0", "24h"
    pub keep_alive: Option<String>,
    /// OLLAMA_NUM_PARALLEL - number of parallel requests to process
    pub num_parallel: Option<u32>,
    /// OLLAMA_MAX_LOADED_MODELS - maximum number of models to keep loaded in memory
    pub max_loaded_models: Option<u32>,
    /// OLLAMA_GPU_LAYERS - number of GPU layers to load (-1 for all available)
    pub gpu_layers: Option<i32>,
}

impl OllamaApiConfig {
    pub fn new() -> OllamaApiConfig {
        OllamaApiConfig::default()
    }

    /// Address the API listens on, e.g. "0.0.0.0:11434"
    pub fn with_listening_endpoint(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }

    pub fn with_cors_origins(mut self, origins: &[&str]) -> Self {
        self.origins = Some(origins.iter().map(|origin| origin.to_string()).collect());
        self
    }

    pub fn with_models_path(mut self, models_path: &str) -> Self {
        self.models_path = Some(models_path.to_string());
        self
    }

    /// How long an idle model stays loaded in memory
    pub fn with_keep_alive(mut self, keep_alive: Duration) -> Self {
        self.keep_alive = Some(format!("{}ms", keep_alive.as_millis()));
        self
    }

    pub fn with_models_kept_loaded_forever(mut self) -> Self {
        self.keep_alive = Some("-1".to_string());
        self
    }

    /// Number of requests each model processes in parallel
    pub fn with_num_parallel(mut self, num_parallel: u32) -> Self {
        self.num_parallel = Some(num_parallel);
        self
    }

    pub fn with_max_loaded_models(mut self, max_loaded_models: u32) -> Self {
        self.max_loaded_models = Some(max_loaded_models);
        self
    }

    pub fn with_gpu_layers(mut self, gpu_layers: u16) -> Self {
        self.gpu_layers = Some(gpu_layers.into());
        self
    }

    pub fn with_all_gpu_layers(mut self) -> Self {
        self.gpu_layers = Some(-1);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OllamaExpectedState {
    #[serde(rename_all = "PascalCase")]
    Present {
        /// Written to the systemd override file
        api_config: OllamaApiConfig,
        models: Vec<OllamaModel>,
    },
    Absent,
}

impl Timeout for OllamaExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl OllamaExpectedState {
    pub fn absent() -> OllamaExpectedState {
        OllamaExpectedState::Absent
    }

    pub fn present_with_default_config() -> OllamaExpectedState {
        OllamaExpectedState::Present {
            api_config: OllamaApiConfig::new(),
            models: Vec::new(),
        }
    }

    pub fn present_with_config(api_config: OllamaApiConfig) -> OllamaExpectedState {
        OllamaExpectedState::Present {
            api_config,
            models: Vec::new(),
        }
    }

    pub fn present_with_models(models: Vec<OllamaModel>) -> OllamaExpectedState {
        OllamaExpectedState::Present {
            api_config: OllamaApiConfig::new(),
            models,
        }
    }

    pub fn present_with_config_and_models(
        api_config: OllamaApiConfig,
        models: Vec<OllamaModel>,
    ) -> OllamaExpectedState {
        OllamaExpectedState::Present { api_config, models }
    }

    fn api_host(&self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Present {
                api_config,
                models: _models,
            } => api_config.host.clone(),
        }
    }

    /// Ollama is missing: install it, configure it and pull the `Present`
    /// models in the same run (`Absent` models can't exist yet)
    fn installation_api_calls(&self) -> Vec<OllamaModuleInternalApiCall> {
        let mut api_calls = vec![OllamaModuleInternalApiCall::Install];

        if let OllamaExpectedState::Present { api_config, models } = self {
            api_calls.push(OllamaModuleInternalApiCall::WriteApiConfig {
                content: build_api_config_content(api_config),
            });

            api_calls.extend(
                models
                    .iter()
                    .filter(|model| model.state == OllamaModelState::Present)
                    .map(|model| OllamaModuleInternalApiCall::PullModel {
                        name: normalize_model_name(&model.name),
                        host: self.api_host(),
                    }),
            );
        }
        api_calls
    }

    /// Ollama is installed: the API calls bringing its configuration and
    /// models to the expected state, or why models can't be managed
    async fn configuration_api_calls<Handler: HostHandler>(
        &self,
        host_handler: &mut Handler,
    ) -> Result<Result<Vec<OllamaModuleInternalApiCall>, String>, RegentError> {
        let mut api_calls = Vec::new();
        // Models are listed before the remediations run: through the address
        // the daemon listens on now, which differs from the configured one
        // while the new configuration is not applied.
        let mut current_host = self.api_host();

        if let OllamaExpectedState::Present { api_config, models } = self {
            let expected_content = build_api_config_content(api_config);
            let current = query(
                host_handler,
                &quoted_command(&["cat", OVERRIDE_FILE]),
                &Privilege::None,
            )
            .await?;
            let current_content = if current.return_code == 0 {
                current.stdout
            } else {
                String::new()
            };

            if current_content != expected_content {
                current_host = host_in_override(&current_content);
                api_calls.push(OllamaModuleInternalApiCall::WriteApiConfig {
                    content: expected_content,
                });
            } else if let Some((address, port)) =
                api_config.host.as_deref().and_then(api_listen_address)
            {
                // The override file matches, but the running daemon may
                // predate it: it must listen on the expected address.
                // A stopped service is left alone: the Service
                // attribute starts it with the override in place.
                if unit_state(host_handler, OLLAMA_UNIT, &Privilege::None)
                    .await?
                    .active
                {
                    let sockets = query(
                        host_handler,
                        &quoted_command(&["ss", "-tln"]),
                        &Privilege::None,
                    )
                    .await?;
                    if sockets.return_code == 0 && !listens_on(&sockets.stdout, &address, port) {
                        // Started without the override: on Ollama's default address
                        current_host = None;
                        api_calls.push(OllamaModuleInternalApiCall::RestartService);
                    }
                }
            }

            let list_command = ollama_command(current_host.as_deref(), &["list"]);
            let listing = query(host_handler, &list_command, &Privilege::None).await?;
            if listing.return_code != 0 {
                return Ok(Err(format!(
                    "Unable to list the Ollama models, {} failed (RC {}): {}{}. The ollama service must be running and reachable to manage models.",
                    list_command, listing.return_code, listing.stdout, listing.stderr
                )));
            }
            let installed_models = parse_ollama_list(&listing.stdout);

            for model in models {
                let name = normalize_model_name(&model.name);
                let is_installed = installed_models.contains(&name);
                match model.state {
                    OllamaModelState::Present if !is_installed => {
                        api_calls.push(OllamaModuleInternalApiCall::PullModel {
                            name,
                            host: self.api_host(),
                        });
                    }
                    OllamaModelState::Absent if is_installed => {
                        api_calls.push(OllamaModuleInternalApiCall::RemoveModel {
                            name,
                            host: self.api_host(),
                        });
                    }
                    _ => {}
                }
            }
        }

        Ok(Ok(api_calls))
    }
}

impl Check for OllamaExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties)
    }
}

fn check_linux_host(host_properties: &HostProperties) -> Result<(), RegentError> {
    match host_properties.os_kind() {
        OsKind::Linux(_) => Ok(()),
        incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
            "Host is {:?} but Ollama Attribute is only supported for Linux",
            incompatible_os_kind
        ))),
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for OllamaExpectedState {
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

        let binary_path = locate_ollama(host_handler).await?;
        let api_calls = match (&self, binary_path) {
            (OllamaExpectedState::Absent, None) => Vec::new(),
            (OllamaExpectedState::Absent, Some(binary_path)) => {
                vec![OllamaModuleInternalApiCall::Uninstall { binary_path }]
            }
            (
                OllamaExpectedState::Present {
                    api_config: _api_config,
                    models: _models,
                },
                None,
            ) => self.installation_api_calls(),
            (
                OllamaExpectedState::Present {
                    api_config: _api_config,
                    models: _models,
                },
                Some(_),
            ) => match self.configuration_api_calls(host_handler).await? {
                Ok(api_calls) => api_calls,
                Err(reason) => {
                    return Ok(AttributeComplianceAssessment::NonCompliantFatal(reason));
                }
            },
        };

        if api_calls.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        let remediations = api_calls
            .into_iter()
            .map(|api_call| Remediation::Ollama(OllamaApiCall::from(api_call, privilege.clone())))
            .collect();
        Ok(AttributeComplianceAssessment::NonCompliant(
            RemediationsList::from(remediations)?,
        ))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const OLLAMA_UNIT: &str = "ollama";
const UNIT_FILE: &str = "/etc/systemd/system/ollama.service";
const OVERRIDE_DIR: &str = "/etc/systemd/system/ollama.service.d";
const OVERRIDE_FILE: &str = "/etc/systemd/system/ollama.service.d/override.conf";
const INSTALL_SCRIPT_URL: &str = "https://ollama.com/install.sh";
/// Where the install script puts the binary, whatever `command -v` finds first
const WELL_KNOWN_BINARIES: [&str; 2] = ["/usr/local/bin/ollama", "/usr/bin/ollama"];
const INSTALLATION_DIRECTORIES: [&str; 4] = [
    "/usr/local/lib/ollama",
    "/usr/lib/ollama",
    "/usr/share/ollama",
    OVERRIDE_DIR,
];

/// Appends `:latest` if the model name contains no `:`.
fn normalize_model_name(name: &str) -> String {
    if name.contains(':') {
        name.to_string()
    } else {
        format!("{}:latest", name)
    }
}

/// `ollama <args>` talking to the API at `host` (Ollama's default address when `None`)
fn ollama_command(host: Option<&str>, args: &[&str]) -> String {
    let mut words = vec!["ollama"];
    words.extend(args);
    let command = quoted_command(&words);
    match host {
        Some(host) => format!("OLLAMA_HOST={} {}", shell_quote(host), command),
        None => command,
    }
}

fn locate_command() -> String {
    quoted_command(&["command", "-v", "ollama"])
}

/// Path printed by `command -v ollama`. With sudo, stderr is folded into
/// stdout: only the last line holding an absolute path counts.
fn parse_command_v(return_code: i64, stdout: &str) -> Option<String> {
    if return_code != 0 {
        return None;
    }
    stdout
        .lines()
        .map(str::trim)
        .rfind(|line| line.starts_with('/'))
        .map(str::to_string)
}

/// Path of the `ollama` binary, `None` when Ollama is not installed
async fn locate_ollama<Handler: HostHandler>(
    host_handler: &mut Handler,
) -> Result<Option<String>, RegentError> {
    let result = query(host_handler, &locate_command(), &Privilege::None).await?;
    Ok(parse_command_v(result.return_code, &result.stdout))
}

/// Model names, first column of `ollama list` (header skipped)
fn parse_ollama_list(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// `OLLAMA_HOST` set by an override file written by [`build_api_config_content`]
fn host_in_override(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Environment=\"OLLAMA_HOST=")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_string)
    })
}

/// Builds the content of `/etc/systemd/system/ollama.service.d/override.conf`
/// from an `OllamaApiConfig`.
pub fn build_api_config_content(api: &OllamaApiConfig) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("[Service]".to_string());

    if let Some(host) = &api.host {
        lines.push(format!("Environment=\"OLLAMA_HOST={}\"", host));
    }
    if let Some(origins) = &api.origins {
        lines.push(format!(
            "Environment=\"OLLAMA_ORIGINS={}\"",
            origins.join(",")
        ));
    }
    if let Some(models_path) = &api.models_path {
        lines.push(format!("Environment=\"OLLAMA_MODELS={}\"", models_path));
    }
    if let Some(keep_alive) = &api.keep_alive {
        lines.push(format!("Environment=\"OLLAMA_KEEP_ALIVE={}\"", keep_alive));
    }
    if let Some(num_parallel) = api.num_parallel {
        lines.push(format!(
            "Environment=\"OLLAMA_NUM_PARALLEL={}\"",
            num_parallel
        ));
    }
    if let Some(max_loaded_models) = api.max_loaded_models {
        lines.push(format!(
            "Environment=\"OLLAMA_MAX_LOADED_MODELS={}\"",
            max_loaded_models
        ));
    }
    if let Some(gpu_layers) = api.gpu_layers {
        lines.push(format!("Environment=\"OLLAMA_GPU_LAYERS={}\"", gpu_layers));
    }

    // The trailing newline is part of the file written by WriteApiConfig: the
    // assessment compares the whole file content.
    format!("{}\n", lines.join("\n"))
}

/// Splits an `OLLAMA_HOST` value into a listen address and port. Returns
/// `None` when the value has no port or the address is not an IP literal
/// (e.g. a hostname): the live listen check only applies to IP literals.
fn api_listen_address(host: &str) -> Option<(String, u16)> {
    let (address, port) = host.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let address = address.trim_start_matches('[').trim_end_matches(']');
    match address.parse::<std::net::IpAddr>() {
        Ok(address) => Some((address.to_string(), port)),
        Err(_details) => None,
    }
}

/// Whether `ss -tln` output shows a LISTEN socket bound to `address:port`.
/// A wildcard expectation (`0.0.0.0`, `::`) is also satisfied by the other
/// wildcard representations (`*`, `[::]`).
fn listens_on(ss_output: &str, address: &str, port: u16) -> bool {
    let expected = format!("{}:{}", address, port);
    let expected_v6 = format!("[{}]:{}", address, port);
    let wildcard = matches!(address, "0.0.0.0" | "::" | "*");
    ss_output.lines().any(|line| {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 4 || columns[0] != "LISTEN" {
            return false;
        }
        let local = columns[3];
        local == expected || local == expected_v6 || (wildcard && is_wildcard_bind(local, port))
    })
}

fn is_wildcard_bind(local: &str, port: u16) -> bool {
    match local.strip_suffix(&format!(":{}", port)) {
        Some(address) => matches!(address, "0.0.0.0" | "*" | "::" | "[::]"),
        None => false,
    }
}

fn systemctl(args: &[&str]) -> String {
    let mut words = vec!["systemctl"];
    words.extend(args);
    quoted_command(&words)
}

/// Write the override file and make systemd read it
fn write_override_commands(content: &str) -> Vec<String> {
    vec![
        quoted_command(&["mkdir", "-p", OVERRIDE_DIR]),
        format!(
            "printf '%s' {} > {}",
            shell_quote(content),
            shell_quote(OVERRIDE_FILE)
        ),
        systemctl(&["daemon-reload"]),
    ]
}

/// Remove the files of an installation whose binary was found at `binary_path`
fn removal_commands(binary_path: &str) -> Vec<String> {
    let mut binaries = vec![binary_path];
    binaries.extend(
        WELL_KNOWN_BINARIES
            .iter()
            .filter(|path| **path != binary_path),
    );
    let mut remove_binaries = vec!["rm", "-f"];
    remove_binaries.extend(binaries);
    let mut remove_directories = vec!["rm", "-rf"];
    remove_directories.extend(INSTALLATION_DIRECTORIES);
    vec![
        quoted_command(&remove_binaries),
        quoted_command(&remove_directories),
        quoted_command(&["rm", "-f", UNIT_FILE]),
        systemctl(&["daemon-reload"]),
    ]
}

/// The platform helpers report a command that could not be run as an
/// assessment error: during a remediation, it is a failure to run it.
fn as_remediation_error(error: RegentError) -> RegentError {
    match error {
        RegentError::FailedDryRunEvaluation(details) => RegentError::FailureToRunCommand(details),
        other => other,
    }
}

async fn install<Handler: HostHandler>(
    host_handler: &mut Handler,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let tmp = match make_temp_dir(host_handler, privilege)
        .await
        .map_err(as_remediation_error)?
    {
        Ok(tmp) => tmp,
        Err(failure) => return Ok(failure),
    };
    let script = format!("{}/install.sh", tmp);
    let mut outcome = download(host_handler, INSTALL_SCRIPT_URL, &script, privilege).await;
    if is_success(&outcome) {
        outcome = run_step(host_handler, &quoted_command(&["sh", &script]), privilege).await;
    }
    remove_temp_dir(host_handler, &tmp, privilege).await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }

    match locate_ollama(host_handler)
        .await
        .map_err(as_remediation_error)?
    {
        Some(_) => Ok(outcome),
        None => Ok(InternalApiCallOutcome::Failure(format!(
            "The Ollama install script succeeded but {} does not find ollama",
            locate_command()
        ))),
    }
}

async fn write_api_config<Handler: HostHandler>(
    host_handler: &mut Handler,
    content: &str,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let outcome = run_steps(host_handler, &write_override_commands(content), privilege).await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }
    // A stopped service is started later (Service attribute) with the
    // override in place.
    let unit = unit_state(host_handler, OLLAMA_UNIT, privilege)
        .await
        .map_err(as_remediation_error)?;
    if unit.active {
        return Ok(run_step(
            host_handler,
            &systemctl(&["restart", OLLAMA_UNIT]),
            privilege,
        )
        .await);
    }
    Ok(outcome)
}

/// Following https://docs.ollama.com/linux#uninstall
async fn uninstall<Handler: HostHandler>(
    host_handler: &mut Handler,
    binary_path: &str,
    privilege: &Privilege,
) -> Result<InternalApiCallOutcome, RegentError> {
    let unit = unit_state(host_handler, OLLAMA_UNIT, privilege)
        .await
        .map_err(as_remediation_error)?;
    let mut steps = Vec::new();
    if unit.active {
        steps.push(systemctl(&["stop", OLLAMA_UNIT]));
    }
    if unit.enablement == UnitEnablement::Enabled {
        steps.push(systemctl(&["disable", OLLAMA_UNIT]));
    }
    steps.extend(removal_commands(binary_path));
    let outcome = run_steps(host_handler, &steps, privilege).await;
    if !is_success(&outcome) {
        return Ok(outcome);
    }

    // userdel may remove the group too: the group is looked up afterwards
    let account_removals: [(&[&str], &[&str]); 2] = [
        (&["id", "ollama"], &["userdel", "ollama"]),
        (&["getent", "group", "ollama"], &["groupdel", "ollama"]),
    ];
    for (lookup, removal) in account_removals {
        let lookup = quoted_command(lookup);
        let exists = host_handler
            .run_command(&lookup, privilege)
            .await
            .map_err(|e| {
                RegentError::FailureToRunCommand(format!("Unable to run {:?}: {:?}", lookup, e))
            })?
            .return_code
            == 0;
        if exists {
            let outcome = run_step(host_handler, &quoted_command(removal), privilege).await;
            if !is_success(&outcome) {
                return Ok(outcome);
            }
        }
    }

    match locate_ollama(host_handler)
        .await
        .map_err(as_remediation_error)?
    {
        Some(path) => Ok(InternalApiCallOutcome::Failure(format!(
            "ollama is still found at {} after the uninstallation",
            path
        ))),
        None => Ok(outcome),
    }
}

// ── ApiCall variants ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaModuleInternalApiCall {
    /// Install Ollama using the official install script
    Install,
    /// Uninstall Ollama and clean up all files
    Uninstall {
        /// Found by `command -v ollama` during the assessment
        binary_path: String,
    },
    PullModel {
        name: String,
        /// Address of the API (`OLLAMA_HOST`), Ollama's default when `None`
        #[serde(default)]
        host: Option<String>,
    },
    RemoveModel {
        name: String,
        /// Address of the API (`OLLAMA_HOST`), Ollama's default when `None`
        #[serde(default)]
        host: Option<String>,
    },
    WriteApiConfig {
        content: String,
    },
    /// Restart the ollama service so the API configuration takes effect
    RestartService,
}

impl std::fmt::Display for OllamaModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OllamaModuleInternalApiCall::Install => write!(f, "install ollama"),
            OllamaModuleInternalApiCall::Uninstall { .. } => write!(f, "uninstall ollama"),
            OllamaModuleInternalApiCall::PullModel { name, .. } => {
                write!(f, "pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name, .. } => {
                write!(f, "remove model {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { .. } => {
                write!(f, "write ollama api config")
            }
            OllamaModuleInternalApiCall::RestartService => {
                write!(f, "restart the ollama service")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OllamaApiCall {
    pub api_call: OllamaModuleInternalApiCall,
    privilege: Privilege,
}

impl OllamaApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            OllamaModuleInternalApiCall::Install => "Install ollama".to_string(),
            OllamaModuleInternalApiCall::Uninstall { binary_path } => {
                format!("Uninstall ollama ({})", binary_path)
            }
            OllamaModuleInternalApiCall::PullModel { name, .. } => {
                format!("Pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name, .. } => {
                format!("Remove model {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { .. } => {
                "Configure ollama REST API".to_string()
            }
            OllamaModuleInternalApiCall::RestartService => {
                "Restart the ollama service (to apply the API configuration)".to_string()
            }
        }
    }

    fn from(api_call: OllamaModuleInternalApiCall, privilege: Privilege) -> OllamaApiCall {
        OllamaApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for OllamaApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        check_linux_host(host_properties)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for OllamaApiCall {
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
            OllamaModuleInternalApiCall::Install => install(host_handler, privilege).await,
            OllamaModuleInternalApiCall::Uninstall { binary_path } => {
                uninstall(host_handler, binary_path, privilege).await
            }
            OllamaModuleInternalApiCall::WriteApiConfig { content } => {
                write_api_config(host_handler, content, privilege).await
            }
            OllamaModuleInternalApiCall::PullModel { name, host } => Ok(run_step(
                host_handler,
                &ollama_command(host.as_deref(), &["pull", name]),
                privilege,
            )
            .await),
            OllamaModuleInternalApiCall::RemoveModel { name, host } => Ok(run_step(
                host_handler,
                &ollama_command(host.as_deref(), &["rm", name]),
                privilege,
            )
            .await),
            OllamaModuleInternalApiCall::RestartService => Ok(run_step(
                host_handler,
                &systemctl(&["restart", OLLAMA_UNIT]),
                privilege,
            )
            .await),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::attribute::Attribute;

    #[test]
    fn model_constructors_set_the_state() {
        assert_eq!(
            OllamaModel::present("llama3"),
            OllamaModel {
                name: "llama3".to_string(),
                state: OllamaModelState::Present,
            }
        );
        assert_eq!(
            OllamaModel::absent("mistral:7b"),
            OllamaModel {
                name: "mistral:7b".to_string(),
                state: OllamaModelState::Absent,
            }
        );
    }

    #[test]
    fn scratch_probe_yaml_format() {
        let present = OllamaExpectedState::present_with_config_and_models(
            OllamaApiConfig::new().with_listening_endpoint("0.0.0.0:11434"),
            vec![OllamaModel::present("llama3")],
        );
        println!(
            "=== serialized present ===\n{}",
            yaml_serde::to_string(&present).unwrap()
        );
        println!(
            "=== serialized absent ===\n{}",
            yaml_serde::to_string(&OllamaExpectedState::absent()).unwrap()
        );

        let candidates = [
            (
                "externally_tagged_map",
                "---\nPresent:\n  ApiConfig:\n    Host: '0.0.0.0:11434'\n  Models:\n    - Name: llama3\n      State: Present\n",
            ),
            ("plain_absent", "---\nAbsent\n"),
            (
                "old_struct_format",
                "---\nState: Present\nApiConfig:\n  Host: '0.0.0.0:11434'\nModels:\n  - Name: llama3\n    State: Present\n",
            ),
        ];
        for (label, raw) in candidates {
            match yaml_serde::from_str::<OllamaExpectedState>(raw) {
                Ok(value) => println!("{label}: OK -> {value:?}"),
                Err(error) => println!("{label}: ERR -> {error}"),
            }
        }

        let envelope_candidates = [
            (
                "nested_externally_tagged",
                "---\nName: test\nPrivilege: !WithSudo\nDetail: !Ollama\n  Present:\n    ApiConfig:\n      Host: '0.0.0.0:11434'\n    Models:\n      - Name: llama3\n        State: Present\n",
            ),
            (
                "nested_absent_scalar",
                "---\nName: test\nPrivilege: !WithSudo\nDetail: !Ollama Absent\n",
            ),
            (
                "nested_absent_block",
                "---\nName: test\nPrivilege: !WithSudo\nDetail: !Ollama\n  Absent\n",
            ),
        ];
        for (label, raw) in envelope_candidates {
            match yaml_serde::from_str::<Attribute>(raw) {
                Ok(value) => println!("{label}: OK -> {value:?}"),
                Err(error) => println!("{label}: ERR -> {error}"),
            }
        }

        let full = "\
Attributes:
  - Name: Ollama must be installed with qwen2.5:1.5b
    Privilege: !WithSudo
    Timeout: 30m
    Detail: !Ollama
      Present:
        ApiConfig:
          Host: '0.0.0.0:11434'
        Models:
          - Name: qwen2.5:1.5b
            State: Present
";
        match crate::state::ExpectedState::from_raw_yaml(full) {
            Ok(value) => println!(
                "full_expected_state: OK -> {} attributes",
                value.attributes.len()
            ),
            Err(error) => println!("full_expected_state: ERR -> {error}"),
        }
    }

    #[test]
    fn parsing_ollama_module_block_from_yaml_str() {
        let raw = "---
State: Present
ApiConfig:
  Host: '0.0.0.0:11434'
  Origins:
    - '*'
  KeepAlive: 5m
  NumParallel: 4
  MaxLoadedModels: 2
  GpuLayers: -1
Models:
  - Name: llama3
    State: Present
  - Name: mistral:7b
    State: Absent
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(block.state, OllamaExpectedState::Present);
        assert!(block.check().is_ok());

        let api_config = block.api_config.as_ref().unwrap();
        assert_eq!(api_config.host, Some("0.0.0.0:11434".to_string()));
        assert_eq!(api_config.origins, Some(vec!["*".to_string()]));
        assert_eq!(api_config.keep_alive, Some("5m".to_string()));
        assert_eq!(api_config.num_parallel, Some(4));
        assert_eq!(api_config.max_loaded_models, Some(2));
        assert_eq!(api_config.gpu_layers, Some(-1));

        let models = block.models.as_ref().unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].name, "llama3");
        assert_eq!(models[0].state, OllamaModelState::Present);
        assert_eq!(models[1].name, "mistral:7b");
        assert_eq!(models[1].state, OllamaModelState::Absent);

        // Absent carries neither config nor models
        let raw = "---
State: Absent
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(block, OllamaExpectedState::absent());
        assert!(block.check().is_ok());

        // ... and cannot carry them
        let raw = "---
State: Absent
Models:
  - Name: llama3
    State: Present
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        assert!(block.check().is_err());
    }

    #[test]
    fn parsing_full_ollama_attribute_envelope_from_yaml_str() {
        // Regression test: the payload of `Detail: !Ollama` is a struct, so the
        // whole attribute must parse from YAML (an enum payload nested in
        // another enum's tag is not supported by the YAML deserializer).
        let raw_attribute = "---
Name: Ollama with the llama3 model must be installed
Privilege: !WithSudo
Timeout: 10m
Detail: !Ollama
  State: Present
  ApiConfig:
    Host: '0.0.0.0:11434'
  Models:
    - Name: llama3
      State: Present
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
        assert_eq!(
            attribute.name(),
            "Ollama with the llama3 model must be installed"
        );
    }

    #[test]
    fn parsing_ollama_expected_state_from_raw_yaml() {
        // The exact entry point the `reg` CLI uses.
        let raw = "
Attributes:
  - Name: Ollama must be installed with qwen2.5:1.5b
    Privilege: !WithSudo
    Timeout: 30m
    Detail: !Ollama
      State: Present
      ApiConfig:
        Host: '0.0.0.0:11434'
      Models:
        - Name: qwen2.5:1.5b
          State: Present
";
        let expected_state = crate::state::ExpectedState::from_raw_yaml(raw).unwrap();
        assert_eq!(expected_state.attributes.len(), 1);
    }

    #[test]
    fn model_name_normalization() {
        assert_eq!(normalize_model_name("llama3"), "llama3:latest");
        assert_eq!(normalize_model_name("mistral:7b"), "mistral:7b");
        assert_eq!(normalize_model_name("codellama:13b"), "codellama:13b");
    }

    #[test]
    fn command_v_output_is_parsed() {
        assert_eq!(
            parse_command_v(0, "/usr/local/bin/ollama\n"),
            Some("/usr/local/bin/ollama".to_string())
        );
        assert_eq!(
            parse_command_v(0, "sudo: some warning\n/usr/bin/ollama\n"),
            Some("/usr/bin/ollama".to_string())
        );
        assert_eq!(parse_command_v(1, ""), None);
        assert_eq!(parse_command_v(1, "/usr/bin/ollama\n"), None);
        // An alias or a function is not an installed binary
        assert_eq!(parse_command_v(0, "ollama\n"), None);
        assert_eq!(locate_command(), "'command' '-v' 'ollama'");
    }

    #[test]
    fn ollama_list_output_is_parsed() {
        let output = "\
NAME            ID              SIZE      MODIFIED
llama3:latest   365c0bd3c000    4.7 GB    2 days ago
qwen2.5:1.5b    65ec06548149    986 MB    3 weeks ago
";
        assert_eq!(
            parse_ollama_list(output),
            vec!["llama3:latest", "qwen2.5:1.5b"]
        );
        assert!(parse_ollama_list("NAME ID SIZE MODIFIED\n").is_empty());
    }

    #[test]
    fn host_is_read_from_the_override_file() {
        let content = build_api_config_content(
            &OllamaApiConfig::new()
                .with_listening_endpoint("0.0.0.0:11500")
                .with_cors_origins(&["*"]),
        );
        assert_eq!(
            host_in_override(&content),
            Some("0.0.0.0:11500".to_string())
        );
        assert_eq!(
            host_in_override(&build_api_config_content(&OllamaApiConfig::new())),
            None
        );
        assert_eq!(host_in_override(""), None);
    }

    #[test]
    fn missing_ollama_is_installed_configured_and_gets_its_models_in_one_run() {
        let expected_state = OllamaExpectedState::present_with_config_and_models(
            OllamaApiConfig::new().with_listening_endpoint("0.0.0.0:11500"),
            vec![
                OllamaModel::present("llama3"),
                OllamaModel::absent("mistral"),
            ],
        );
        assert_eq!(
            expected_state.installation_api_calls(),
            vec![
                OllamaModuleInternalApiCall::Install,
                OllamaModuleInternalApiCall::WriteApiConfig {
                    content: "[Service]\nEnvironment=\"OLLAMA_HOST=0.0.0.0:11500\"\n".to_string()
                },
                OllamaModuleInternalApiCall::PullModel {
                    name: "llama3:latest".to_string(),
                    host: Some("0.0.0.0:11500".to_string()),
                },
            ]
        );
        assert_eq!(
            OllamaExpectedState::present_with_default_config().installation_api_calls(),
            vec![OllamaModuleInternalApiCall::Install]
        );
    }

    #[test]
    fn api_listen_address_parses_ip_literals() {
        assert_eq!(
            api_listen_address("0.0.0.0:11434"),
            Some(("0.0.0.0".to_string(), 11434))
        );
        assert_eq!(
            api_listen_address("127.0.0.1:11434"),
            Some(("127.0.0.1".to_string(), 11434))
        );
        assert_eq!(
            api_listen_address("[::]:11434"),
            Some(("::".to_string(), 11434))
        );
        // Hostnames are not checked live.
        assert_eq!(api_listen_address("localhost:11434"), None);
        assert_eq!(api_listen_address("0.0.0.0"), None);
        assert_eq!(api_listen_address("0.0.0.0:notaport"), None);
        assert_eq!(api_listen_address("0.0.0.0:99999"), None);
    }

    #[test]
    fn listens_on_matches_ss_output() {
        let ss = "\
State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0      4096   127.0.0.1:11434    0.0.0.0:*
LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
LISTEN 0      128    [::]:22            [::]:*
";
        assert!(listens_on(ss, "127.0.0.1", 11434));
        // No match: bound to loopback only.
        assert!(!listens_on(ss, "0.0.0.0", 11434));
        // Wildcard expectation satisfied by the other wildcard forms.
        assert!(listens_on(ss, "0.0.0.0", 22));
        assert!(listens_on(ss, "::", 22));
        assert!(!listens_on(ss, "0.0.0.0", 8080));
        // Header line is never a match.
        assert!(!listens_on("State Recv-Q Send-Q Local Peer\n", "State", 0));

        let ss_star = "LISTEN 0 4096 *:11434 0.0.0.0:*\n";
        assert!(listens_on(ss_star, "0.0.0.0", 11434));
        assert!(listens_on(ss_star, "::", 11434));
        assert!(!listens_on(ss_star, "127.0.0.1", 11434));
    }

    #[test]
    fn commands_quote_every_value() {
        assert_eq!(ollama_command(None, &["list"]), "'ollama' 'list'");
        assert_eq!(
            ollama_command(Some("0.0.0.0:11500"), &["list"]),
            "OLLAMA_HOST='0.0.0.0:11500' 'ollama' 'list'"
        );
        assert_eq!(
            ollama_command(Some("0.0.0.0:11500"), &["pull", "qwen2.5:1.5b"]),
            "OLLAMA_HOST='0.0.0.0:11500' 'ollama' 'pull' 'qwen2.5:1.5b'"
        );
        assert_eq!(
            ollama_command(None, &["rm", "x'; rm -rf /; '"]),
            "'ollama' 'rm' 'x'\\''; rm -rf /; '\\'''"
        );
        assert_eq!(
            systemctl(&["restart", OLLAMA_UNIT]),
            "'systemctl' 'restart' 'ollama'"
        );
    }

    #[test]
    fn override_file_is_written_in_separate_steps() {
        let content = "[Service]\nEnvironment=\"OLLAMA_ORIGINS=it's\"\n";
        assert_eq!(
            write_override_commands(content),
            vec![
                "'mkdir' '-p' '/etc/systemd/system/ollama.service.d'".to_string(),
                "printf '%s' '[Service]\nEnvironment=\"OLLAMA_ORIGINS=it'\\''s\"\n' > '/etc/systemd/system/ollama.service.d/override.conf'".to_string(),
                "'systemctl' 'daemon-reload'".to_string(),
            ]
        );
    }

    #[test]
    fn uninstallation_removes_every_installed_file() {
        assert_eq!(
            removal_commands("/usr/local/bin/ollama"),
            vec![
                "'rm' '-f' '/usr/local/bin/ollama' '/usr/bin/ollama'".to_string(),
                "'rm' '-rf' '/usr/local/lib/ollama' '/usr/lib/ollama' '/usr/share/ollama' '/etc/systemd/system/ollama.service.d'".to_string(),
                "'rm' '-f' '/etc/systemd/system/ollama.service'".to_string(),
                "'systemctl' 'daemon-reload'".to_string(),
            ]
        );
        assert_eq!(
            removal_commands("/opt/bin/ollama")[0],
            "'rm' '-f' '/opt/bin/ollama' '/usr/local/bin/ollama' '/usr/bin/ollama'"
        );
    }

    #[test]
    fn restart_service_is_displayed() {
        assert_eq!(
            OllamaModuleInternalApiCall::RestartService.to_string(),
            "restart the ollama service"
        );
        let api_call = OllamaApiCall::from(
            OllamaModuleInternalApiCall::RestartService,
            Privilege::WithSudo,
        );
        assert_eq!(
            api_call.display(),
            "Restart the ollama service (to apply the API configuration)"
        );
        let api_call = OllamaApiCall::from(
            OllamaModuleInternalApiCall::Uninstall {
                binary_path: "/usr/local/bin/ollama".to_string(),
            },
            Privilege::WithSudo,
        );
        assert_eq!(api_call.api_call.to_string(), "uninstall ollama");
        assert_eq!(
            api_call.display(),
            "Uninstall ollama (/usr/local/bin/ollama)"
        );
    }

    #[test]
    fn api_config_builder_methods() {
        let api_config = OllamaApiConfig::new()
            .with_listening_endpoint("0.0.0.0:11434")
            .with_cors_origins(&["*"])
            .with_models_path("/data/ollama")
            .with_keep_alive(Duration::from_secs(300))
            .with_num_parallel(4)
            .with_max_loaded_models(2)
            .with_all_gpu_layers();
        assert_eq!(
            build_api_config_content(&api_config),
            "[Service]
Environment=\"OLLAMA_HOST=0.0.0.0:11434\"
Environment=\"OLLAMA_ORIGINS=*\"
Environment=\"OLLAMA_MODELS=/data/ollama\"
Environment=\"OLLAMA_KEEP_ALIVE=300000ms\"
Environment=\"OLLAMA_NUM_PARALLEL=4\"
Environment=\"OLLAMA_MAX_LOADED_MODELS=2\"
Environment=\"OLLAMA_GPU_LAYERS=-1\"
"
        );

        let api_config = OllamaApiConfig::new()
            .with_models_kept_loaded_forever()
            .with_gpu_layers(33);
        assert_eq!(api_config.keep_alive, Some("-1".to_string()));
        assert_eq!(api_config.gpu_layers, Some(33));
    }
}
