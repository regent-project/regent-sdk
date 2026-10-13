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
//!     OllamaApiConfig, OllamaExpectedState, OllamaModel, OllamaModelState,
//! };
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install Ollama, expose the API on all interfaces, and pull a model
//! let ollama = OllamaExpectedState::present_with_default_config()
//!     .with_api_config(OllamaApiConfig {
//!         host: Some("0.0.0.0:11434".to_string()),
//!         ..Default::default()
//!     })
//!     .with_models(vec![OllamaModel {
//!         name: "llama3".to_string(),
//!         state: OllamaModelState::Present,
//!     }]);
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
use std::time::Duration;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaModelState {
    Present,
    Absent,
}

// ── Sub-structs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaModel {
    /// Name of the model (e.g., "llama3", "mistral:7b")
    pub name: String,
    pub state: OllamaModelState,
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

// ── BlockExpectedState ────────────────────────────────────────────────────────

/// Whether Ollama must be installed on the host
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaState {
    /// Ollama must be installed (and configured, when `ApiConfig` / `Models` are set)
    Present,
    /// Ollama must be removed
    Absent,
}

/// Configuration for the Ollama AI inference engine
///
/// `ApiConfig` and `Models` are only managed in the `Present` state: an
/// `Absent` state carrying them is rejected by [`Check::check`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaExpectedState {
    /// Install or remove Ollama
    state: OllamaState,
    /// REST API / environment configuration (written to the systemd override file)
    api_config: Option<OllamaApiConfig>,
    /// LLM models to manage (pull or remove)
    models: Option<Vec<OllamaModel>>,
}

impl Timeout for OllamaExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl OllamaExpectedState {
    pub fn absent() -> OllamaExpectedState {
        OllamaExpectedState {
            state: OllamaState::Absent,
            api_config: None,
            models: None,
        }
    }

    pub fn present_with_default_config() -> OllamaExpectedState {
        OllamaExpectedState {
            state: OllamaState::Present,
            api_config: None,
            models: None,
        }
    }

    pub fn present_with_config(api_config: OllamaApiConfig) -> OllamaExpectedState {
        OllamaExpectedState::present_with_default_config().with_api_config(api_config)
    }

    pub fn present_with_models(models: Vec<OllamaModel>) -> OllamaExpectedState {
        OllamaExpectedState::present_with_default_config().with_models(models)
    }

    pub fn present_with_config_and_models(
        api_config: OllamaApiConfig,
        models: Vec<OllamaModel>,
    ) -> OllamaExpectedState {
        OllamaExpectedState::present_with_config(api_config).with_models(models)
    }

    pub fn with_api_config(mut self, api_config: OllamaApiConfig) -> Self {
        self.api_config = Some(api_config);
        self
    }

    pub fn with_models(mut self, models: Vec<OllamaModel>) -> Self {
        self.models = Some(models);
        self
    }
}

impl Check for OllamaExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.state == OllamaState::Absent && (self.api_config.is_some() || self.models.is_some())
        {
            return Err(RegentError::IncoherentExpectedState(
                "Ollama Absent state cannot carry an ApiConfig or Models".to_string(),
            ));
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
                "Host is {:?} but Ollama Attribute is only supported for Linux",
                incompatible_os_kind
            ))),
        }
    }
}

// ── assess_compliance ─────────────────────────────────────────────────────────

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

        let mut remediations: Vec<Remediation> = Vec::new();

        // ── Step 1: check whether ollama is installed ─────────────────────────
        let ollama_is_installed = host_handler
            .run_command(
                "test -f /usr/local/bin/ollama || which ollama 2>/dev/null",
                &Privilege::None,
            )
            .await
            .unwrap()
            .return_code
            == 0;

        match &self.state {
            OllamaState::Absent => {
                if ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Uninstall,
                        privilege.clone(),
                    )));
                }
            }
            OllamaState::Present => {
                if !ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Install,
                        privilege.clone(),
                    )));
                } else {
                    // ***** Configuration *****
                    if let Some(api_config) = &self.api_config {
                        let expected_content = build_api_config_content(api_config);

                        let current_result = host_handler
                            .run_command(
                                "cat /etc/systemd/system/ollama.service.d/override.conf 2>/dev/null",
                                &Privilege::None,
                            )
                            .await
                            .unwrap();

                        let current_content = if current_result.return_code == 0 {
                            current_result.stdout.clone()
                        } else {
                            String::new()
                        };

                        if current_content != expected_content {
                            remediations.push(Remediation::Ollama(OllamaApiCall::from(
                                OllamaModuleInternalApiCall::WriteApiConfig {
                                    content: expected_content,
                                },
                                privilege.clone(),
                            )));
                        } else if let Some((address, port)) =
                            api_config.host.as_deref().and_then(api_listen_address)
                        {
                            // The override file matches, but the running daemon may
                            // predate it: it must listen on the expected address.
                            // A stopped service is left alone: the Service
                            // attribute starts it with the override in place.
                            let service_is_active = host_handler
                                .run_command("systemctl is-active --quiet ollama", &Privilege::None)
                                .await
                                .unwrap()
                                .return_code
                                == 0;
                            if service_is_active {
                                let sockets = host_handler
                                    .run_command("ss -tln", &Privilege::None)
                                    .await
                                    .unwrap();
                                if sockets.return_code == 0
                                    && !listens_on(&sockets.stdout, &address, port)
                                {
                                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                                        OllamaModuleInternalApiCall::RestartService,
                                        privilege.clone(),
                                    )));
                                }
                            }
                        }
                    }

                    // ***** Models *****
                    if let Some(models) = &self.models {
                        let installed_models = installed_models(host_handler).await;

                        for model in models {
                            let normalized_name = normalize_model_name(&model.name);

                            match model.state {
                                OllamaModelState::Present => {
                                    if !installed_models.contains(&normalized_name) {
                                        remediations.push(Remediation::Ollama(
                                            OllamaApiCall::from(
                                                OllamaModuleInternalApiCall::PullModel {
                                                    name: normalized_name,
                                                },
                                                privilege.clone(),
                                            ),
                                        ));
                                    }
                                }
                                OllamaModelState::Absent => {
                                    if installed_models.contains(&normalized_name) {
                                        remediations.push(Remediation::Ollama(
                                            OllamaApiCall::from(
                                                OllamaModuleInternalApiCall::RemoveModel {
                                                    name: normalized_name,
                                                },
                                                privilege.clone(),
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Appends `:latest` if the model name contains no `:`.
fn normalize_model_name(name: &str) -> String {
    if name.contains(':') {
        name.to_string()
    } else {
        format!("{}:latest", name)
    }
}

/// Model names currently present on the host, first column of `ollama list`
/// (header skipped); empty when ollama is not usable.
async fn installed_models<Handler: HostHandler>(host_handler: &mut Handler) -> Vec<String> {
    let Ok(result) = host_handler
        .run_command("ollama list 2>/dev/null", &Privilege::None)
        .await
    else {
        return Vec::new();
    };
    if result.return_code != 0 {
        return Vec::new();
    }
    result
        .stdout
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
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

    // Terminate with a trailing newline, matching the file format produced by
    // the WriteApiConfig command.
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

/// Whether an `ss` local address column is a wildcard bind on `port`.
fn is_wildcard_bind(local: &str, port: u16) -> bool {
    match local.strip_suffix(&format!(":{}", port)) {
        Some(address) => matches!(address, "0.0.0.0" | "*" | "::" | "[::]"),
        None => false,
    }
}

/// Escapes a string for use as the argument to `printf`: replaces `\` with `\\`,
/// `%` with `%%`, and newlines with `\n`.
fn escape_for_printf(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "%%")
        .replace('\n', "\\n")
}

// ── ApiCall variants ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaModuleInternalApiCall {
    /// Install Ollama using the official install script
    Install,
    /// Uninstall Ollama and clean up all files
    Uninstall,
    /// Pull a model from the Ollama registry
    PullModel {
        name: String,
    },
    RemoveModel {
        name: String,
    },
    /// Write API configuration to systemd override file
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
            OllamaModuleInternalApiCall::Uninstall => write!(f, "uninstall ollama"),
            OllamaModuleInternalApiCall::PullModel { name } => {
                write!(f, "pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
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
            OllamaModuleInternalApiCall::Uninstall => "Uninstall ollama".to_string(),
            OllamaModuleInternalApiCall::PullModel { name } => {
                format!("Pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
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
        match host_properties.os_kind() {
            OsKind::Linux(_) | OsKind::MacOs(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but Ollama is only supported on Linux and macOS",
                incompatible_os_kind
            ))),
        }
    }
}

/// Builds the shell command executed for an [`OllamaModuleInternalApiCall`].
fn ollama_api_call_command(api_call: &OllamaModuleInternalApiCall) -> String {
    match api_call {
        OllamaModuleInternalApiCall::Install => concat!(
            "curl -fsSL -o /tmp/regent-ollama-install.sh https://ollama.com/install.sh && ",
            "sh /tmp/regent-ollama-install.sh"
        )
        .to_string(),
        OllamaModuleInternalApiCall::Uninstall => concat!(
            "systemctl stop ollama 2>/dev/null; ",
            "systemctl disable ollama 2>/dev/null; ",
            "rm -f /usr/local/bin/ollama /usr/bin/ollama; ",
            "rm -f /etc/systemd/system/ollama.service; ",
            "systemctl daemon-reload 2>/dev/null; ",
            "rm -rf /usr/share/ollama"
        )
        .to_string(),
        OllamaModuleInternalApiCall::PullModel { name } => {
            format!("ollama pull {}", name)
        }
        OllamaModuleInternalApiCall::RemoveModel { name } => {
            format!("ollama rm {}", name)
        }
        OllamaModuleInternalApiCall::WriteApiConfig { content } => {
            let escaped = escape_for_printf(content);
            // Restart only when the service is active: a stopped service is
            // started later (Service attribute) with the override in place.
            format!(
                concat!(
                    "mkdir -p /etc/systemd/system/ollama.service.d && ",
                    "printf '{}' > /etc/systemd/system/ollama.service.d/override.conf; ",
                    "systemctl daemon-reload; ",
                    "if systemctl is-active --quiet ollama; then systemctl restart ollama; fi"
                ),
                escaped
            )
        }
        OllamaModuleInternalApiCall::RestartService => "systemctl restart ollama".to_string(),
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

        let cmd = ollama_api_call_command(&self.api_call);

        let result = host_handler
            .run_command(&cmd, &self.privilege)
            .await
            .unwrap();

        if result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success(None))
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC: {}, STDOUT: {}, STDERR: {}",
                result.return_code, result.stdout, result.stderr
            )))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::attribute::Attribute;

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
        assert_eq!(block.state, OllamaState::Present);
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
        // Name without tag → :latest appended.
        assert_eq!(normalize_model_name("llama3"), "llama3:latest");
        // Name with tag → unchanged.
        assert_eq!(normalize_model_name("mistral:7b"), "mistral:7b");
        assert_eq!(normalize_model_name("codellama:13b"), "codellama:13b");
    }

    #[test]
    fn escape_for_printf_handles_special_chars() {
        let input = "[Service]\nEnvironment=\"OLLAMA_HOST=0.0.0.0:11434\"\n";
        let escaped = escape_for_printf(input);
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\n"));
        // No bare % in the input, but test % escaping.
        let with_percent = "foo%bar";
        assert_eq!(escape_for_printf(with_percent), "foo%%bar");
        // Backslash escaping.
        let with_backslash = "foo\\bar";
        assert_eq!(escape_for_printf(with_backslash), "foo\\\\bar");
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
        // Missing or invalid port.
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
        // Exact match.
        assert!(listens_on(ss, "127.0.0.1", 11434));
        // No match: bound to loopback only.
        assert!(!listens_on(ss, "0.0.0.0", 11434));
        // Wildcard expectation satisfied by the other wildcard forms.
        assert!(listens_on(ss, "0.0.0.0", 22));
        assert!(listens_on(ss, "::", 22));
        // Port not bound at all.
        assert!(!listens_on(ss, "0.0.0.0", 8080));
        // Header line is never a match.
        assert!(!listens_on("State Recv-Q Send-Q Local Peer\n", "State", 0));

        let ss_star = "LISTEN 0 4096 *:11434 0.0.0.0:*\n";
        assert!(listens_on(ss_star, "0.0.0.0", 11434));
        assert!(listens_on(ss_star, "::", 11434));
        assert!(!listens_on(ss_star, "127.0.0.1", 11434));
    }

    #[test]
    fn api_call_commands_are_built_as_expected() {
        // WriteApiConfig writes the override, reloads systemd, and restarts the
        // service only when it is active.
        let cmd = ollama_api_call_command(&OllamaModuleInternalApiCall::WriteApiConfig {
            content: build_api_config_content(&OllamaApiConfig {
                host: Some("0.0.0.0:11434".to_string()),
                ..Default::default()
            }),
        });
        assert!(cmd.contains("printf '[Service]"));
        assert!(cmd.contains("> /etc/systemd/system/ollama.service.d/override.conf"));
        assert!(cmd.contains("systemctl daemon-reload"));
        assert!(
            cmd.contains(
                "if systemctl is-active --quiet ollama; then systemctl restart ollama; fi"
            )
        );

        assert_eq!(
            ollama_api_call_command(&OllamaModuleInternalApiCall::RestartService),
            "systemctl restart ollama"
        );
        assert_eq!(
            ollama_api_call_command(&OllamaModuleInternalApiCall::PullModel {
                name: "qwen2.5:1.5b".to_string()
            }),
            "ollama pull qwen2.5:1.5b"
        );
        assert_eq!(
            ollama_api_call_command(&OllamaModuleInternalApiCall::RemoveModel {
                name: "qwen2.5:1.5b".to_string()
            }),
            "ollama rm qwen2.5:1.5b"
        );
        assert!(
            ollama_api_call_command(&OllamaModuleInternalApiCall::Install)
                .contains("ollama.com/install.sh")
        );
        assert!(
            ollama_api_call_command(&OllamaModuleInternalApiCall::Uninstall)
                .contains("rm -f /usr/local/bin/ollama")
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
    }
}
