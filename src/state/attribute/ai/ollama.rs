//! Ollama AI management attribute
//!
//! This module provides the `OllamaBlockExpectedState` type for managing the Ollama
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
//! use regent_sdk::state::attribute::ai::ollama::{OllamaBlockExpectedState, OllamaExpectedState, OllamaServiceState, OllamaModel, OllamaModelState, OllamaApiConfig};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install Ollama, start the service, and pull a model
//! let ollama = OllamaBlockExpectedState::builder()
//!     .with_state(OllamaExpectedState::Present)
//!     .with_service(OllamaServiceState::Started)
//!     .with_models(vec![
//!         OllamaModel {
//!             name: "llama3".to_string(),
//!             state: Some(OllamaModelState::Present),
//!         }
//!     ])
//!     .build()
//!     .unwrap();
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
//!   - Detail: !Ollama
//!       State: !Present
//!       Service: !Started
//!       ServiceEnabled: true
//!       Models:
//!         - Name: llama3
//!           State: !Present
//!       Api:
//!         Host: '0.0.0.0:11434'
//!         Origins:
//!           - '*'
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

// ── Enums ─────────────────────────────────────────────────────────────────────

/// Desired installation state of Ollama
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaExpectedState {
    /// Ollama should be installed
    Present,
    /// Ollama should be uninstalled
    Absent,
}

/// Desired service state of Ollama
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaServiceState {
    /// Service should be started
    Started,
    /// Service should be stopped
    Stopped,
    /// Service should be restarted
    Restarted,
    /// Service should be reloaded
    Reloaded,
}

/// Desired state of an Ollama model
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaModelState {
    /// Model should be pulled and available locally
    Present,
    /// Model should be removed from the local system
    Absent,
}

// ── Sub-structs ───────────────────────────────────────────────────────────────

/// Configuration for an Ollama model
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaModel {
    /// Name of the model (e.g., "llama3", "mistral:7b")
    name: String,
    /// Desired state of the model (defaults to Present if not specified)
    state: Option<OllamaModelState>,
}

/// REST API and environment configuration for Ollama
///
/// These settings are written to `/etc/systemd/system/ollama.service.d/override.conf`
/// and control the Ollama service behavior.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaApiConfig {
    /// OLLAMA_HOST env var - the address the server listens on, e.g. "0.0.0.0:11434"
    host: Option<String>,
    /// OLLAMA_ORIGINS - allowed origins for CORS, e.g. ["*"] or specific URLs
    origins: Option<Vec<String>>,
    /// OLLAMA_MODELS - custom model storage path
    models_path: Option<String>,
    /// OLLAMA_KEEP_ALIVE - how long to keep models in memory, e.g. "5m", "0", "24h"
    keep_alive: Option<String>,
    /// OLLAMA_NUM_PARALLEL - number of parallel requests to process
    num_parallel: Option<u32>,
    /// OLLAMA_MAX_LOADED_MODELS - maximum number of models to keep loaded in memory
    max_loaded_models: Option<u32>,
    /// OLLAMA_GPU_LAYERS - number of GPU layers to load (-1 for all available)
    gpu_layers: Option<i32>,
}

// ── BlockExpectedState ────────────────────────────────────────────────────────

/// Configuration for Ollama AI inference engine
///
/// Use the builder pattern to configure Ollama installation, service state,
/// model management, and API settings.
///
/// At least one field must be set. When state is None, only the specified
/// fields (service, models, api) will be managed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct OllamaBlockExpectedState {
    /// Present (install) / Absent (uninstall). When None: manage only what is
    /// specified by other fields (service, models, api).
    state: Option<OllamaExpectedState>,
    /// Desired run-state of the ollama service.
    service: Option<OllamaServiceState>,
    /// Whether the service should be enabled on boot.
    service_enabled: Option<bool>,
    /// LLM models to manage (pull or remove).
    models: Option<Vec<OllamaModel>>,
    /// REST API / environment configuration.
    api: Option<OllamaApiConfig>,
}

impl Timeout for OllamaBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl OllamaBlockExpectedState {
    pub fn builder() -> OllamaBlockExpectedState {
        OllamaBlockExpectedState {
            state: None,
            service: None,
            service_enabled: None,
            models: None,
            api: None,
        }
    }

    pub fn with_state(&mut self, state: OllamaExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_service(&mut self, service: OllamaServiceState) -> &mut Self {
        self.service = Some(service);
        self
    }

    pub fn with_service_enabled(&mut self, enabled: bool) -> &mut Self {
        self.service_enabled = Some(enabled);
        self
    }

    pub fn with_models(&mut self, models: Vec<OllamaModel>) -> &mut Self {
        self.models = Some(models);
        self
    }

    pub fn with_api(&mut self, api: OllamaApiConfig) -> &mut Self {
        self.api = Some(api);
        self
    }

    pub fn build(&self) -> Result<OllamaBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for OllamaBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.state.is_none()
            && self.service.is_none()
            && self.service_enabled.is_none()
            && self.models.is_none()
            && self.api.is_none()
        {
            return Err(RegentError::IncoherentExpectedState(
                "At least one of State, Service, ServiceEnabled, Models, or Api must be set."
                    .to_string(),
            ));
        }

        if let Some(models) = &self.models {
            for model in models {
                if model.name.is_empty() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Model name must not be empty.".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn check_host_compatibility(&self, host_properties: &HostProperties) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) | OsKind::MacOs => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(
                format!("Host is {:?} but Ollama is only supported on Linux and macOS", incompatible_os_kind)
            )),
        }
    }
}

// ── assess_compliance ─────────────────────────────────────────────────────────

impl<Handler: HostHandler> AssessCompliance<Handler> for OllamaBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Linux or macOS)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let mut remediations: Vec<Remediation> = Vec::new();

        // ── Step 1: check whether ollama is installed ─────────────────────────
        let is_installed = host_handler
            .run_command(
                "test -f /usr/local/bin/ollama || which ollama 2>/dev/null",
                &Privilege::None,
            )
            .await
            .unwrap()
            .return_code
            == 0;

        // ── Step 2: state = Absent ────────────────────────────────────────────
        if let Some(OllamaExpectedState::Absent) = &self.state {
            if is_installed {
                remediations.push(Remediation::Ollama(OllamaApiCall::from(
                    OllamaModuleInternalApiCall::StopService,
                    privilege.clone(),
                )));
                remediations.push(Remediation::Ollama(OllamaApiCall::from(
                    OllamaModuleInternalApiCall::DisableService,
                    privilege.clone(),
                )));
                remediations.push(Remediation::Ollama(OllamaApiCall::from(
                    OllamaModuleInternalApiCall::Uninstall,
                    privilege.clone(),
                )));
                return Ok(AttributeComplianceAssessment::NonCompliant(remediations));
            }
            // Already absent → compliant.
            return Ok(AttributeComplianceAssessment::Compliant);
        }

        // ── Step 3: state = Present, but not installed ────────────────────────
        if let Some(OllamaExpectedState::Present) = &self.state {
            if !is_installed {
                remediations.push(Remediation::Ollama(OllamaApiCall::from(
                    OllamaModuleInternalApiCall::Install,
                    privilege.clone(),
                )));
                return Ok(AttributeComplianceAssessment::NonCompliant(remediations));
            }
        }

        // ── Step 4: ollama is installed (or state=None + installed) ───────────
        // Nothing to do if state=None and not installed.
        if !is_installed {
            return Ok(AttributeComplianceAssessment::Compliant);
        }

        // 4a. Service run-state ─────────────────────────────────────────────────
        let mut service_is_currently_active = false;
        if self.service.is_some() || self.api.is_some() {
            // We need to know the current active state for both service and api logic.
            service_is_currently_active = host_handler
                .run_command("systemctl is-active ollama", &Privilege::None)
                .await
                .unwrap()
                .return_code
                == 0;
        }

        if let Some(service_state) = &self.service {
            match service_state {
                OllamaServiceState::Started => {
                    if !service_is_currently_active {
                        remediations.push(Remediation::Ollama(OllamaApiCall::from(
                            OllamaModuleInternalApiCall::StartService,
                            privilege.clone(),
                        )));
                    }
                }
                OllamaServiceState::Stopped => {
                    if service_is_currently_active {
                        remediations.push(Remediation::Ollama(OllamaApiCall::from(
                            OllamaModuleInternalApiCall::StopService,
                            privilege.clone(),
                        )));
                    }
                }
                OllamaServiceState::Restarted => {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::RestartService,
                        privilege.clone(),
                    )));
                }
                OllamaServiceState::Reloaded => {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::ReloadService,
                        privilege.clone(),
                    )));
                }
            }
        }

        // 4b. Boot-enable state ────────────────────────────────────────────────
        if let Some(should_be_enabled) = self.service_enabled {
            let is_enabled = host_handler
                .run_command("systemctl is-enabled ollama", &Privilege::None)
                .await
                .unwrap()
                .return_code
                == 0;

            match should_be_enabled {
                true => {
                    if !is_enabled {
                        remediations.push(Remediation::Ollama(OllamaApiCall::from(
                            OllamaModuleInternalApiCall::EnableService,
                            privilege.clone(),
                        )));
                    }
                }
                false => {
                    if is_enabled {
                        remediations.push(Remediation::Ollama(OllamaApiCall::from(
                            OllamaModuleInternalApiCall::DisableService,
                            privilege.clone(),
                        )));
                    }
                }
            }
        }

        // 4c. Models ───────────────────────────────────────────────────────────
        if let Some(models) = &self.models {
            let list_result = host_handler
                .run_command(
                    "ollama list 2>/dev/null | awk 'NR>1 {print $1}'",
                    &Privilege::None,
                )
                .await
                .unwrap();

            let installed_models: Vec<String> = if list_result.return_code == 0 {
                list_result
                    .stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            } else {
                Vec::new()
            };

            for model in models {
                let desired_state = model.state.as_ref().unwrap_or(&OllamaModelState::Present);
                let normalized_name = normalize_model_name(&model.name);

                match desired_state {
                    OllamaModelState::Present => {
                        if !installed_models.contains(&normalized_name) {
                            remediations.push(Remediation::Ollama(OllamaApiCall::from(
                                OllamaModuleInternalApiCall::PullModel {
                                    name: normalized_name,
                                },
                                privilege.clone(),
                            )));
                        }
                    }
                    OllamaModelState::Absent => {
                        if installed_models.contains(&normalized_name) {
                            remediations.push(Remediation::Ollama(OllamaApiCall::from(
                                OllamaModuleInternalApiCall::RemoveModel {
                                    name: normalized_name,
                                },
                                privilege.clone(),
                            )));
                        }
                    }
                }
            }
        }

        // 4d. API config ───────────────────────────────────────────────────────
        if let Some(api) = &self.api {
            let expected_content = build_api_config_content(api);

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
                remediations.push(Remediation::Ollama(OllamaApiCall::from(
                    OllamaModuleInternalApiCall::DaemonReload,
                    privilege.clone(),
                )));

                // Restart service if it is currently active or the service field requests it.
                let should_restart = service_is_currently_active
                    || matches!(
                        &self.service,
                        Some(OllamaServiceState::Started) | Some(OllamaServiceState::Restarted)
                    );

                if should_restart {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::RestartService,
                        privilege.clone(),
                    )));
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Appends `:latest` if the model name contains no `:`.
fn normalize_model_name(name: &str) -> String {
    if name.contains(':') {
        name.to_string()
    } else {
        format!("{}:latest", name)
    }
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

/// Escapes a string for use as the argument to `printf`: replaces `\` with `\\`,
/// `%` with `%%`, and newlines with `\n`.
fn escape_for_printf(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "%%")
        .replace('\n', "\\n")
}

// ── ApiCall variants ──────────────────────────────────────────────────────────

/// Internal API calls for Ollama management
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OllamaModuleInternalApiCall {
    /// Install Ollama using the official install script
    Install,
    /// Uninstall Ollama and clean up all files
    Uninstall,
    /// Start the Ollama service
    StartService,
    /// Stop the Ollama service
    StopService,
    /// Restart the Ollama service
    RestartService,
    /// Reload the Ollama service
    ReloadService,
    /// Enable Ollama service to start on boot
    EnableService,
    /// Disable Ollama service from starting on boot
    DisableService,
    /// Pull a model from the Ollama registry
    PullModel { name: String },
    /// Remove a model from the local system
    RemoveModel { name: String },
    /// Write API configuration to systemd override file
    WriteApiConfig { content: String },
    /// Reload systemd daemon after configuration changes
    DaemonReload,
}

impl std::fmt::Display for OllamaModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OllamaModuleInternalApiCall::Install => write!(f, "install ollama"),
            OllamaModuleInternalApiCall::Uninstall => write!(f, "uninstall ollama"),
            OllamaModuleInternalApiCall::StartService => write!(f, "start ollama service"),
            OllamaModuleInternalApiCall::StopService => write!(f, "stop ollama service"),
            OllamaModuleInternalApiCall::RestartService => write!(f, "restart ollama service"),
            OllamaModuleInternalApiCall::ReloadService => write!(f, "reload ollama service"),
            OllamaModuleInternalApiCall::EnableService => write!(f, "enable ollama service"),
            OllamaModuleInternalApiCall::DisableService => write!(f, "disable ollama service"),
            OllamaModuleInternalApiCall::PullModel { name } => {
                write!(f, "pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
                write!(f, "remove model {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { .. } => {
                write!(f, "write ollama api config")
            }
            OllamaModuleInternalApiCall::DaemonReload => write!(f, "systemctl daemon-reload"),
        }
    }
}

/// An Ollama API call with its associated privilege level
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OllamaApiCall {
    /// The internal API call to execute
    pub api_call: OllamaModuleInternalApiCall,
    /// Privilege level required for this call
    privilege: Privilege,
}

impl OllamaApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            OllamaModuleInternalApiCall::Install => "Install ollama".to_string(),
            OllamaModuleInternalApiCall::Uninstall => "Uninstall ollama".to_string(),
            OllamaModuleInternalApiCall::StartService => "Start ollama service".to_string(),
            OllamaModuleInternalApiCall::StopService => "Stop ollama service".to_string(),
            OllamaModuleInternalApiCall::RestartService => "Restart ollama service".to_string(),
            OllamaModuleInternalApiCall::ReloadService => "Reload ollama service".to_string(),
            OllamaModuleInternalApiCall::EnableService => {
                "Enable ollama service on boot".to_string()
            }
            OllamaModuleInternalApiCall::DisableService => {
                "Disable ollama service on boot".to_string()
            }
            OllamaModuleInternalApiCall::PullModel { name } => {
                format!("Pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
                format!("Remove model {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { .. } => {
                "Configure ollama REST API".to_string()
            }
            OllamaModuleInternalApiCall::DaemonReload => "Reload systemd daemon".to_string(),
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

    fn check_host_compatibility(&self, host_properties: &HostProperties) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) | OsKind::MacOs => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(
                format!("Host is {:?} but Ollama is only supported on Linux and macOS", incompatible_os_kind)
            )),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for OllamaApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Linux or macOS)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let cmd: String = match &self.api_call {
            OllamaModuleInternalApiCall::Install => {
                "curl -fsSL https://ollama.com/install.sh | sh".to_string()
            }
            OllamaModuleInternalApiCall::Uninstall => concat!(
                "systemctl stop ollama 2>/dev/null; ",
                "systemctl disable ollama 2>/dev/null; ",
                "rm -f /usr/local/bin/ollama /usr/bin/ollama; ",
                "rm -f /etc/systemd/system/ollama.service; ",
                "systemctl daemon-reload 2>/dev/null; ",
                "rm -rf /usr/share/ollama"
            )
            .to_string(),
            OllamaModuleInternalApiCall::StartService => "systemctl start ollama".to_string(),
            OllamaModuleInternalApiCall::StopService => "systemctl stop ollama".to_string(),
            OllamaModuleInternalApiCall::RestartService => "systemctl restart ollama".to_string(),
            OllamaModuleInternalApiCall::ReloadService => "systemctl reload ollama".to_string(),
            OllamaModuleInternalApiCall::EnableService => "systemctl enable ollama".to_string(),
            OllamaModuleInternalApiCall::DisableService => "systemctl disable ollama".to_string(),
            OllamaModuleInternalApiCall::PullModel { name } => {
                format!("ollama pull {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
                format!("ollama rm {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { content } => {
                let escaped = escape_for_printf(content);
                format!(
                    "mkdir -p /etc/systemd/system/ollama.service.d && printf '{}' > /etc/systemd/system/ollama.service.d/override.conf",
                    escaped
                )
            }
            OllamaModuleInternalApiCall::DaemonReload => "systemctl daemon-reload".to_string(),
        };

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

    #[test]
    fn parsing_ollama_module_block_from_yaml_str() {
        let raw = "---
- State: !Present
  Service: !Started
  ServiceEnabled: true
  Models:
    - Name: llama3
    - Name: mistral:7b
      State: !Present
    - Name: codellama:13b
      State: !Absent
  Api:
    Host: '0.0.0.0:11434'
    Origins:
      - '*'
    KeepAlive: 5m
    NumParallel: 4
    MaxLoadedModels: 2
    GpuLayers: -1

- State: !Absent

- Models:
    - Name: mistral:7b
        ";
        let blocks: Vec<OllamaBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(blocks[0].state, Some(OllamaExpectedState::Present));
        assert_eq!(blocks[0].service, Some(OllamaServiceState::Started));
        assert_eq!(blocks[0].service_enabled, Some(true));
        let models = blocks[0].models.as_ref().unwrap();
        assert_eq!(models.len(), 3);
        assert_eq!(models[0].name, "llama3");
        assert_eq!(models[0].state, None);
        assert_eq!(models[1].name, "mistral:7b");
        assert_eq!(models[1].state, Some(OllamaModelState::Present));
        assert_eq!(models[2].name, "codellama:13b");
        assert_eq!(models[2].state, Some(OllamaModelState::Absent));
        let api = blocks[0].api.as_ref().unwrap();
        assert_eq!(api.host, Some("0.0.0.0:11434".to_string()));
        assert_eq!(api.origins, Some(vec!["*".to_string()]));
        assert_eq!(api.keep_alive, Some("5m".to_string()));
        assert_eq!(api.num_parallel, Some(4));
        assert_eq!(api.max_loaded_models, Some(2));
        assert_eq!(api.gpu_layers, Some(-1));

        assert_eq!(blocks[1].state, Some(OllamaExpectedState::Absent));
        assert!(blocks[2].models.is_some());
    }

    #[test]
    fn check_rejects_nothing_set() {
        let result = OllamaBlockExpectedState::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_empty_model_name() {
        let result = OllamaBlockExpectedState::builder()
            .with_models(vec![OllamaModel {
                name: String::new(),
                state: None,
            }])
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_minimal() {
        let result = OllamaBlockExpectedState::builder()
            .with_models(vec![OllamaModel {
                name: "llama3".to_string(),
                state: None,
            }])
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_api_config_content_basic() {
        let api = OllamaApiConfig {
            host: Some("0.0.0.0:11434".to_string()),
            origins: Some(vec!["*".to_string()]),
            models_path: None,
            keep_alive: Some("5m".to_string()),
            num_parallel: None,
            max_loaded_models: None,
            gpu_layers: None,
        };
        let content = build_api_config_content(&api);
        assert!(content.starts_with("[Service]\n"));
        assert!(content.contains("Environment=\"OLLAMA_HOST=0.0.0.0:11434\""));
        assert!(content.contains("Environment=\"OLLAMA_ORIGINS=*\""));
        assert!(content.contains("Environment=\"OLLAMA_KEEP_ALIVE=5m\""));
        assert!(!content.contains("OLLAMA_MODELS"));
        assert!(!content.contains("OLLAMA_NUM_PARALLEL"));
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn build_api_config_content_multiple_origins() {
        let api = OllamaApiConfig {
            host: None,
            origins: Some(vec![
                "https://app.example.com".to_string(),
                "https://other.example.com".to_string(),
            ]),
            models_path: Some("/mnt/models".to_string()),
            keep_alive: None,
            num_parallel: Some(2),
            max_loaded_models: Some(1),
            gpu_layers: Some(-1),
        };
        let content = build_api_config_content(&api);
        assert!(content.contains(
            "Environment=\"OLLAMA_ORIGINS=https://app.example.com,https://other.example.com\""
        ));
        assert!(content.contains("Environment=\"OLLAMA_MODELS=/mnt/models\""));
        assert!(content.contains("Environment=\"OLLAMA_NUM_PARALLEL=2\""));
        assert!(content.contains("Environment=\"OLLAMA_MAX_LOADED_MODELS=1\""));
        assert!(content.contains("Environment=\"OLLAMA_GPU_LAYERS=-1\""));
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
}
