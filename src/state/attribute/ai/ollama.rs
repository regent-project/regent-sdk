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
//! use regent_sdk::state::attribute::ai::ollama::{OllamaExpectedState, OllamaExpectedState, OllamaServiceState, OllamaModel, OllamaModelState, OllamaApiConfig};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Install Ollama, start the service, and pull a model
//! let ollama = OllamaExpectedState::builder()
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
//!   - Name: Ollama with llama3 model must be present and running
//!     Privilege: !WithSudo
//!     Detail: !Ollama
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
use std::time::Duration;

// ── Enums ─────────────────────────────────────────────────────────────────────

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
    /// Desired state of the model
    state: OllamaModelState,
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
#[serde(rename_all = "PascalCase")]
pub enum OllamaExpectedState {
    Absent,
    Present,
    // #[serde(untagged)]
    #[serde(rename_all = "PascalCase")]
    PresentWithConfig {
        /// REST API / environment configuration.
        api_config: OllamaApiConfig,
    },
    // #[serde(untagged)]
    #[serde(rename_all = "PascalCase")]
    PresentWithModels {
        /// LLM models to manage (pull or remove).
        models: Vec<OllamaModel>,
    },
    // #[serde(untagged)]
    #[serde(rename_all = "PascalCase")]
    PresentWithConfigAndModels {
        api_config: OllamaApiConfig,
        models: Vec<OllamaModel>,
    },
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
        OllamaExpectedState::Present
    }

    pub fn present_with_config(api_config: OllamaApiConfig) -> OllamaExpectedState {
        OllamaExpectedState::PresentWithConfig { api_config }
    }

    pub fn present_with_models(models: Vec<OllamaModel>) -> OllamaExpectedState {
        OllamaExpectedState::PresentWithModels { models }
    }

    pub fn present_with_config_and_models(
        api_config: OllamaApiConfig,
        models: Vec<OllamaModel>,
    ) -> OllamaExpectedState {
        OllamaExpectedState::PresentWithConfigAndModels { api_config, models }
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
        // Early check: verify we're on a compatible host (Linux or macOS)
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

        match self {
            OllamaExpectedState::Absent => {
                if ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Uninstall,
                        privilege.clone(),
                    )));
                }
            }
            OllamaExpectedState::Present => {
                if !ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Install,
                        privilege.clone(),
                    )));
                }
            }
            OllamaExpectedState::PresentWithConfig { api_config } => {
                if !ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Install,
                        privilege.clone(),
                    )));
                } else {
                    // Checks on configuration
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
                    }
                }
            }
            OllamaExpectedState::PresentWithModels { models } => {
                if !ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Install,
                        privilege.clone(),
                    )));
                } else {
                    // Checks on models
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
                        let normalized_name = normalize_model_name(&model.name);

                        match model.state {
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
            }
            OllamaExpectedState::PresentWithConfigAndModels { api_config, models } => {
                if !ollama_is_installed {
                    remediations.push(Remediation::Ollama(OllamaApiCall::from(
                        OllamaModuleInternalApiCall::Install,
                        privilege.clone(),
                    )));
                } else {
                    // Checks on configuration & models
                    // ***** Configuration *****
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
                    }

                    // ***** Models *****
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
                        let normalized_name = normalize_model_name(&model.name);

                        match model.state {
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
    /// Pull a model from the Ollama registry
    PullModel { name: String },
    /// Remove a model from the local system
    RemoveModel { name: String },
    /// Write API configuration to systemd override file
    WriteApiConfig { content: String },
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
            OllamaModuleInternalApiCall::PullModel { name } => {
                format!("Pull model {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
                format!("Remove model {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { .. } => {
                "Configure ollama REST API".to_string()
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
            OllamaModuleInternalApiCall::PullModel { name } => {
                format!("ollama pull {}", name)
            }
            OllamaModuleInternalApiCall::RemoveModel { name } => {
                format!("ollama rm {}", name)
            }
            OllamaModuleInternalApiCall::WriteApiConfig { content } => {
                let escaped = escape_for_printf(content);
                format!(
                    "mkdir -p /etc/systemd/system/ollama.service.d && printf '{}' > /etc/systemd/system/ollama.service.d/override.conf; systemctl daemon-reload",
                    escaped
                )
            }
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
        let serde_helper: Vec<OllamaExpectedState> = vec![
            OllamaExpectedState::Present,
            OllamaExpectedState::Absent,
            OllamaExpectedState::PresentWithModels {
                models: vec![OllamaModel {
                    name: "mistral:7b".to_string(),
                    state: OllamaModelState::Present,
                }],
            },
        ];
        println!("{}", yaml_serde::to_string(&serde_helper).unwrap());

        let raw = "---
!Absent
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(block, OllamaExpectedState::Absent);

        let raw = "---
!Present
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(block, OllamaExpectedState::Present);

        let raw = "---
!PresentWithModels
Models:
    - Name: mistral:7b
      State: Present
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(
            block,
            OllamaExpectedState::PresentWithModels {
                models: vec![OllamaModel {
                    name: "mistral:7b".to_string(),
                    state: OllamaModelState::Present
                }]
            }
        );

        let raw = "---
!PresentWithConfigAndModels
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
      State: Present
    - Name: codellama:13b
      State: Absent
";
        let block: OllamaExpectedState = yaml_serde::from_str(raw).unwrap();
        match &block {
            OllamaExpectedState::PresentWithConfigAndModels { api_config, models } => {
                assert_eq!(models.len(), 3);
                assert_eq!(models[0].name, "llama3");
                assert_eq!(models[0].state, OllamaModelState::Present);
                assert_eq!(models[1].name, "mistral:7b");
                assert_eq!(models[1].state, OllamaModelState::Present);
                assert_eq!(models[2].name, "codellama:13b");
                assert_eq!(models[2].state, OllamaModelState::Absent);

                assert_eq!(api_config.host, Some("0.0.0.0:11434".to_string()));
                assert_eq!(api_config.origins, Some(vec!["*".to_string()]));
                assert_eq!(api_config.keep_alive, Some("5m".to_string()));
                assert_eq!(api_config.num_parallel, Some(4));
                assert_eq!(api_config.max_loaded_models, Some(2));
                assert_eq!(api_config.gpu_layers, Some(-1));
            }
            wrong_variant => panic!("Wrong variant chosen : {:?}", wrong_variant),
        }
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
