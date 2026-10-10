//! ONNX Runtime management attribute
//!
//! This module provides the `OnnxExpectedState` type for managing ONNX
//! Runtime on inference hosts: the installed `onnxruntime` (CPU) or
//! `onnxruntime-gpu` (CUDA) wheel in a given Python environment, plus
//! assertions on the execution providers the deployment relies on.
//!
//! **Compatible OS:** Linux (any flavor), macOS.
//!
//! The attribute splits its surface the same way as the other AI
//! attributes:
//!
//! - **Managed component** — the ONNX Runtime wheel itself:
//!   - `Version` (e.g. `1.20.0`) pins the exact wheel; `None` accepts any.
//!   - `Gpu: true` manages `onnxruntime-gpu` instead of `onnxruntime`
//!     (installing the GPU wheel also removes a coexisting CPU wheel, the
//!     classic provider-conflict pitfall).
//!   - `Python` selects the interpreter (a venv's `python` on inference
//!     hosts); defaults to `python3`. Installation goes through
//!     `<python> -m pip`, which works for virtual environments and
//!     user-scoped installs alike.
//! - **Fatal assertions** (checked, never remediated here):
//!   - `Providers` (e.g. `[CUDAExecutionProvider]`) — the runtime must
//!     report these execution providers via
//!     `onnxruntime.get_available_providers()`. A missing provider is the
//!     consequence of the wheel build and the GPU driver stack, not
//!     something this attribute can fix: pair `CUDAExecutionProvider` with
//!     the `NvidiaDriver` and `NvidiaContainerToolkit` attributes and
//!     `CoreMLExecutionProvider` with the `AppleMps` attribute (gpu
//!     category).
//! - **`Absent`** uninstalls both wheels from the Python environment.
//!
//! Model files themselves (`.onnx` artifacts) are pinned files: use the
//! container/artifact attributes or a `Command`/`get_url`-style workflow
//! until a dedicated model-artifact attribute exists.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::ai::onnx::OnnxExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // A pinned GPU runtime in the inference venv
//! let onnx = OnnxExpectedState::gpu("1.20.0")
//!     .with_python("/opt/inference/bin/python")
//!     .with_providers(vec!["CUDAExecutionProvider".to_string()]);
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::onnx(onnx, Privilege::None, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: ONNX Runtime GPU 1.20.0 in the inference venv
//!     Privilege: !None
//!     Timeout: 600
//!     Detail: !Onnx
//!       State: Present
//!       Runtime:
//!         Version: 1.20.0
//!         Gpu: true
//!         Python: /opt/inference/bin/python
//!         Providers:
//!           - CUDAExecutionProvider
//! ```

use std::time::Duration;

use serde::{Deserialize, Serialize};

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
use crate::state::compliance::AttributeComplianceAssessment;

// ── ExpectedState ─────────────────────────────────────────────────────────────

/// The Python interpreter the wheels are managed in. Defaults to `python3`.
fn default_python() -> String {
    "python3".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct OnnxRuntime {
    /// Exact wheel version to pin (`1.20.0`). `None` accepts any version.
    pub version: Option<String>,
    /// Manage `onnxruntime-gpu` (CUDA build) instead of `onnxruntime`.
    pub gpu: Option<bool>,
    /// Python interpreter to use (a venv's `python`). Defaults to `python3`.
    #[serde(default = "default_python")]
    pub python: String,
    /// Execution providers the runtime must report
    /// (`CUDAExecutionProvider`, `CoreMLExecutionProvider`, ...). Asserted,
    /// never remediated here: pair with `NvidiaDriver` /
    /// `NvidiaContainerToolkit` / `AppleMps` (gpu category).
    pub providers: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "State",
    rename_all = "PascalCase",
    rename_all_fields = "PascalCase"
)]
pub enum OnnxExpectedState {
    Absent {
        /// Python interpreter to uninstall from. Defaults to `python3`.
        #[serde(default = "default_python")]
        python: String,
    },
    Present {
        runtime: OnnxRuntime,
    },
}

impl Timeout for OnnxExpectedState {
    fn default_timeout(&self) -> Duration {
        match self {
            OnnxExpectedState::Absent { .. } => Duration::from_secs(180),
            // Wheels are a few hundred MB for the GPU build
            OnnxExpectedState::Present { .. } => Duration::from_secs(600),
        }
    }
}

impl OnnxExpectedState {
    pub fn cpu(version: &str) -> OnnxExpectedState {
        OnnxExpectedState::Present {
            runtime: OnnxRuntime {
                version: Some(version.to_string()),
                gpu: None,
                python: default_python(),
                providers: None,
            },
        }
    }

    pub fn gpu(version: &str) -> OnnxExpectedState {
        OnnxExpectedState::Present {
            runtime: OnnxRuntime {
                version: Some(version.to_string()),
                gpu: Some(true),
                python: default_python(),
                providers: None,
            },
        }
    }

    pub fn any_cpu() -> OnnxExpectedState {
        OnnxExpectedState::Present {
            runtime: OnnxRuntime {
                version: None,
                gpu: None,
                python: default_python(),
                providers: None,
            },
        }
    }

    pub fn absent() -> OnnxExpectedState {
        OnnxExpectedState::Absent {
            python: default_python(),
        }
    }

    pub fn python(&self) -> &str {
        match self {
            OnnxExpectedState::Absent { python } => python,
            OnnxExpectedState::Present { runtime } => &runtime.python,
        }
    }

    fn map_runtime(mut self, mutate: impl FnOnce(&mut OnnxRuntime)) -> Self {
        if let OnnxExpectedState::Present { runtime } = &mut self {
            mutate(runtime);
        }
        self
    }

    pub fn with_version(self, version: &str) -> Self {
        self.map_runtime(|runtime| runtime.version = Some(version.to_string()))
    }

    pub fn with_gpu(self, gpu: bool) -> Self {
        self.map_runtime(|runtime| runtime.gpu = Some(gpu))
    }

    pub fn with_python(self, python: &str) -> Self {
        match self {
            OnnxExpectedState::Absent { .. } => self,
            OnnxExpectedState::Present { mut runtime } => {
                runtime.python = python.to_string();
                OnnxExpectedState::Present { runtime }
            }
        }
    }

    pub fn with_providers(self, providers: Vec<String>) -> Self {
        self.map_runtime(|runtime| runtime.providers = Some(providers))
    }
}

impl Check for OnnxExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        match self {
            OnnxExpectedState::Absent { python } => {
                if python.trim().is_empty() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Onnx state has an empty Python".to_string(),
                    ));
                }
                Ok(())
            }
            OnnxExpectedState::Present { runtime } => {
                if let Some(version) = &runtime.version
                    && version.trim().is_empty()
                {
                    return Err(RegentError::IncoherentExpectedState(
                        "Onnx state has an empty Version".to_string(),
                    ));
                }
                if runtime.python.trim().is_empty() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Onnx state has an empty Python".to_string(),
                    ));
                }
                if let Some(providers) = &runtime.providers
                    && providers.iter().any(|provider| provider.trim().is_empty())
                {
                    return Err(RegentError::IncoherentExpectedState(
                        "Onnx state has an empty execution provider entry".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) | OsKind::MacOs(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but the Onnx attribute is only supported for Linux and macOS",
                incompatible_os_kind
            ))),
        }
    }
}

// ── Internal API calls ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OnnxModuleInternalApiCall {
    InstallRuntime {
        version: Option<String>,
        gpu: bool,
        python: String,
    },
    RemoveRuntime {
        python: String,
    },
}

impl std::fmt::Display for OnnxModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnnxModuleInternalApiCall::InstallRuntime { version, gpu, .. } => {
                let package = if *gpu {
                    "onnxruntime-gpu"
                } else {
                    "onnxruntime"
                };
                match version {
                    Some(version) => write!(f, "install {}=={}", package, version),
                    None => write!(f, "install {}", package),
                }
            }
            OnnxModuleInternalApiCall::RemoveRuntime { .. } => {
                write!(f, "uninstall onnxruntime")
            }
        }
    }
}

// ── ApiCall ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnnxApiCall {
    pub api_call: OnnxModuleInternalApiCall,
    privilege: Privilege,
}

impl Check for OnnxApiCall {
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
                "Host is {:?} but the Onnx attribute is only supported for Linux and macOS",
                incompatible_os_kind
            ))),
        }
    }
}

impl OnnxApiCall {
    pub fn display(&self) -> String {
        format!("onnx: {}", self.api_call)
    }

    pub fn from(api_call: OnnxModuleInternalApiCall, privilege: Privilege) -> OnnxApiCall {
        OnnxApiCall {
            api_call,
            privilege,
        }
    }
}

// ── Assessment ───────────────────────────────────────────────────────────────

impl<Handler: HostHandler> AssessCompliance<Handler> for OnnxExpectedState {
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

        match self {
            OnnxExpectedState::Absent { python } => {
                let installed_version = probe_onnx_version(host_handler, python).await?;
                if installed_version.is_some() {
                    remediations.push(Remediation::Onnx(OnnxApiCall::from(
                        OnnxModuleInternalApiCall::RemoveRuntime {
                            python: python.clone(),
                        },
                        privilege.clone(),
                    )));
                }
            }
            OnnxExpectedState::Present { runtime } => {
                // 1. Wheel presence and version (the managed component)
                let installed_version = probe_onnx_version(host_handler, &runtime.python).await?;
                let version_ok = match (&installed_version, &runtime.version) {
                    (Some(_), None) => true,
                    (Some(installed), Some(expected)) => installed == expected,
                    (None, _) => false,
                };
                if !version_ok {
                    remediations.push(Remediation::Onnx(OnnxApiCall::from(
                        OnnxModuleInternalApiCall::InstallRuntime {
                            version: runtime.version.clone(),
                            gpu: runtime.gpu.unwrap_or(false),
                            python: runtime.python.clone(),
                        },
                        privilege.clone(),
                    )));
                }

                // 2. Execution providers (assertions: consequences of the
                //    wheel build and the driver stack, not remediable here)
                if let Some(expected_providers) = &runtime.providers {
                    let available =
                        probe_available_providers(host_handler, &runtime.python).await?;
                    if let Some(available) = available {
                        let missing: Vec<String> = expected_providers
                            .iter()
                            .filter(|provider| !available.contains(provider))
                            .cloned()
                            .collect();
                        if !missing.is_empty() {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                "ONNX Runtime is installed but lacks execution providers {:?}; available: {:?}. Use the matching wheel (onnxruntime-gpu / CoreML build) and pair with the NvidiaDriver / NvidiaContainerToolkit / AppleMps attributes (gpu category) for the driver stack",
                                missing, available
                            )));
                        }
                    } else if installed_version.is_some() {
                        // Import succeeded for the version probe but the
                        // providers probe failed: broken installation
                        return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                            "ONNX Runtime is installed but get_available_providers() fails; the installation is broken".to_string(),
                        ));
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

// ── Remediation execution ─────────────────────────────────────────────────────

impl<Handler: HostHandler> ReachCompliance<Handler> for OnnxApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        match &self.api_call {
            OnnxModuleInternalApiCall::InstallRuntime {
                version,
                gpu,
                python,
            } => {
                let cmd = build_install_command(python, *gpu, version.as_deref());
                let result = host_handler
                    .run_command(&cmd, &self.privilege)
                    .await
                    .map_err(|e| RegentError::FailureToRunCommand(format!("{:?}", e)))?;
                if result.return_code != 0 {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "onnxruntime install failed (RC {}): {}",
                        result.return_code,
                        result.stderr.trim()
                    )));
                }
                match probe_onnx_version(host_handler, python).await? {
                    Some(_) => Ok(InternalApiCallOutcome::Success(None)),
                    None => Ok(InternalApiCallOutcome::Failure(
                        "onnxruntime install succeeded but the module still fails to import"
                            .to_string(),
                    )),
                }
            }
            OnnxModuleInternalApiCall::RemoveRuntime { python } => {
                let cmd = build_remove_command(python);
                let result = host_handler
                    .run_command(&cmd, &self.privilege)
                    .await
                    .map_err(|e| RegentError::FailureToRunCommand(format!("{:?}", e)))?;
                if result.return_code != 0 {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "onnxruntime removal failed (RC {}): {}",
                        result.return_code,
                        result.stderr.trim()
                    )));
                }
                if probe_onnx_version(host_handler, python).await?.is_some() {
                    Ok(InternalApiCallOutcome::Failure(
                        "onnxruntime removal succeeded but the module still imports".to_string(),
                    ))
                } else {
                    Ok(InternalApiCallOutcome::Success(None))
                }
            }
        }
    }
}

// ── Command builders ──────────────────────────────────────────────────────────

/// Build the `<python> -m pip install ...` command. The GPU build removes a
/// coexisting CPU wheel first: having both installed breaks provider loading.
fn build_install_command(python: &str, gpu: bool, version: Option<&str>) -> String {
    let package = match (gpu, version) {
        (true, Some(version)) => format!("onnxruntime-gpu=={}", version),
        (true, None) => "onnxruntime-gpu".to_string(),
        (false, Some(version)) => format!("onnxruntime=={}", version),
        (false, None) => "onnxruntime".to_string(),
    };
    if gpu {
        format!(
            "{python} -m pip uninstall -y onnxruntime >/dev/null 2>&1 || true; \
             {python} -m pip install --quiet {package}",
            python = shell_quote(python),
            package = package
        )
    } else {
        format!(
            "{python} -m pip install --quiet {package}",
            python = shell_quote(python),
            package = package
        )
    }
}

/// Build the uninstall command for both wheels (each `|| true`-guarded: only
/// the post-verification decides the real outcome).
fn build_remove_command(python: &str) -> String {
    format!(
        "{python} -m pip uninstall -y onnxruntime >/dev/null 2>&1 || true; \
         {python} -m pip uninstall -y onnxruntime-gpu >/dev/null 2>&1 || true",
        python = shell_quote(python)
    )
}

// ── Host interaction helpers ──────────────────────────────────────────────────

/// ONNX Runtime version reported by the interpreter (`None` when the module
/// is not importable).
async fn probe_onnx_version<Handler: HostHandler>(
    host_handler: &mut Handler,
    python: &str,
) -> Result<Option<String>, RegentError> {
    let cmd = format!(
        "{python} -c 'import onnxruntime; print(onnxruntime.__version__)' 2>/dev/null",
        python = shell_quote(python)
    );
    let result = host_handler
        .run_command(&cmd, &Privilege::None)
        .await
        .map_err(|e| RegentError::FailedDryRunEvaluation(format!("{:?}", e)))?;
    let version = result.stdout.trim();
    if result.return_code != 0 || version.is_empty() {
        Ok(None)
    } else {
        Ok(Some(version.to_string()))
    }
}

/// Execution providers reported by the runtime, one per line
/// (`None` when the probe itself fails).
async fn probe_available_providers<Handler: HostHandler>(
    host_handler: &mut Handler,
    python: &str,
) -> Result<Option<Vec<String>>, RegentError> {
    let cmd = format!(
        "{python} -c 'import onnxruntime; print(\"\\n\".join(onnxruntime.get_available_providers()))' 2>/dev/null",
        python = shell_quote(python)
    );
    let result = host_handler
        .run_command(&cmd, &Privilege::None)
        .await
        .map_err(|e| RegentError::FailedDryRunEvaluation(format!("{:?}", e)))?;
    if result.return_code != 0 {
        return Ok(None);
    }
    let providers: Vec<String> = result
        .stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    if providers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(providers))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    use super::*;
    use crate::state::attribute::Attribute;

    #[test]
    fn parsing_onnx_module_block_from_yaml_str() {
        let raw_attribute = "---
State: Present
Runtime:
  Version: 1.20.0
  Gpu: true
  Python: /opt/inference/bin/python
  Providers:
    - CUDAExecutionProvider
    - CPUExecutionProvider
";

        let attribute: OnnxExpectedState = yaml_serde::from_str(raw_attribute).unwrap();

        let OnnxExpectedState::Present { runtime } = &attribute else {
            panic!("expected the Present variant");
        };

        assert_eq!(runtime.version, Some("1.20.0".to_string()));
        assert_eq!(runtime.gpu, Some(true));
        assert_eq!(runtime.python, "/opt/inference/bin/python");
        assert_eq!(
            runtime.providers,
            Some(vec![
                "CUDAExecutionProvider".to_string(),
                "CPUExecutionProvider".to_string(),
            ])
        );
        assert!(attribute.check().is_ok());

        // Absent carries only the interpreter; the Python key defaults
        let raw_absent = "---\nState: Absent\n";
        let absent: OnnxExpectedState = yaml_serde::from_str(raw_absent).unwrap();
        assert_eq!(absent, OnnxExpectedState::absent());
        assert_eq!(absent.python(), "python3");

        // Runtime Python defaults to python3
        let raw_minimal = "---\nState: Present\nRuntime:\n  Version: 1.20.0\n";
        let minimal: OnnxExpectedState = yaml_serde::from_str(raw_minimal).unwrap();
        assert_eq!(minimal.python(), "python3");
    }

    #[test]
    fn rejecting_incorrect_onnx_module_block_from_yaml_str() {
        // Missing State tag
        let raw = "---\nRuntime:\n  Version: 1.20.0\n";
        assert!(yaml_serde::from_str::<OnnxExpectedState>(raw).is_err());

        // Invalid state value
        let raw = "---\nState: Flying\n";
        assert!(yaml_serde::from_str::<OnnxExpectedState>(raw).is_err());

        // NOTE: unknown keys inside `Runtime` are silently ignored (serde's
        // internally tagged enum buffering does not honor deny_unknown_fields).
    }

    #[test]
    fn check_validates_spec_invariants() {
        // Empty version
        let spec = OnnxExpectedState::cpu("  ");
        assert!(spec.check().is_err());

        // Empty python path
        let spec = OnnxExpectedState::cpu("1.20.0").with_python("  ");
        assert!(spec.check().is_err());

        // Empty provider entry
        let spec = OnnxExpectedState::cpu("1.20.0")
            .with_providers(vec!["CUDAExecutionProvider".to_string(), "  ".to_string()]);
        assert!(spec.check().is_err());

        // Valid GPU spec
        let spec = OnnxExpectedState::gpu("1.20.0")
            .with_python("/opt/venv/bin/python")
            .with_providers(vec!["CUDAExecutionProvider".to_string()]);
        spec.check().unwrap();
    }

    #[test]
    fn install_and_remove_command_builders() {
        assert_eq!(
            build_install_command("/opt/venv/bin/python", false, Some("1.20.0")),
            "'/opt/venv/bin/python' -m pip install --quiet onnxruntime==1.20.0"
        );
        assert_eq!(
            build_install_command("python3", false, None),
            "'python3' -m pip install --quiet onnxruntime"
        );
        let gpu = build_install_command("python3", true, Some("1.20.0"));
        assert!(
            gpu.starts_with("'python3' -m pip uninstall -y onnxruntime >/dev/null 2>&1 || true;")
        );
        assert!(gpu.contains("'python3' -m pip install --quiet onnxruntime-gpu==1.20.0"));

        let remove = build_remove_command("python3");
        assert!(
            remove.contains("'python3' -m pip uninstall -y onnxruntime >/dev/null 2>&1 || true")
        );
        assert!(
            remove
                .contains("'python3' -m pip uninstall -y onnxruntime-gpu >/dev/null 2>&1 || true")
        );
    }

    #[test]
    fn api_call_display() {
        let call = OnnxApiCall::from(
            OnnxModuleInternalApiCall::InstallRuntime {
                version: Some("1.20.0".to_string()),
                gpu: true,
                python: "python3".to_string(),
            },
            Privilege::None,
        );
        assert_eq!(call.display(), "onnx: install onnxruntime-gpu==1.20.0");
    }

    #[test]
    fn parsing_full_onnx_attribute_envelope_from_yaml_str() {
        // Same shape as the module's YAML API documentation example.
        let raw_attribute = "---
Name: ONNX Runtime GPU in the inference venv
Privilege: !None
Timeout: 600
Detail: !Onnx
  State: Present
  Runtime:
    Version: 1.20.0
    Gpu: true
    Python: /opt/inference/bin/python
    Providers:
      - CUDAExecutionProvider
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
        assert_eq!(attribute.name(), "ONNX Runtime GPU in the inference venv");
    }
}
