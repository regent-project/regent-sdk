//! Apple MPS (Metal Performance Shaders) management attribute
//!
//! This module provides the `AppleMpsExpectedState` type for managing the MPS
//! prerequisites on Apple hosts — the GPU compute backend used by PyTorch,
//! Core ML and most local-inference stacks on Apple Silicon.
//!
//! **Compatible OS:** macOS only.
//!
//! Unlike NVIDIA CUDA, MPS is part of the operating system: there is no
//! driver, kernel module or SDK package to install. The attribute therefore
//! splits its surface in two:
//!
//! - **Fatal assertions** (checked, never remediated — hardware and OS
//!   versions cannot be declaratively enforced from a config tool):
//!   - `AppleSilicon: true` — the host must be arm64 (`uname -m`); MPS is
//!     unavailable on Intel Macs.
//!   - `MinMacosVersion: "13.5"` — the host must run at least this macOS
//!     version (`sw_vers -productVersion`). Older versions are reported as
//!     `NonCompliantFatal` with an upgrade note (run the upgrade via
//!     `softwareupdate` yourself, or use regops on a maintenance window).
//! - **Managed component** (installed/removed by this attribute):
//!   - `CommandLineTools: true` — the Xcode Command Line Tools, which carry
//!     the Metal toolchain (`xcrun -f metal`) needed to compile Metal
//!     kernels. Installed headless via the `softwareupdate` on-demand
//!     mechanism (flag choice documented below), removed by deleting
//!     `/Library/Developer/CommandLineTools`. When present but the Metal
//!     toolchain is unusable, the assessment is `NonCompliantFatal`
//!     (reinstall the tools).
//!
//! `Absent` removes the Command Line Tools; MPS itself is OS-provided and
//! cannot be removed. Inference-tuning environment variables
//! (`PYTORCH_MPS_HIGH_WATERMARK_RATIO`, ...) belong to `LineInFile` /
//! `Template` attributes on the service unit or shell profile.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::gpu::apple_mps::AppleMpsExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // The classic Apple-Silicon inference host
//! let mps = AppleMpsExpectedState::inference_host("13.5");
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::apple_mps(mps, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: MPS inference host prerequisites
//!     Privilege: !WithSudo
//!     Timeout: 1800
//!     Detail: !AppleMps
//!       State: Present
//!       AppleSilicon: true
//!       MinMacosVersion: "13.5"
//!       CommandLineTools: true
//! ```

use std::cmp::Ordering;
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

// ── Value enums ───────────────────────────────────────────────────────────────

// ── ExpectedState ─────────────────────────────────────────────────────────────

/// Desired state of the Apple MPS (Metal) prerequisites.
///
/// Type-system-first: each variant carries only the parameters that make
/// sense for it. `Absent` removes the Xcode Command Line Tools — the only
/// removable MPS component, MPS itself is part of macOS — and needs no
/// parameters. `Present` carries the requested prerequisite checks, each
/// optional; with none set it simply asserts the host is a Mac (a hardware
/// `Ping`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "State",
    rename_all = "PascalCase",
    rename_all_fields = "PascalCase"
)]
pub enum AppleMpsExpectedState {
    /// The Xcode Command Line Tools must be removed. MPS itself is part of
    /// macOS and cannot be removed.
    Absent,
    Present {
        /// The host must run on Apple Silicon (`arm64`). Cannot be `false`.
        apple_silicon: Option<bool>,
        /// The host must run at least this macOS version (`13.5`, `14.0`, ...).
        min_macos_version: Option<String>,
        /// The Xcode Command Line Tools (Metal toolchain) must be installed
        /// (`true`) or removed (`false`).
        command_line_tools: Option<bool>,
    },
}

/// Path the Xcode Command Line Tools install to (and are removed from).
const COMMAND_LINE_TOOLS_PATH: &str = "/Library/Developer/CommandLineTools";

impl Timeout for AppleMpsExpectedState {
    fn default_timeout(&self) -> Duration {
        match self {
            AppleMpsExpectedState::Absent => Duration::from_secs(300),
            // Command Line Tools are a multi-GB download
            AppleMpsExpectedState::Present { .. } => Duration::from_secs(1800),
        }
    }
}

impl AppleMpsExpectedState {
    /// Assert a Mac host (no further requirements).
    pub fn present() -> AppleMpsExpectedState {
        AppleMpsExpectedState::Present {
            apple_silicon: None,
            min_macos_version: None,
            command_line_tools: None,
        }
    }

    /// The classic Apple-Silicon inference host: arm64 + minimum macOS
    /// version + Xcode Command Line Tools (Metal toolchain).
    pub fn inference_host(min_macos_version: &str) -> AppleMpsExpectedState {
        AppleMpsExpectedState::Present {
            apple_silicon: Some(true),
            min_macos_version: Some(min_macos_version.to_string()),
            command_line_tools: Some(true),
        }
    }

    pub fn absent() -> AppleMpsExpectedState {
        AppleMpsExpectedState::Absent
    }

    pub fn with_apple_silicon(mut self, apple_silicon: bool) -> Self {
        if let AppleMpsExpectedState::Present {
            apple_silicon: field,
            ..
        } = &mut self
        {
            *field = Some(apple_silicon);
        }
        self
    }

    pub fn with_min_macos_version(mut self, version: &str) -> Self {
        if let AppleMpsExpectedState::Present {
            min_macos_version, ..
        } = &mut self
        {
            *min_macos_version = Some(version.to_string());
        }
        self
    }

    pub fn with_command_line_tools(mut self, installed: bool) -> Self {
        if let AppleMpsExpectedState::Present {
            command_line_tools, ..
        } = &mut self
        {
            *command_line_tools = Some(installed);
        }
        self
    }
}

impl Check for AppleMpsExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        match self {
            AppleMpsExpectedState::Absent => Ok(()),
            AppleMpsExpectedState::Present {
                apple_silicon,
                min_macos_version,
                ..
            } => {
                if *apple_silicon == Some(false) {
                    return Err(RegentError::IncoherentExpectedState(
                        "AppleMps AppleSilicon only accepts true: MPS requires Apple Silicon"
                            .to_string(),
                    ));
                }
                if let Some(version) = min_macos_version
                    && parse_macos_version(version).is_none()
                {
                    return Err(RegentError::IncoherentExpectedState(format!(
                        "AppleMps state has an invalid MinMacosVersion (expected 13.5, 14.0, ...): {}",
                        version
                    )));
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
            OsKind::MacOs(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but the AppleMps attribute is only supported for macOS",
                incompatible_os_kind
            ))),
        }
    }
}

// ── Internal API calls ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppleMpsModuleInternalApiCall {
    /// Install the Xcode Command Line Tools (headless, via softwareupdate).
    InstallCommandLineTools,
    RemoveCommandLineTools,
}

impl std::fmt::Display for AppleMpsModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppleMpsModuleInternalApiCall::InstallCommandLineTools => {
                write!(f, "install Xcode command line tools")
            }
            AppleMpsModuleInternalApiCall::RemoveCommandLineTools => {
                write!(f, "remove Xcode command line tools")
            }
        }
    }
}

// ── ApiCall ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppleMpsApiCall {
    pub api_call: AppleMpsModuleInternalApiCall,
    privilege: Privilege,
}

impl Check for AppleMpsApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::MacOs(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but the AppleMps attribute is only supported for macOS",
                incompatible_os_kind
            ))),
        }
    }
}

impl AppleMpsApiCall {
    pub fn display(&self) -> String {
        format!("apple-mps: {}", self.api_call)
    }

    pub fn from(api_call: AppleMpsModuleInternalApiCall, privilege: Privilege) -> AppleMpsApiCall {
        AppleMpsApiCall {
            api_call,
            privilege,
        }
    }
}

// ── Assessment ───────────────────────────────────────────────────────────────

impl<Handler: HostHandler> AssessCompliance<Handler> for AppleMpsExpectedState {
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
        let command_line_tools_installed = command_line_tools_present(host_handler).await?;

        match self {
            AppleMpsExpectedState::Absent => {
                if command_line_tools_installed {
                    remediations.push(Remediation::AppleMps(AppleMpsApiCall::from(
                        AppleMpsModuleInternalApiCall::RemoveCommandLineTools,
                        privilege.clone(),
                    )));
                }
            }
            AppleMpsExpectedState::Present {
                apple_silicon,
                min_macos_version,
                command_line_tools,
            } => {
                // 1. Apple Silicon assertion (hardware: fatal, not remediable)
                if *apple_silicon == Some(true) {
                    let arch = probe_architecture(host_handler).await?;
                    if arch.as_deref() != Some("arm64") {
                        return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                            "MPS requires Apple Silicon; this Mac reports architecture {:?}",
                            arch
                        )));
                    }
                }

                // 2. Minimum macOS version assertion (OS: fatal, not remediable)
                if let Some(minimum) = min_macos_version {
                    let installed = probe_macos_version(host_handler).await?;
                    let installed = installed.ok_or_else(|| {
                        RegentError::FailedDryRunEvaluation(
                            "Unable to determine the macOS version (sw_vers)".to_string(),
                        )
                    })?;
                    match compare_dotted_versions(&installed, minimum) {
                        Some(Ordering::Less) => {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                                "macOS {} is older than the required {}; upgrade the OS to use MPS (softwareupdate)",
                                installed, minimum
                            )));
                        }
                        None => {
                            return Err(RegentError::FailedDryRunEvaluation(format!(
                                "Unable to compare macOS version {} with {}",
                                installed, minimum
                            )));
                        }
                        _ => {}
                    }
                }

                // 3. Command Line Tools (the managed component)
                match command_line_tools {
                    Some(true) => {
                        if !command_line_tools_installed {
                            remediations.push(Remediation::AppleMps(AppleMpsApiCall::from(
                                AppleMpsModuleInternalApiCall::InstallCommandLineTools,
                                privilege.clone(),
                            )));
                        } else if !metal_toolchain_usable(host_handler).await? {
                            return Ok(AttributeComplianceAssessment::NonCompliantFatal(
                                "Xcode Command Line Tools are installed but the Metal toolchain is unusable (xcrun -f metal); reinstall them".to_string(),
                            ));
                        }
                    }
                    Some(false) if command_line_tools_installed => {
                        remediations.push(Remediation::AppleMps(AppleMpsApiCall::from(
                            AppleMpsModuleInternalApiCall::RemoveCommandLineTools,
                            privilege.clone(),
                        )));
                    }
                    _ => {}
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

impl<Handler: HostHandler> ReachCompliance<Handler> for AppleMpsApiCall {
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
            AppleMpsModuleInternalApiCall::InstallCommandLineTools => {
                // Headless install through the softwareupdate on-demand
                // mechanism (`xcode-select --install` opens a GUI, unusable
                // over SSH). The product title is parsed from the raw
                // `softwareupdate -l` output in Rust.
                let flag = "/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress";
                let cleanup = format!("rm -f {flag}");

                let result = host_handler
                    .run_command(&format!("touch {flag}"), &self.privilege)
                    .await
                    .map_err(|e| RegentError::FailureToRunCommand(format!("{:?}", e)))?;
                if result.return_code != 0 {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "softwareupdate on-demand flag creation failed (RC {}): {}",
                        result.return_code,
                        result.stderr.trim()
                    )));
                }

                let listing = host_handler
                    .run_command("softwareupdate -l", &self.privilege)
                    .await
                    .map_err(|e| RegentError::FailureToRunCommand(format!("{:?}", e)))?;
                if listing.return_code != 0 {
                    let _ = host_handler.run_command(&cleanup, &self.privilege).await;
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "softwareupdate -l failed (RC {}): {}",
                        listing.return_code,
                        listing.stderr.trim()
                    )));
                }

                // Product title of the Command Line Tools update: the
                // `*`-prefixed line among the first "Command Line" mention
                // and the line before it — everything after the `*`, leading
                // spaces stripped.
                let lines: Vec<&str> = listing.stdout.lines().collect();
                let mut product: Option<String> = None;
                if let Some(at) = lines.iter().position(|l| l.contains("Command Line")) {
                    let from = at.saturating_sub(1);
                    for line in &lines[from..=at] {
                        if let Some((_, after)) = line.split_once('*') {
                            product = Some(after.trim_start().to_string());
                            break;
                        }
                    }
                }
                let Some(product) = product else {
                    let _ = host_handler.run_command(&cleanup, &self.privilege).await;
                    return Ok(InternalApiCallOutcome::Failure(
                        "no Command Line Tools update found in the softwareupdate output"
                            .to_string(),
                    ));
                };

                let result = host_handler
                    .run_command(
                        &format!("softwareupdate -i {} --verbose", shell_quote(&product)),
                        &self.privilege,
                    )
                    .await
                    .map_err(|e| RegentError::FailureToRunCommand(format!("{:?}", e)))?;
                let _ = host_handler.run_command(&cleanup, &self.privilege).await;
                if result.return_code != 0 {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "command line tools install failed (RC {}): {}",
                        result.return_code,
                        result.stderr.trim()
                    )));
                }
                if command_line_tools_present(host_handler).await? {
                    Ok(InternalApiCallOutcome::Success(None))
                } else {
                    Ok(InternalApiCallOutcome::Failure(
                        "command line tools install succeeded but they are still not present"
                            .to_string(),
                    ))
                }
            }
            AppleMpsModuleInternalApiCall::RemoveCommandLineTools => {
                let cmd = format!("rm -rf {}", shell_quote(COMMAND_LINE_TOOLS_PATH));
                let result = host_handler
                    .run_command(&cmd, &self.privilege)
                    .await
                    .map_err(|e| RegentError::FailureToRunCommand(format!("{:?}", e)))?;
                if result.return_code != 0 {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "command line tools removal failed (RC {}): {}",
                        result.return_code,
                        result.stderr.trim()
                    )));
                }
                if command_line_tools_present(host_handler).await? {
                    Ok(InternalApiCallOutcome::Failure(format!(
                        "removal succeeded but {} still exists",
                        COMMAND_LINE_TOOLS_PATH
                    )))
                } else {
                    Ok(InternalApiCallOutcome::Success(None))
                }
            }
        }
    }
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

/// Parse a macOS version string (`13.5`, `14.1.1`) into numeric components.
fn parse_macos_version(version: &str) -> Option<Vec<u64>> {
    let parts: Vec<&str> = version.trim().split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    parts
        .iter()
        .map(|part| {
            if part.is_empty() {
                None
            } else {
                part.parse::<u64>().ok()
            }
        })
        .collect()
}

/// Compare two dotted numeric versions, padding the shorter with zeros.
/// `None` when either side is not a valid dotted numeric version.
fn compare_dotted_versions(a: &str, b: &str) -> Option<Ordering> {
    let a = parse_macos_version(a)?;
    let b = parse_macos_version(b)?;
    let len = a.len().max(b.len());
    for i in 0..len {
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        match left.cmp(&right) {
            Ordering::Equal => continue,
            ordering => return Some(ordering),
        }
    }
    Some(Ordering::Equal)
}

// ── Host interaction helpers ──────────────────────────────────────────────────

/// The CPU architecture reported by `uname -m` (e.g. `arm64`).
async fn probe_architecture<Handler: HostHandler>(
    host_handler: &mut Handler,
) -> Result<Option<String>, RegentError> {
    let result = host_handler
        .run_command("uname -m", &Privilege::None)
        .await
        .map_err(|e| RegentError::FailedDryRunEvaluation(format!("{:?}", e)))?;
    let arch = result.stdout.trim();
    if result.return_code != 0 || arch.is_empty() {
        Ok(None)
    } else {
        Ok(Some(arch.to_string()))
    }
}

/// The macOS product version reported by `sw_vers -productVersion` (e.g.
/// `14.5`).
async fn probe_macos_version<Handler: HostHandler>(
    host_handler: &mut Handler,
) -> Result<Option<String>, RegentError> {
    let result = host_handler
        .run_command("sw_vers -productVersion", &Privilege::None)
        .await
        .map_err(|e| RegentError::FailedDryRunEvaluation(format!("{:?}", e)))?;
    let version = result.stdout.trim();
    if result.return_code != 0 || version.is_empty() {
        Ok(None)
    } else {
        Ok(Some(version.to_string()))
    }
}

/// Whether the Xcode Command Line Tools are installed at their standard path.
async fn command_line_tools_present<Handler: HostHandler>(
    host_handler: &mut Handler,
) -> Result<bool, RegentError> {
    let cmd = format!("test -d {}", shell_quote(COMMAND_LINE_TOOLS_PATH));
    let result = host_handler
        .run_command(&cmd, &Privilege::None)
        .await
        .map_err(|e| RegentError::FailedDryRunEvaluation(format!("{:?}", e)))?;
    Ok(result.return_code == 0)
}

/// Whether the Metal toolchain is usable (`xcrun -f metal`).
async fn metal_toolchain_usable<Handler: HostHandler>(
    host_handler: &mut Handler,
) -> Result<bool, RegentError> {
    let result = host_handler
        .run_command("xcrun -f metal >/dev/null 2>&1", &Privilege::None)
        .await
        .map_err(|e| RegentError::FailedDryRunEvaluation(format!("{:?}", e)))?;
    Ok(result.return_code == 0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    use super::*;
    use crate::state::attribute::Attribute;

    #[test]
    fn parsing_apple_mps_module_block_from_yaml_str() {
        let raw_attribute = "---
State: Present
AppleSilicon: true
MinMacosVersion: '13.5'
CommandLineTools: true
";

        let attribute: AppleMpsExpectedState = yaml_serde::from_str(raw_attribute).unwrap();

        let AppleMpsExpectedState::Present {
            apple_silicon,
            min_macos_version,
            command_line_tools,
        } = &attribute
        else {
            panic!("expected the Present variant");
        };
        assert_eq!(*apple_silicon, Some(true));
        assert_eq!(min_macos_version, &Some("13.5".to_string()));
        assert_eq!(*command_line_tools, Some(true));
        assert!(attribute.check().is_ok());

        let raw_absent = "---\nState: Absent\n";
        let absent: AppleMpsExpectedState = yaml_serde::from_str(raw_absent).unwrap();
        assert_eq!(absent, AppleMpsExpectedState::Absent);

        // Bare Present: the hardware Ping
        let raw_bare = "---\nState: Present\n";
        let bare: AppleMpsExpectedState = yaml_serde::from_str(raw_bare).unwrap();
        assert_eq!(bare, AppleMpsExpectedState::present());
        assert!(bare.check().is_ok());
    }

    #[test]
    fn rejecting_incorrect_apple_mps_module_block_from_yaml_str() {
        // Missing State tag
        let raw = "---\nAppleSilicon: true\n";
        assert!(yaml_serde::from_str::<AppleMpsExpectedState>(raw).is_err());

        // Invalid state value
        let raw = "---\nState: Flying\n";
        assert!(yaml_serde::from_str::<AppleMpsExpectedState>(raw).is_err());

        // NOTE: unknown keys inside the `Present` variant are silently ignored
        // (serde's internally tagged enum buffering does not honor
        // deny_unknown_fields).
    }

    #[test]
    fn check_validates_spec_invariants() {
        // AppleSilicon: false makes no sense for MPS
        let spec = AppleMpsExpectedState::present().with_apple_silicon(false);
        assert!(spec.check().is_err());

        // Invalid macOS version
        let spec = AppleMpsExpectedState::present().with_min_macos_version("13.x");
        assert!(spec.check().is_err());

        // Valid inference host
        let spec = AppleMpsExpectedState::inference_host("13.5");
        spec.check().unwrap();

        // Absent is always valid
        AppleMpsExpectedState::absent().check().unwrap();
    }

    #[test]
    fn dotted_version_comparison() {
        assert_eq!(
            compare_dotted_versions("13.5", "13.5"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_dotted_versions("14.0", "13.5"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_dotted_versions("12.7", "13.5"),
            Some(Ordering::Less)
        );
        // Shorter versions are padded with zeros
        assert_eq!(compare_dotted_versions("13", "13.0"), Some(Ordering::Equal));
        assert_eq!(
            compare_dotted_versions("14.1.1", "14.1"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_dotted_versions("14.x", "13"), None);
    }

    #[test]
    fn api_call_display() {
        let call = AppleMpsApiCall::from(
            AppleMpsModuleInternalApiCall::InstallCommandLineTools,
            Privilege::WithSudo,
        );
        assert_eq!(
            call.display(),
            "apple-mps: install Xcode command line tools"
        );
    }

    #[test]
    fn parsing_full_apple_mps_attribute_envelope_from_yaml_str() {
        let raw_attribute = "---
Name: MPS inference host prerequisites
Privilege: !WithSudo
Timeout: 1800
Detail: !AppleMps
  State: Present
  AppleSilicon: true
  MinMacosVersion: '13.5'
  CommandLineTools: true
";
        let attribute: Attribute = yaml_serde::from_str(raw_attribute).unwrap();
        assert!(attribute.check().is_ok());
        assert_eq!(attribute.name(), "MPS inference host prerequisites");
    }
}
