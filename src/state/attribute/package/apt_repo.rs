//! APT repository management attribute
//!
//! This module provides the `AptRepoBlockExpectedState` type for managing APT repository
//! sources in `/etc/apt/sources.list.d/`. Supports both legacy `.list` format and modern
//! `.sources` (deb822) format.
//!
//! **Compatible OS:** Linux (Debian-based distributions: Debian, Ubuntu, etc.)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::apt_repo::{AptRepoBlockExpectedState, AptRepoExpectedState, AptRepoType};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Add a repository using legacy format
//! let repo = AptRepoBlockExpectedState::builder("docker")
//!     .with_state(AptRepoExpectedState::Present)
//!     .with_repo("deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable")
//!     .with_update_cache(true)
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::apt_repo(repo, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !AptRepo
//!       Filename: docker
//!       State: !Present
//!       Repo: "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable"
//!       UpdateCache: true
//!       Privilege: !WithSudo
//! ```

use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::{HostProperties, LinuxFlavor, LinuxSpecifics, OsKind};
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Desired state of a repository
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AptRepoExpectedState {
    /// Repository should exist
    Present,
    /// Repository should be removed
    Absent,
}

/// Repository type for deb822 format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AptRepoType {
    /// Binary packages
    Deb,
    /// Source packages
    DebSrc,
}

impl AptRepoType {
    fn as_str(&self) -> &str {
        match self {
            AptRepoType::Deb => "deb",
            AptRepoType::DebSrc => "deb-src",
        }
    }
}

/// Configuration for an APT repository
///
/// Manages an APT repository source file in `/etc/apt/sources.list.d/`.
/// Supports two formats:
///
/// **Legacy** (.list): set `repo` to the full one-liner string
///   `repo: "deb https://... focal main"`
///
/// **Deb822** (.sources): set `types`, `uris`, `suites` (and optionally `components`,
///   `signed_by`, `architectures`, `enabled`)
///
/// `filename` (without extension) is required in both cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct AptRepoBlockExpectedState {
    /// Filename (without extension) for the repository file in /etc/apt/sources.list.d/
    filename: String,
    /// Desired state of the repository
    state: Option<AptRepoExpectedState>,
    /// Whether to run apt-get update after adding/removing repositories
    update_cache: Option<bool>,
    /// Legacy one-liner format → writes to <filename>.list
    repo: Option<String>,
    /// Repository types for deb822 format → writes to <filename>.sources
    types: Option<Vec<AptRepoType>>,
    /// URIs for deb822 format
    uris: Option<Vec<String>>,
    /// Suites for deb822 format
    suites: Option<Vec<String>>,
    /// Components for deb822 format
    components: Option<Vec<String>>,
    /// Signed-by fingerprint for deb822 format
    signed_by: Option<String>,
    /// Whether the repository is enabled for deb822 format
    enabled: Option<bool>,
    /// Architectures for deb822 format
    architectures: Option<Vec<String>>,
}

impl Timeout for AptRepoBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(3)
    }
}

impl AptRepoBlockExpectedState {
    pub fn builder(filename: &str) -> AptRepoBlockExpectedState {
        AptRepoBlockExpectedState {
            filename: filename.to_string(),
            state: None,
            update_cache: None,
            repo: None,
            types: None,
            uris: None,
            suites: None,
            components: None,
            signed_by: None,
            enabled: None,
            architectures: None,
        }
    }

    pub fn with_state(&mut self, state: AptRepoExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_update_cache(&mut self, update_cache: bool) -> &mut Self {
        self.update_cache = Some(update_cache);
        self
    }

    pub fn with_repo(&mut self, repo: &str) -> &mut Self {
        self.repo = Some(repo.to_string());
        self
    }

    pub fn with_types(&mut self, types: Vec<AptRepoType>) -> &mut Self {
        self.types = Some(types);
        self
    }

    pub fn with_uris(&mut self, uris: Vec<String>) -> &mut Self {
        self.uris = Some(uris);
        self
    }

    pub fn with_suites(&mut self, suites: Vec<String>) -> &mut Self {
        self.suites = Some(suites);
        self
    }

    pub fn with_components(&mut self, components: Vec<String>) -> &mut Self {
        self.components = Some(components);
        self
    }

    pub fn with_signed_by(&mut self, signed_by: &str) -> &mut Self {
        self.signed_by = Some(signed_by.to_string());
        self
    }

    pub fn with_enabled(&mut self, enabled: bool) -> &mut Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn with_architectures(&mut self, architectures: Vec<String>) -> &mut Self {
        self.architectures = Some(architectures);
        self
    }

    pub fn build(&self) -> Result<AptRepoBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for AptRepoBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.filename.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "Filename cannot be empty.".to_string(),
            ));
        }

        let state = self
            .state
            .as_ref()
            .unwrap_or(&AptRepoExpectedState::Present);
        if let AptRepoExpectedState::Present = state {
            let is_legacy = self.repo.is_some();
            let is_deb822 = self.types.is_some() || self.uris.is_some() || self.suites.is_some();

            if !is_legacy && !is_deb822 {
                return Err(RegentError::IncoherentExpectedState(
                    "State Present requires either Repo (legacy) or Types+Uris+Suites (deb822)."
                        .to_string(),
                ));
            }
            if is_legacy && is_deb822 {
                return Err(RegentError::IncoherentExpectedState(
                    "Repo (legacy) and deb822 fields (Types, Uris, Suites, ...) are mutually exclusive.".to_string(),
                ));
            }
            if is_deb822 {
                if self.types.is_none() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Deb822 format requires Types.".to_string(),
                    ));
                }
                if self.uris.is_none() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Deb822 format requires Uris.".to_string(),
                    ));
                }
                if self.suites.is_none() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Deb822 format requires Suites.".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Debian,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but APT repositories are only supported on Debian-based Linux distributions",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for AptRepoBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Debian-based Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let state = self
            .state
            .as_ref()
            .unwrap_or(&AptRepoExpectedState::Present);
        let is_legacy = self.repo.is_some();
        let file_path = apt_repo_file_path(&self.filename, is_legacy);

        let current_content = match read_file(host_handler, &file_path).await {
            Ok(c) => c,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        match state {
            AptRepoExpectedState::Absent => {
                if current_content.is_none() {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::AptRepo(AptRepoApiCall::from(
                        AptRepoModuleInternalApiCall::RemoveFile { path: file_path },
                        privilege.clone(),
                    )),
                ]));
            }
            AptRepoExpectedState::Present => {
                let expected_content = if is_legacy {
                    build_legacy_content(self.repo.as_deref().unwrap())
                } else {
                    build_deb822_content(self)
                };

                let already_correct = current_content
                    .as_deref()
                    .map(|c| c.trim() == expected_content.trim())
                    .unwrap_or(false);

                if already_correct {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }

                // Enhanced verification: explicitly check critical properties like URLs
                // This provides better error messages and ensures source verification
                if !is_legacy {
                    // For deb822 format, verify that critical properties match
                    if let Some(ref current) = current_content {
                        let current_trimmed = current.trim();
                        let expected_trimmed = expected_content.trim();

                        // Check if URIs (source URLs) are different
                        if let (Some(current_uris), Some(expected_uris)) = (
                            extract_uris_from_deb822(current_trimmed),
                            extract_uris_from_deb822(expected_trimmed),
                        ) {
                            if current_uris != expected_uris {
                                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                                    Remediation::AptRepo(AptRepoApiCall::from(
                                        AptRepoModuleInternalApiCall::WriteFile {
                                            path: file_path,
                                            content: expected_content,
                                        },
                                        privilege.clone(),
                                    )),
                                ]));
                            }
                        }
                    }
                }

                let mut remediations = vec![Remediation::AptRepo(AptRepoApiCall::from(
                    AptRepoModuleInternalApiCall::WriteFile {
                        path: file_path,
                        content: expected_content,
                    },
                    privilege.clone(),
                ))];

                if self.update_cache.unwrap_or(false) {
                    remediations.push(Remediation::AptRepo(AptRepoApiCall::from(
                        AptRepoModuleInternalApiCall::UpdateCache,
                        privilege.clone(),
                    )));
                }

                Ok(AttributeComplianceAssessment::NonCompliant(remediations))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AptRepoModuleInternalApiCall {
    WriteFile { path: String, content: String },
    RemoveFile { path: String },
    UpdateCache,
}

impl std::fmt::Display for AptRepoModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AptRepoModuleInternalApiCall::WriteFile { path, .. } => {
                write!(f, "write apt repo file {}", path)
            }
            AptRepoModuleInternalApiCall::RemoveFile { path } => {
                write!(f, "remove apt repo file {}", path)
            }
            AptRepoModuleInternalApiCall::UpdateCache => write!(f, "apt-get update"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AptRepoApiCall {
    pub api_call: AptRepoModuleInternalApiCall,
    privilege: Privilege,
}

impl Check for AptRepoApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Debian,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but APT repositories are only supported on Debian-based Linux distributions",
                incompatible_os_kind
            ))),
        }
    }
}

impl AptRepoApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            AptRepoModuleInternalApiCall::WriteFile { path, .. } => {
                format!("Write apt repo file {}", path)
            }
            AptRepoModuleInternalApiCall::RemoveFile { path } => {
                format!("Remove apt repo file {}", path)
            }
            AptRepoModuleInternalApiCall::UpdateCache => "Run apt-get update".to_string(),
        }
    }

    fn from(api_call: AptRepoModuleInternalApiCall, privilege: Privilege) -> AptRepoApiCall {
        AptRepoApiCall {
            api_call,
            privilege,
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for AptRepoApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Debian-based Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let (cmd, privilege) = match &self.api_call {
            AptRepoModuleInternalApiCall::WriteFile { path, content } => (
                format!("printf '{}' > {}", escape_for_printf(content), path),
                &self.privilege,
            ),
            AptRepoModuleInternalApiCall::RemoveFile { path } => {
                (format!("rm -f {}", path), &self.privilege)
            }
            AptRepoModuleInternalApiCall::UpdateCache => {
                ("apt-get update".to_string(), &self.privilege)
            }
        };

        let cmd_result = host_handler
            .run_command(cmd.as_str(), privilege)
            .await
            .unwrap();

        if cmd_result.return_code == 0 {
            Ok(InternalApiCallOutcome::Success(None))
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC: {}, STDOUT: {}, STDERR: {}",
                cmd_result.return_code, cmd_result.stdout, cmd_result.stderr
            )))
        }
    }
}

fn apt_repo_file_path(filename: &str, is_legacy: bool) -> String {
    let ext = if is_legacy { "list" } else { "sources" };
    format!("/etc/apt/sources.list.d/{}.{}", filename, ext)
}

fn build_legacy_content(repo_line: &str) -> String {
    format!("{}\n", repo_line.trim())
}

fn build_deb822_content(block: &AptRepoBlockExpectedState) -> String {
    let mut lines: Vec<String> = Vec::new();

    if let Some(false) = block.enabled {
        lines.push("Enabled: no".to_string());
    }
    if let Some(ref types) = block.types {
        let s: Vec<&str> = types.iter().map(|t| t.as_str()).collect();
        lines.push(format!("Types: {}", s.join(" ")));
    }
    if let Some(ref uris) = block.uris {
        lines.push(format!("URIs: {}", uris.join(" ")));
    }
    if let Some(ref suites) = block.suites {
        lines.push(format!("Suites: {}", suites.join(" ")));
    }
    if let Some(ref components) = block.components {
        lines.push(format!("Components: {}", components.join(" ")));
    }
    if let Some(ref archs) = block.architectures {
        lines.push(format!("Architectures: {}", archs.join(" ")));
    }
    if let Some(ref signed_by) = block.signed_by {
        lines.push(format!("Signed-By: {}", signed_by));
    }

    lines.join("\n") + "\n"
}

fn escape_for_printf(content: &str) -> String {
    content
        .replace('\\', "\\\\")
        .replace('%', "%%")
        .replace('\n', "\\n")
}

/// Extract URIs from deb822 format content for source verification.
/// This ensures that repository URLs are explicitly checked during assessment.
fn extract_uris_from_deb822(content: &str) -> Option<Vec<String>> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("URIs:") || trimmed.starts_with("URI:") {
            let uris_part = trimmed.split(':').nth(1).map(|s| s.trim());
            if let Some(uris_str) = uris_part {
                let uris: Vec<String> =
                    uris_str.split_whitespace().map(|s| s.to_string()).collect();
                return Some(uris);
            }
        }
    }
    None
}

async fn read_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
) -> Result<Option<String>, String> {
    match host_handler
        .run_command(&format!("cat {}", path), &Privilege::None)
        .await
    {
        Ok(result) => {
            if result.return_code == 0 {
                Ok(Some(result.stdout))
            } else {
                Ok(None) // File does not exist
            }
        }
        Err(e) => Err(format!("Failed to read {}: {:?}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_apt_repo_legacy_from_yaml() {
        let raw = "---
- Filename: docker
  Repo: 'deb https://download.docker.com/linux/ubuntu focal stable'

- Filename: docker
  State: !Absent
        ";
        let _attrs: Vec<AptRepoBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }

    #[test]
    fn parsing_apt_repo_deb822_from_yaml() {
        let raw = "---
- Filename: docker
  Types:
    - !Deb
  Uris:
    - https://download.docker.com/linux/ubuntu
  Suites:
    - focal
  Components:
    - stable
  SignedBy: /usr/share/keyrings/docker-archive-keyring.gpg
        ";
        let _attrs: Vec<AptRepoBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }

    #[test]
    fn check_rejects_empty_filename() {
        let result = AptRepoBlockExpectedState::builder("").build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_present_without_content() {
        let result = AptRepoBlockExpectedState::builder("test")
            .with_state(AptRepoExpectedState::Present)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_mixed_legacy_and_deb822() {
        let result = AptRepoBlockExpectedState::builder("test")
            .with_repo("deb http://... focal main")
            .with_types(vec![AptRepoType::Deb])
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_deb822_missing_uris() {
        let result = AptRepoBlockExpectedState::builder("test")
            .with_types(vec![AptRepoType::Deb])
            .with_suites(vec!["focal".to_string()])
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_absent_without_content() {
        let result = AptRepoBlockExpectedState::builder("test")
            .with_state(AptRepoExpectedState::Absent)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_deb822_content_basic() {
        let block = AptRepoBlockExpectedState::builder("docker")
            .with_types(vec![AptRepoType::Deb])
            .with_uris(vec!["https://download.docker.com/linux/ubuntu".to_string()])
            .with_suites(vec!["focal".to_string()])
            .with_components(vec!["stable".to_string()])
            .build()
            .unwrap();
        let content = build_deb822_content(&block);
        assert!(content.contains("Types: deb"));
        assert!(content.contains("URIs: https://download.docker.com/linux/ubuntu"));
        assert!(content.contains("Suites: focal"));
        assert!(content.contains("Components: stable"));
    }

    #[test]
    fn build_legacy_content_trims_and_adds_newline() {
        let content = build_legacy_content("  deb http://example.com focal main  ");
        assert_eq!(content, "deb http://example.com focal main\n");
    }

    #[test]
    fn escape_for_printf_handles_special_chars() {
        let escaped = escape_for_printf("a\nb%c\\d");
        assert_eq!(escaped, "a\\nb%%c\\\\d");
    }
}
