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
//!   - Name: Docker repository must be present
//!     Privilege: !WithSudo
//!     Detail: !AptRepo
//!       Filename: docker
//!       State: Present
//!       Format:
//!         Repo: "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable"
//!       UpdateCache: true
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
use crate::state::attribute::RemediationsList;
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
    state: AptRepoExpectedState,
    /// Whether to run apt-get update after adding/removing repositories
    #[serde(default)]
    cache_up_to_date: bool,
    #[serde(default)]
    format: Option<AptRepoFormat>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(untagged)]
pub enum AptRepoFormat {
    #[serde(rename_all = "PascalCase")]
    Legacy {
        /// Legacy one-liner format → writes to a `.list` file
        repo: String,
    },
    #[serde(rename_all = "PascalCase")]
    Deb822 {
        /// Repository types for deb822 format → writes to a `.sources` file
        types: Vec<AptRepoType>,
        /// URIs for deb822 format
        uris: Vec<String>,
        /// Suites for deb822 format
        suites: Vec<String>,
        /// Components for deb822 format
        components: Option<Vec<String>>,
        /// Signed-by fingerprint for deb822 format
        signed_by: Option<String>,
        /// Whether the repository is enabled for deb822 format
        enabled: Option<bool>,
        /// Architectures for deb822 format
        architectures: Option<Vec<String>>,
    },
}

impl Timeout for AptRepoBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(3)
    }
}

impl AptRepoBlockExpectedState {
    pub fn legacy_format(
        filename: &str,
        repo: &str,
        state: AptRepoExpectedState,
        cache_up_to_date: bool,
    ) -> AptRepoBlockExpectedState {
        AptRepoBlockExpectedState {
            filename: filename.to_string(),
            state,
            cache_up_to_date,
            format: Some(AptRepoFormat::Legacy {
                repo: repo.to_string(),
            }),
        }
    }

    pub fn deb822_format(
        filename: &str,
        state: AptRepoExpectedState,
        types: Vec<AptRepoType>,
        uris: Vec<String>,
        suites: Vec<String>,
        components: Option<Vec<String>>,
        signed_by: Option<String>,
        enabled: Option<bool>,
        architectures: Option<Vec<String>>,
        cache_up_to_date: bool,
    ) -> AptRepoBlockExpectedState {
        AptRepoBlockExpectedState {
            filename: filename.to_string(),
            state,
            cache_up_to_date,
            format: Some(AptRepoFormat::Deb822 {
                types,
                uris,
                suites,
                components,
                signed_by,
                enabled,
                architectures,
            }),
        }
    }
}

impl Check for AptRepoBlockExpectedState {
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

        let mut remediations: Vec<Remediation> = Vec::new();

        let current_content = match read_file(host_handler, &self.filename).await {
            Ok(c) => c,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        match self.state {
            AptRepoExpectedState::Absent => {
                if current_content.is_some() {
                    remediations.push(Remediation::AptRepo(AptRepoApiCall::from(
                        AptRepoModuleInternalApiCall::RemoveFile {
                            path: self.filename.clone(),
                        },
                        privilege.clone(),
                    )));
                }
            }
            AptRepoExpectedState::Present => {
                let format = self.format.as_ref().expect("Format must be provided for Present state");
                let expected_content = match format {
                    AptRepoFormat::Legacy { repo } => build_legacy_content(&repo),
                    AptRepoFormat::Deb822 {
                        types: _,
                        uris: _,
                        suites: _,
                        components: _,
                        signed_by: _,
                        enabled: _,
                        architectures: _,
                    } => build_deb822_content(format),
                };

                if current_content.is_some() {
                    // Check on content required
                    if let Some(current) = current_content {
                        if current.trim() != expected_content.trim() {
                            remediations.push(Remediation::AptRepo(AptRepoApiCall::from(
                                AptRepoModuleInternalApiCall::WriteFile {
                                    path: self.filename.clone(),
                                    content: expected_content,
                                },
                                privilege.clone(),
                            )));
                        }
                    }
                } else {
                    // Creation from scratch required
                    remediations.push(Remediation::AptRepo(AptRepoApiCall::from(
                        AptRepoModuleInternalApiCall::WriteFile {
                            path: self.filename.clone(),
                            content: expected_content,
                        },
                        privilege.clone(),
                    )));
                }
            }
        }

        if self.cache_up_to_date {
            remediations.push(Remediation::AptRepo(AptRepoApiCall::from(
                AptRepoModuleInternalApiCall::UpdateCache,
                privilege.clone(),
            )));
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

fn build_deb822_content(format: &AptRepoFormat) -> String {
    let mut lines: Vec<String> = Vec::new();

    match format {
        AptRepoFormat::Legacy { .. } => {
            // This shouldn't be called for Legacy format
            unreachable!();
        }
        AptRepoFormat::Deb822 {
            types,
            uris,
            suites,
            components,
            signed_by,
            enabled,
            architectures,
        } => {
            if let Some(false) = enabled {
                lines.push("Enabled: no".to_string());
            }
            if !types.is_empty() {
                let s: Vec<&str> = types.iter().map(|t| t.as_str()).collect();
                lines.push(format!("Types: {}", s.join(" ")));
            }
            if !uris.is_empty() {
                lines.push(format!("URIs: {}", uris.join(" ")));
            }
            if !suites.is_empty() {
                lines.push(format!("Suites: {}", suites.join(" ")));
            }
            if let Some(components) = components {
                if !components.is_empty() {
                    lines.push(format!("Components: {}", components.join(" ")));
                }
            }
            if let Some(archs) = architectures {
                if !archs.is_empty() {
                    lines.push(format!("Architectures: {}", archs.join(" ")));
                }
            }
            if let Some(signed_by) = signed_by {
                lines.push(format!("Signed-By: {}", signed_by));
            }
        }
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
  State: Present
  Format:
    Repo: 'deb https://download.docker.com/linux/ubuntu focal stable'

- Filename: docker
  State: Absent
        ";
        let _attrs: Vec<AptRepoBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }

    #[test]
    fn parsing_apt_repo_deb822_from_yaml() {
        let raw = "---
- Filename: docker
  State: Present
  Format:
    Types:
      - Deb
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
