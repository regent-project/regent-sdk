//! DNF/YUM repository management attribute
//!
//! This module provides the `DnfRepoBlockExpectedState` enum for managing DNF/YUM
//! repository `.repo` files in `/etc/yum.repos.d/`. The enum-based design ensures
//! that incoherent state combinations are impossible to represent at compile time.
//!
//! **Compatible OS:** Linux (Fedora, CentOS, RHEL-based distributions)
//!
//! # Design
//!
//! The `DnfRepoBlockExpectedState` enum uses two variants to enforce type safety:
//!
//! - **`Present`**: Contains all repository configuration fields including `source` (required),
//!   `description`, `enabled`, `gpgcheck`, `gpgkey`, `file`, `priority`, `sslverify`, and `exclude` (all optional).
//! - **`Absent`**: Contains only `name` (required) and `file` (optional) fields.
//!
//! This design makes it impossible to represent invalid states such as:
//! - An absent repository with `enabled`, `gpgcheck`, or other configuration settings
//! - A present repository without a `source`
//! - Multiple source types (baseurl, mirrorlist, metalink) simultaneously
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::dnf_repo::{DnfRepoBlockExpectedState, DnfRepoSource};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Using factory methods (recommended for most cases)
//! let repo = DnfRepoBlockExpectedState::present("docker-ce",
//!     DnfRepoSource::Baseurl(vec!["https://download.docker.com/linux/centos/7/x86_64/stable".to_string()])
//! );
//!
//! // Or using struct literal syntax for full configuration
//! let repo = DnfRepoBlockExpectedState::Present {
//!     name: "docker-ce".to_string(),
//!     source: DnfRepoSource::Baseurl(vec!["https://download.docker.com/linux/centos/7/x86_64/stable".to_string()]),
//!     description: Some("Docker CE Stable".to_string()),
//!     enabled: Some(true),
//!     gpgcheck: Some(true),
//!     gpgkey: Some(vec!["https://download.docker.com/linux/centos/gpg".to_string()]),
//!     file: None,
//!     priority: None,
//!     sslverify: None,
//!     exclude: None,
//! };
//!
//! // Remove a repository (only name and optional file are available)
//! let repo_absent = DnfRepoBlockExpectedState::absent("docker-ce");
//!
//! // Or using struct literal
//! let repo_absent = DnfRepoBlockExpectedState::Absent {
//!     name: "docker-ce".to_string(),
//!     file: None,
//! };
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::dnf_repo(repo, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   # Repository must be present with configuration
//!   - Name: Docker CE repository must be present
//!     Privilege: !WithSudo
//!     Detail: !DnfRepo
//!       Present:
//!         Name: docker-ce
//!         Source: !Baseurl
//!           - "https://download.docker.com/linux/centos/7/x86_64/stable"
//!         Description: Docker CE Stable
//!         Enabled: true
//!         Gpgcheck: true
//!         Gpgkey:
//!           - "https://download.docker.com/linux/centos/gpg"
//!
//!   # Repository must be absent (removed)
//!   - Name: Docker CE repository must be absent
//!     Privilege: !WithSudo
//!     Detail: !DnfRepo
//!       Absent:
//!         Name: docker-ce
//!
//!   # Absent with custom file path
//!   - Name: Remove old repository file
//!     Privilege: !WithSudo
//!     Detail: !DnfRepo
//!       Absent:
//!         Name: docker-ce
//!         File: custom-repo
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

/// Desired state of a DNF/YUM repository
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DnfRepoExpectedState {
    /// Repository should exist
    Present,
    /// Repository should be removed
    Absent,
}

/// Source configuration for a DNF/YUM repository
///
/// This enum ensures that exactly one source type is specified, making it impossible
/// to have multiple conflicting source definitions. The variants are:
///
/// - **`Baseurl`**: One or more base URLs for the repository
/// - **`Mirrorlist`**: URL to a file containing a list of mirror URLs
/// - **`Metalink`**: URL to a metalink file for repository metadata
///
/// Exactly one of these must be set for a Present repository.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DnfRepoSource {
    /// One or more base URLs for the repository
    Baseurl(Vec<String>),
    /// URL to a file containing mirror URLs
    Mirrorlist(String),
    /// URL to a metalink file
    Metalink(String),
}

/// Configuration for a DNF/YUM repository
///
/// Manages a repository section inside a `.repo` file in `/etc/yum.repos.d/`.
///
/// This enum uses a type-safe design where each variant represents a valid state:
///
/// - **`Present` variant**: Represents a repository that should exist on the system.
///   Contains all configuration fields needed to define the repository:
///   - `name`: Repository name (used as INI section header)
///   - `source`: **Required** - The repository source (Baseurl, Mirrorlist, or Metalink)
///   - `description`: Human-readable description
///   - `enabled`: Whether the repository is enabled (defaults to system default)
///   - `gpgcheck`: Whether to verify packages with GPG signatures
///   - `gpgkey`: URLs to GPG keys for package verification
///   - `file`: Custom filename for the .repo file (overrides `name`)
///   - `priority`: Repository priority (lower = higher priority)
///   - `sslverify`: Whether to verify SSL certificates
///   - `exclude`: Packages to exclude from this repository
///
/// - **`Absent` variant**: Represents a repository that should be removed from the system.
///   Only contains the fields needed to identify which repository to remove:
///   - `name`: Repository name (used to identify the section to remove)
///   - `file`: Optional custom filename if the repo file uses a different name
///
/// This design ensures type safety by making it impossible to:
/// - Create an Absent repository with configuration settings (they don't apply to non-existent repos)
/// - Create a Present repository without a source
/// - Specify multiple source types simultaneously
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
#[serde(untagged)]
pub enum DnfRepoBlockExpectedState {
    /// Repository should be present with full configuration
    Present {
        /// Repository name (used as INI section header)
        name: String,
        /// Repository source (mutually exclusive: Baseurl, Mirrorlist, or Metalink)
        source: DnfRepoSource,
        /// Human-readable description of the repository
        #[serde(default)]
        description: Option<String>,
        /// Whether the repository is enabled
        #[serde(default)]
        enabled: Option<bool>,
        /// Whether to verify packages with GPG signatures
        #[serde(default)]
        gpgcheck: Option<bool>,
        /// URLs to GPG keys for package verification
        #[serde(default)]
        gpgkey: Option<Vec<String>>,
        /// Custom filename for the .repo file (overrides using `name`)
        #[serde(default)]
        file: Option<String>,
        /// Repository priority (lower = higher priority)
        #[serde(default)]
        priority: Option<u32>,
        /// Whether to verify SSL certificates
        #[serde(default)]
        sslverify: Option<bool>,
        /// Packages to exclude from this repository
        #[serde(default)]
        exclude: Option<Vec<String>>,
    },
    /// Repository should be absent (removed)
    /// Only name and optional file are available - other settings don't make sense
    /// for a repository that should not exist
    Absent {
        /// Repository name (used to identify the repository to remove)
        name: String,
        /// Custom filename for the .repo file (overrides using `name`)
        #[serde(default)]
        file: Option<String>,
    },
}

impl Timeout for DnfRepoBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

impl DnfRepoBlockExpectedState {
    /// Get the repository name
    pub fn name(&self) -> &str {
        match self {
            DnfRepoBlockExpectedState::Present { name, .. } => name,
            DnfRepoBlockExpectedState::Absent { name, .. } => name,
        }
    }

    /// Get the repository filename (either custom or default to name)
    pub fn repo_filename(&self) -> String {
        match self {
            DnfRepoBlockExpectedState::Present { file, name, .. } => {
                file.as_deref().unwrap_or(name).to_string()
            }
            DnfRepoBlockExpectedState::Absent { file, name } => {
                file.as_deref().unwrap_or(name).to_string()
            }
        }
    }

    /// Get the source URLs for verification purposes (only available for Present variant)
    pub fn source_urls(&self) -> Option<Vec<String>> {
        match self {
            DnfRepoBlockExpectedState::Present { source, .. } => Some(match source {
                DnfRepoSource::Baseurl(urls) => urls.clone(),
                DnfRepoSource::Mirrorlist(url) => vec![url.clone()],
                DnfRepoSource::Metalink(url) => vec![url.clone()],
            }),
            DnfRepoBlockExpectedState::Absent { .. } => None,
        }
    }

    /// Check if this is a Present state
    pub fn is_present(&self) -> bool {
        matches!(self, DnfRepoBlockExpectedState::Present { .. })
    }

    /// Check if this is an Absent state
    pub fn is_absent(&self) -> bool {
        matches!(self, DnfRepoBlockExpectedState::Absent { .. })
    }

    /// Create a Present state configuration
    pub fn present(name: &str, source: DnfRepoSource) -> DnfRepoBlockExpectedState {
        DnfRepoBlockExpectedState::Present {
            name: name.to_string(),
            source,
            description: None,
            enabled: None,
            gpgcheck: None,
            gpgkey: None,
            file: None,
            priority: None,
            sslverify: None,
            exclude: None,
        }
    }

    /// Create an Absent state configuration
    pub fn absent(name: &str) -> DnfRepoBlockExpectedState {
        DnfRepoBlockExpectedState::Absent {
            name: name.to_string(),
            file: None,
        }
    }

    /// Validate the configuration
    pub fn check(&self) -> Result<(), RegentError> {
        match self {
            DnfRepoBlockExpectedState::Present { name, .. } => {
                if name.is_empty() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Repo name cannot be empty.".to_string(),
                    ));
                }
                Ok(())
            }
            DnfRepoBlockExpectedState::Absent { name, .. } => {
                if name.is_empty() {
                    return Err(RegentError::IncoherentExpectedState(
                        "Repo name cannot be empty.".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Check host compatibility
    pub fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Fedora,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but DNF/YUM repositories are only supported on Fedora/CentOS/RHEL Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl Check for DnfRepoBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        DnfRepoBlockExpectedState::check(self)
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        DnfRepoBlockExpectedState::check_host_compatibility(self, host_properties)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DnfRepoBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Fedora/CentOS/RHEL Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let file_name = self.repo_filename();
        let file_path = format!("/etc/yum.repos.d/{}.repo", file_name);

        let current_content = match read_file(host_handler, &file_path).await {
            Ok(c) => c,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        match self {
            DnfRepoBlockExpectedState::Absent { name, .. } => {
                let section_exists = current_content
                    .as_deref()
                    .and_then(|c| extract_section(c, name))
                    .is_some();

                if !section_exists {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }

                Ok(AttributeComplianceAssessment::NonCompliant(
                    RemediationsList::from(vec![Remediation::DnfRepo(DnfRepoApiCall::from(
                        DnfRepoModuleInternalApiCall::RemoveSection {
                            file_name,
                            repo_name: name.clone(),
                        },
                        privilege.clone(),
                    ))])?,
                ))
            }
            DnfRepoBlockExpectedState::Present {
                name,
                source,
                description,
                enabled,
                gpgcheck,
                gpgkey,
                ..
            } => {
                let expected_section =
                    build_section_content(name, source, description, enabled, gpgcheck, gpgkey);

                let already_correct = current_content
                    .as_deref()
                    .and_then(|c| extract_section(c, name))
                    .map(|s| s.trim() == expected_section.trim())
                    .unwrap_or(false);

                if already_correct {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }

                // Enhanced verification: explicitly check critical properties like source URLs
                if let Some(ref current) = current_content {
                    if let Some(current_section) = extract_section(current, name) {
                        let current_sources = extract_source_urls_from_section(&current_section);
                        let expected_sources = extract_source_urls_from_section(&expected_section);

                        if let (Some(current_sources), Some(expected_sources)) =
                            (current_sources, expected_sources)
                        {
                            if current_sources != expected_sources {
                                return Ok(AttributeComplianceAssessment::NonCompliant(
                                    RemediationsList::from(vec![Remediation::DnfRepo(
                                        DnfRepoApiCall::from(
                                            DnfRepoModuleInternalApiCall::UpsertSection {
                                                file_name,
                                                repo_name: name.clone(),
                                                section_content: expected_section,
                                            },
                                            privilege.clone(),
                                        ),
                                    )])?,
                                ));
                            }
                        }
                    }
                }

                Ok(AttributeComplianceAssessment::NonCompliant(
                    RemediationsList::from(vec![Remediation::DnfRepo(DnfRepoApiCall::from(
                        DnfRepoModuleInternalApiCall::UpsertSection {
                            file_name,
                            repo_name: name.clone(),
                            section_content: expected_section,
                        },
                        privilege.clone(),
                    ))])?,
                ))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DnfRepoModuleInternalApiCall {
    UpsertSection {
        file_name: String,
        repo_name: String,
        section_content: String,
    },
    RemoveSection {
        file_name: String,
        repo_name: String,
    },
}

impl std::fmt::Display for DnfRepoModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnfRepoModuleInternalApiCall::UpsertSection {
                repo_name,
                file_name,
                ..
            } => {
                write!(
                    f,
                    "upsert repo [{}] in /etc/yum.repos.d/{}.repo",
                    repo_name, file_name
                )
            }
            DnfRepoModuleInternalApiCall::RemoveSection {
                repo_name,
                file_name,
            } => {
                write!(
                    f,
                    "remove repo [{}] from /etc/yum.repos.d/{}.repo",
                    repo_name, file_name
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnfRepoApiCall {
    pub api_call: DnfRepoModuleInternalApiCall,
    privilege: Privilege,
}

impl DnfRepoApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            DnfRepoModuleInternalApiCall::UpsertSection {
                repo_name,
                file_name,
                ..
            } => {
                format!(
                    "Upsert repo [{}] in /etc/yum.repos.d/{}.repo",
                    repo_name, file_name
                )
            }
            DnfRepoModuleInternalApiCall::RemoveSection {
                repo_name,
                file_name,
            } => {
                format!(
                    "Remove repo [{}] from /etc/yum.repos.d/{}.repo",
                    repo_name, file_name
                )
            }
        }
    }

    fn from(api_call: DnfRepoModuleInternalApiCall, privilege: Privilege) -> DnfRepoApiCall {
        DnfRepoApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for DnfRepoApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(LinuxSpecifics {
                linux_flavor: LinuxFlavor::Fedora,
                ..
            }) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but DNF/YUM repositories are only supported on Fedora/CentOS/RHEL Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for DnfRepoApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Fedora/CentOS/RHEL Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let cmd = match &self.api_call {
            DnfRepoModuleInternalApiCall::UpsertSection {
                file_name,
                repo_name,
                section_content,
            } => build_upsert_cmd(file_name, repo_name, section_content),
            DnfRepoModuleInternalApiCall::RemoveSection {
                file_name,
                repo_name,
            } => build_remove_cmd(file_name, repo_name),
        };

        let cmd_result = host_handler
            .run_command(cmd.as_str(), &self.privilege)
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

fn build_section_content(
    name: &str,
    source: &DnfRepoSource,
    description: &Option<String>,
    enabled: &Option<bool>,
    gpgcheck: &Option<bool>,
    gpgkey: &Option<Vec<String>>,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("[{}]", name));

    if let Some(description) = description {
        lines.push(format!("name={}", description));
    }

    match source {
        DnfRepoSource::Baseurl(urls) => {
            lines.push(format!("baseurl={}", urls.join("\n        ")));
        }
        DnfRepoSource::Mirrorlist(url) => {
            lines.push(format!("mirrorlist={}", url));
        }
        DnfRepoSource::Metalink(url) => {
            lines.push(format!("metalink={}", url));
        }
    }

    if let Some(enabled) = enabled {
        lines.push(format!("enabled={}", if *enabled { 1 } else { 0 }));
    }
    if let Some(gpgcheck) = gpgcheck {
        lines.push(format!("gpgcheck={}", if *gpgcheck { 1 } else { 0 }));
    }
    if let Some(gpgkey) = gpgkey {
        lines.push(format!("gpgkey={}", gpgkey.join("\n        ")));
    }

    lines.join("\n") + "\n"
}

fn extract_section(content: &str, name: &str) -> Option<String> {
    let header = format!("[{}]", name);
    let mut in_section = false;
    let mut section_lines: Vec<&str> = Vec::new();

    for line in content.lines() {
        if line.trim() == header {
            in_section = true;
            section_lines.push(line);
            continue;
        }
        if in_section {
            if line.starts_with('[') {
                break;
            }
            section_lines.push(line);
        }
    }

    if section_lines.is_empty() {
        None
    } else {
        Some(section_lines.join("\n") + "\n")
    }
}

fn escape_for_printf(content: &str) -> String {
    content
        .replace('\\', "\\\\")
        .replace('%', "%%")
        .replace('\n', "\\n")
}

/// Extract source URLs from DNF/YUM repository section content for source verification.
/// This ensures that repository baseurl, mirrorlist, and metalink are explicitly checked during assessment.
fn extract_source_urls_from_section(content: &str) -> Option<Vec<String>> {
    let mut urls: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("baseurl=") {
            // Extract URL(s) from baseurl
            let baseurl_part = trimmed.split('=').nth(1).map(|s| s.trim());
            if let Some(baseurl_str) = baseurl_part {
                // baseurl can contain multiple URLs
                for url in baseurl_str.split_whitespace() {
                    urls.push(url.to_string());
                }
            }
        } else if trimmed.starts_with("mirrorlist=") {
            // Extract mirrorlist URL
            let mirrorlist_part = trimmed.split('=').nth(1).map(|s| s.trim());
            if let Some(mirrorlist_url) = mirrorlist_part {
                urls.push(mirrorlist_url.to_string());
            }
        } else if trimmed.starts_with("metalink=") {
            // Extract metalink URL
            let metalink_part = trimmed.split('=').nth(1).map(|s| s.trim());
            if let Some(metalink_url) = metalink_part {
                urls.push(metalink_url.to_string());
            }
        }
    }

    if urls.is_empty() { None } else { Some(urls) }
}

fn build_upsert_cmd(file_name: &str, repo_name: &str, section: &str) -> String {
    let escaped = escape_for_printf(section);
    let path = format!("/etc/yum.repos.d/{}.repo", file_name);
    let tmp = format!("/tmp/.regent_{}_tmp", file_name);
    format!(
        "{{ awk '/^\\[{n}\\]$/{{p=1}} /^\\[/ && !/^\\[{n}\\]$/{{p=0}} !p' {path} 2>/dev/null; printf '{esc}'; }} > {tmp} && mv {tmp} {path}",
        n = repo_name,
        path = path,
        esc = escaped,
        tmp = tmp,
    )
}

fn build_remove_cmd(file_name: &str, repo_name: &str) -> String {
    let path = format!("/etc/yum.repos.d/{}.repo", file_name);
    let tmp = format!("/tmp/.regent_{}_tmp", file_name);
    format!(
        "{{ awk '/^\\[{n}\\]$/{{p=1}} /^\\[/ && !/^\\[{n}\\]$/{{p=0}} !p' {path} 2>/dev/null; }} > {tmp} && if [ -s {tmp} ]; then mv {tmp} {path}; else rm -f {tmp} {path}; fi",
        n = repo_name,
        path = path,
        tmp = tmp,
    )
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
                Ok(None)
            }
        }
        Err(e) => Err(format!("Failed to read {}: {:?}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_dnf_repo_present_from_yaml() {
        let raw = "---
- Present:
    Name: docker-ce-stable
    Description: Docker CE Stable
    Source: !Baseurl
      - https://download.docker.com/linux/centos/$releasever/$basearch/stable
    Gpgcheck: true
    Gpgkey:
      - https://download.docker.com/linux/centos/gpg
    Enabled: true

- Absent:
    Name: epel
        ";
        let attrs: Vec<DnfRepoBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(attrs.len(), 2);
        match &attrs[0] {
            DnfRepoBlockExpectedState::Present { name, .. } => {
                assert_eq!(name, "docker-ce-stable");
            }
            _ => panic!("Expected Present variant"),
        }
        match &attrs[1] {
            DnfRepoBlockExpectedState::Absent { name, .. } => {
                assert_eq!(name, "epel");
            }
            _ => panic!("Expected Absent variant"),
        }
    }

    #[test]
    fn parsing_dnf_repo_absent_from_yaml() {
        let raw = "---
- Absent:
    Name: epel
    File: custom-repo
        ";
        let attrs: Vec<DnfRepoBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
        assert_eq!(attrs.len(), 1);
        match &attrs[0] {
            DnfRepoBlockExpectedState::Absent { name, file } => {
                assert_eq!(name, "epel");
                assert_eq!(file, &Some("custom-repo".to_string()));
            }
            _ => panic!("Expected Absent variant"),
        }
    }

    #[test]
    fn check_rejects_empty_name_present() {
        let result = DnfRepoBlockExpectedState::Present {
            name: "".to_string(),
            source: DnfRepoSource::Baseurl(vec!["http://example.com".to_string()]),
            description: None,
            enabled: None,
            gpgcheck: None,
            gpgkey: None,
            file: None,
            priority: None,
            sslverify: None,
            exclude: None,
        }
        .check();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_empty_name_absent() {
        let result = DnfRepoBlockExpectedState::Absent {
            name: "".to_string(),
            file: None,
        }
        .check();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_absent() {
        let result = DnfRepoBlockExpectedState::Absent {
            name: "myrepo".to_string(),
            file: None,
        }
        .check();
        assert!(result.is_ok());
    }

    #[test]
    fn build_section_content_basic() {
        let source = DnfRepoSource::Baseurl(vec![
            "https://download.docker.com/linux/centos/7/$basearch/stable".to_string(),
        ]);
        let content = build_section_content(
            "docker-ce",
            &source,
            &Some("Docker CE".to_string()),
            &Some(true),
            &Some(true),
            &None,
        );
        assert!(content.starts_with("[docker-ce]\n"));
        assert!(content.contains("name=Docker CE"));
        assert!(content.contains("gpgcheck=1"));
        assert!(content.contains("enabled=1"));
    }

    #[test]
    fn build_section_content_with_mirrorlist() {
        let source = DnfRepoSource::Mirrorlist(
            "http://mirrors.fedoraproject.org/mirrorlist?repo=epel-7&arch=x86_64".to_string(),
        );
        let content = build_section_content("epel", &source, &None, &None, &None, &None);
        assert!(content.starts_with("[epel]\n"));
        assert!(content.contains(
            "mirrorlist=http://mirrors.fedoraproject.org/mirrorlist?repo=epel-7&arch=x86_64"
        ));
    }

    #[test]
    fn build_section_content_with_metalink() {
        let source = DnfRepoSource::Metalink(
            "https://mirrors.fedoraproject.org/metalink?repo=fedora-35&arch=x86_64".to_string(),
        );
        let content = build_section_content("fedora", &source, &None, &None, &None, &None);
        assert!(content.starts_with("[fedora]\n"));
        assert!(content.contains(
            "metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-35&arch=x86_64"
        ));
    }

    #[test]
    fn extract_section_finds_correct_section() {
        let content = "[other]\nbaseurl=http://other.com\n[myrepo]\nbaseurl=http://example.com\nenabled=1\n[another]\nbaseurl=http://another.com\n";
        let section = extract_section(content, "myrepo").unwrap();
        assert!(section.contains("[myrepo]"));
        assert!(section.contains("baseurl=http://example.com"));
        assert!(!section.contains("[other]"));
        assert!(!section.contains("[another]"));
    }

    #[test]
    fn extract_section_returns_none_when_absent() {
        let content = "[other]\nbaseurl=http://other.com\n";
        assert!(extract_section(content, "myrepo").is_none());
    }

    #[test]
    fn repo_filename_defaults_to_name_present() {
        let block = DnfRepoBlockExpectedState::present(
            "myrepo",
            DnfRepoSource::Baseurl(vec!["http://x.com".to_string()]),
        );
        assert_eq!(block.repo_filename(), "myrepo");
    }

    #[test]
    fn repo_filename_uses_file_field_when_set_present() {
        let block = DnfRepoBlockExpectedState::Present {
            name: "myrepo".to_string(),
            source: DnfRepoSource::Baseurl(vec!["http://x.com".to_string()]),
            description: None,
            enabled: None,
            gpgcheck: None,
            gpgkey: None,
            file: Some("custom-file".to_string()),
            priority: None,
            sslverify: None,
            exclude: None,
        };
        assert_eq!(block.repo_filename(), "custom-file");
    }

    #[test]
    fn repo_filename_uses_file_field_when_set_absent() {
        let block = DnfRepoBlockExpectedState::Absent {
            name: "myrepo".to_string(),
            file: Some("custom-file".to_string()),
        };
        assert_eq!(block.repo_filename(), "custom-file");
    }

    #[test]
    fn source_urls_returns_none_for_absent() {
        let block = DnfRepoBlockExpectedState::absent("myrepo");
        let urls = block.source_urls();
        assert_eq!(urls, None);
    }

    #[test]
    fn is_present_and_is_absent() {
        let present = DnfRepoBlockExpectedState::present(
            "test",
            DnfRepoSource::Baseurl(vec!["http://x.com".to_string()]),
        );
        assert!(present.is_present());
        assert!(!present.is_absent());

        let absent = DnfRepoBlockExpectedState::absent("test");
        assert!(!absent.is_present());
        assert!(absent.is_absent());
    }

    #[test]
    fn absent_variant_only_has_name_and_file() {
        // The Absent variant should only have name and file fields
        let absent = DnfRepoBlockExpectedState::Absent {
            name: "test".to_string(),
            file: None,
        };

        match absent {
            DnfRepoBlockExpectedState::Absent { name, file } => {
                assert_eq!(name, "test");
                assert_eq!(file, None);
            }
            _ => panic!("Expected Absent variant"),
        }
    }
}
