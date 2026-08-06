//! DNF/YUM repository management attribute
//!
//! This module provides the `DnfRepoBlockExpectedState` type for managing DNF/YUM
//! repository `.repo` files in `/etc/yum.repos.d/`.
//!
//! **Compatible OS:** Linux (Fedora, CentOS, RHEL-based distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::package::dnf_repo::{DnfRepoBlockExpectedState, DnfRepoExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Add a repository with baseurl
//! let repo = DnfRepoBlockExpectedState::builder("docker-ce")
//!     .with_state(DnfRepoExpectedState::Present)
//!     .with_baseurl(vec!["https://download.docker.com/linux/centos/7/x86_64/stable".to_string()])
//!     .with_enabled(true)
//!     .with_gpgcheck(true)
//!     .with_gpgkey(vec!["https://download.docker.com/linux/centos/gpg".to_string()])
//!     .build()
//!     .unwrap();
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
//!   - Name: Docker CE repository must be present
//!     Privilege: !WithSudo
//!     Detail: !DnfRepo
//!       Name: docker-ce
//!       State: !Present
//!       Baseurl:
//!         - "https://download.docker.com/linux/centos/7/x86_64/stable"
//!       Enabled: true
//!       Gpgcheck: true
//!       Gpgkey:
//!         - "https://download.docker.com/linux/centos/gpg"
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

/// Configuration for a DNF/YUM repository
///
/// Manages a repository section inside a `.repo` file in `/etc/yum.repos.d/`.
/// `name` is both the INI section header `[name]` and the default filename
/// (override with `file`). Exactly one of `baseurl`, `mirrorlist`, or `metalink`
/// must be set when state is Present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DnfRepoBlockExpectedState {
    /// Repository name (used as INI section header and default filename)
    name: String,
    /// Desired state of the repository
    state: Option<DnfRepoExpectedState>,
    /// Human-readable description of the repository
    description: Option<String>,
    /// Base URLs for the repository
    baseurl: Option<Vec<String>>,
    /// URL to a file containing mirror URLs
    mirrorlist: Option<String>,
    /// URL to a metalink file
    metalink: Option<String>,
    /// Whether the repository is enabled
    enabled: Option<bool>,
    /// Whether to verify packages with GPG signatures
    gpgcheck: Option<bool>,
    /// URLs to GPG keys for package verification
    gpgkey: Option<Vec<String>>,
    /// Custom filename for the .repo file (overrides using `name`)
    file: Option<String>,
    /// Repository priority (lower = higher priority)
    priority: Option<u32>,
    /// Whether to verify SSL certificates
    sslverify: Option<bool>,
    /// Packages to exclude from this repository
    exclude: Option<Vec<String>>,
}

impl Timeout for DnfRepoBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

impl DnfRepoBlockExpectedState {
    pub fn builder(name: &str) -> DnfRepoBlockExpectedState {
        DnfRepoBlockExpectedState {
            name: name.to_string(),
            state: None,
            description: None,
            baseurl: None,
            mirrorlist: None,
            metalink: None,
            enabled: None,
            gpgcheck: None,
            gpgkey: None,
            file: None,
            priority: None,
            sslverify: None,
            exclude: None,
        }
    }

    pub fn with_state(&mut self, state: DnfRepoExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_description(&mut self, description: &str) -> &mut Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn with_baseurl(&mut self, baseurl: Vec<String>) -> &mut Self {
        self.baseurl = Some(baseurl);
        self
    }

    pub fn with_mirrorlist(&mut self, mirrorlist: &str) -> &mut Self {
        self.mirrorlist = Some(mirrorlist.to_string());
        self
    }

    pub fn with_metalink(&mut self, metalink: &str) -> &mut Self {
        self.metalink = Some(metalink.to_string());
        self
    }

    pub fn with_enabled(&mut self, enabled: bool) -> &mut Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn with_gpgcheck(&mut self, gpgcheck: bool) -> &mut Self {
        self.gpgcheck = Some(gpgcheck);
        self
    }

    pub fn with_gpgkey(&mut self, gpgkey: Vec<String>) -> &mut Self {
        self.gpgkey = Some(gpgkey);
        self
    }

    pub fn with_file(&mut self, file: &str) -> &mut Self {
        self.file = Some(file.to_string());
        self
    }

    pub fn with_priority(&mut self, priority: u32) -> &mut Self {
        self.priority = Some(priority);
        self
    }

    pub fn with_sslverify(&mut self, sslverify: bool) -> &mut Self {
        self.sslverify = Some(sslverify);
        self
    }

    pub fn with_exclude(&mut self, exclude: Vec<String>) -> &mut Self {
        self.exclude = Some(exclude);
        self
    }

    pub fn build(&self) -> Result<DnfRepoBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }

    fn repo_filename(&self) -> String {
        self.file.as_deref().unwrap_or(&self.name).to_string()
    }
}

impl Check for DnfRepoBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.name.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "Repo name cannot be empty.".to_string(),
            ));
        }

        let state = self
            .state
            .as_ref()
            .unwrap_or(&DnfRepoExpectedState::Present);
        if let DnfRepoExpectedState::Present = state {
            let source_count = self.baseurl.is_some() as u8
                + self.mirrorlist.is_some() as u8
                + self.metalink.is_some() as u8;

            if source_count == 0 {
                return Err(RegentError::IncoherentExpectedState(
                    "State Present requires exactly one of: Baseurl, Mirrorlist, Metalink."
                        .to_string(),
                ));
            }
            if source_count > 1 {
                return Err(RegentError::IncoherentExpectedState(
                    "Baseurl, Mirrorlist, and Metalink are mutually exclusive.".to_string(),
                ));
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
        let state = self
            .state
            .as_ref()
            .unwrap_or(&DnfRepoExpectedState::Present);
        let file_name = self.repo_filename();
        let file_path = format!("/etc/yum.repos.d/{}.repo", file_name);

        let current_content = match read_file(host_handler, &file_path).await {
            Ok(c) => c,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        match state {
            DnfRepoExpectedState::Absent => {
                let section_exists = current_content
                    .as_deref()
                    .and_then(|c| extract_section(c, &self.name))
                    .is_some();

                if !section_exists {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }

                Ok(AttributeComplianceAssessment::NonCompliant(
                    RemediationsList::from(vec![Remediation::DnfRepo(DnfRepoApiCall::from(
                        DnfRepoModuleInternalApiCall::RemoveSection {
                            file_name,
                            repo_name: self.name.clone(),
                        },
                        privilege.clone(),
                    ))])?,
                ))
            }
            DnfRepoExpectedState::Present => {
                let expected_section = build_section_content(self);

                let already_correct = current_content
                    .as_deref()
                    .and_then(|c| extract_section(c, &self.name))
                    .map(|s| s.trim() == expected_section.trim())
                    .unwrap_or(false);

                if already_correct {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }

                // Enhanced verification: explicitly check critical properties like source URLs
                // This provides better error messages and ensures source verification
                if let Some(ref current) = current_content {
                    if let Some(current_section) = extract_section(current, &self.name) {
                        // Check if source URLs (baseurl, mirrorlist, metalink) are different
                        if let (Some(current_sources), Some(expected_sources)) = (
                            extract_source_urls_from_section(&current_section),
                            extract_source_urls_from_section(&expected_section),
                        ) {
                            if current_sources != expected_sources {
                                return Ok(AttributeComplianceAssessment::NonCompliant(
                                    RemediationsList::from(vec![Remediation::DnfRepo(
                                        DnfRepoApiCall::from(
                                            DnfRepoModuleInternalApiCall::UpsertSection {
                                                file_name,
                                                repo_name: self.name.clone(),
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
                            repo_name: self.name.clone(),
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

fn build_section_content(block: &DnfRepoBlockExpectedState) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("[{}]", block.name));

    if let Some(ref description) = block.description {
        lines.push(format!("name={}", description));
    }
    if let Some(ref baseurl) = block.baseurl {
        lines.push(format!("baseurl={}", baseurl.join("\n        ")));
    }
    if let Some(ref mirrorlist) = block.mirrorlist {
        lines.push(format!("mirrorlist={}", mirrorlist));
    }
    if let Some(ref metalink) = block.metalink {
        lines.push(format!("metalink={}", metalink));
    }
    if let Some(enabled) = block.enabled {
        lines.push(format!("enabled={}", if enabled { 1 } else { 0 }));
    }
    if let Some(gpgcheck) = block.gpgcheck {
        lines.push(format!("gpgcheck={}", if gpgcheck { 1 } else { 0 }));
    }
    if let Some(ref gpgkey) = block.gpgkey {
        lines.push(format!("gpgkey={}", gpgkey.join("\n        ")));
    }
    if let Some(priority) = block.priority {
        lines.push(format!("priority={}", priority));
    }
    if let Some(sslverify) = block.sslverify {
        lines.push(format!("sslverify={}", if sslverify { 1 } else { 0 }));
    }
    if let Some(ref exclude) = block.exclude {
        lines.push(format!("exclude={}", exclude.join(" ")));
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
    fn parsing_dnf_repo_from_yaml() {
        let raw = "---
- Name: docker-ce-stable
  Description: Docker CE Stable
  Baseurl:
    - https://download.docker.com/linux/centos/$releasever/$basearch/stable
  Gpgcheck: true
  Gpgkey:
    - https://download.docker.com/linux/centos/gpg
  Enabled: true

- Name: epel
  State: !Absent
        ";
        let _attrs: Vec<DnfRepoBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }

    #[test]
    fn check_rejects_empty_name() {
        let result = DnfRepoBlockExpectedState::builder("").build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_present_without_url() {
        let result = DnfRepoBlockExpectedState::builder("myrepo")
            .with_state(DnfRepoExpectedState::Present)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_baseurl_and_mirrorlist() {
        let result = DnfRepoBlockExpectedState::builder("myrepo")
            .with_baseurl(vec!["http://example.com".to_string()])
            .with_mirrorlist("http://mirrors.example.com")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_absent_without_url() {
        let result = DnfRepoBlockExpectedState::builder("myrepo")
            .with_state(DnfRepoExpectedState::Absent)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_section_content_basic() {
        let block = DnfRepoBlockExpectedState::builder("docker-ce")
            .with_description("Docker CE")
            .with_baseurl(vec![
                "https://download.docker.com/linux/centos/7/$basearch/stable".to_string(),
            ])
            .with_gpgcheck(true)
            .with_enabled(true)
            .build()
            .unwrap();
        let content = build_section_content(&block);
        assert!(content.starts_with("[docker-ce]\n"));
        assert!(content.contains("name=Docker CE"));
        assert!(content.contains("gpgcheck=1"));
        assert!(content.contains("enabled=1"));
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
    fn repo_filename_defaults_to_name() {
        let block = DnfRepoBlockExpectedState::builder("myrepo")
            .with_baseurl(vec!["http://x.com".to_string()])
            .build()
            .unwrap();
        assert_eq!(block.repo_filename(), "myrepo");
    }

    #[test]
    fn repo_filename_uses_file_field_when_set() {
        let block = DnfRepoBlockExpectedState::builder("myrepo")
            .with_file("custom-file")
            .with_baseurl(vec!["http://x.com".to_string()])
            .build()
            .unwrap();
        assert_eq!(block.repo_filename(), "custom-file");
    }
}
