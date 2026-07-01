use crate::error::RegentError;
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::managed_host::{AssessCompliance, ReachCompliance, Timeout};
use crate::hosts::properties::HostProperties;
use crate::secrets::SecretProvidersPool;
use crate::state::Check;
use crate::state::attribute::HostHandler;
use crate::state::attribute::Privilege;
use crate::state::attribute::Remediation;
use crate::state::compliance::AttributeComplianceAssessment;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DnfRepoExpectedState {
    Present,
    Absent,
}

/// Manages a DNF/YUM repository section inside a `.repo` file in /etc/yum.repos.d/.
///
/// `name` is both the INI section header `[name]` and the default filename
/// (override with `file`). Exactly one of `baseurl`, `mirrorlist`, or `metalink`
/// must be set when state is Present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct DnfRepoBlockExpectedState {
    name: String,
    state: Option<DnfRepoExpectedState>,
    description: Option<String>,
    baseurl: Option<Vec<String>>,
    mirrorlist: Option<String>,
    metalink: Option<String>,
    enabled: Option<bool>,
    gpgcheck: Option<bool>,
    gpgkey: Option<Vec<String>>,
    file: Option<String>,
    priority: Option<u32>,
    sslverify: Option<bool>,
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
}

impl<Handler: HostHandler> AssessCompliance<Handler> for DnfRepoBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        let state = self
            .state
            .as_ref()
            .unwrap_or(&DnfRepoExpectedState::Present);
        let file_name = self.repo_filename();
        let file_path = format!("/etc/yum.repos.d/{}.repo", file_name);

        let current_content = match read_file(host_handler, &file_path) {
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

                Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::DnfRepo(DnfRepoApiCall::from(
                        DnfRepoModuleInternalApiCall::RemoveSection {
                            file_name,
                            repo_name: self.name.clone(),
                        },
                        privilege.clone(),
                    )),
                ]))
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

                Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::DnfRepo(DnfRepoApiCall::from(
                        DnfRepoModuleInternalApiCall::UpsertSection {
                            file_name,
                            repo_name: self.name.clone(),
                            section_content: expected_section,
                        },
                        privilege.clone(),
                    )),
                ]))
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

impl<Handler: HostHandler> ReachCompliance<Handler> for DnfRepoApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
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

fn read_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
) -> Result<Option<String>, String> {
    match host_handler.run_command(&format!("cat {}", path), &Privilege::None) {
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
