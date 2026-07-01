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
pub enum AptRepoExpectedState {
    Present,
    Absent,
}

/// Repository type field for deb822 format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AptRepoType {
    Deb,
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

/// Manages an APT repository source file in /etc/apt/sources.list.d/.
///
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
    filename: String,
    state: Option<AptRepoExpectedState>,
    update_cache: Option<bool>,
    // Legacy one-liner format → writes to <filename>.list
    repo: Option<String>,
    // Deb822 fields → writes to <filename>.sources
    types: Option<Vec<AptRepoType>>,
    uris: Option<Vec<String>>,
    suites: Option<Vec<String>>,
    components: Option<Vec<String>>,
    signed_by: Option<String>,
    enabled: Option<bool>,
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
}

impl<Handler: HostHandler> AssessCompliance<Handler> for AptRepoBlockExpectedState {
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
            .unwrap_or(&AptRepoExpectedState::Present);
        let is_legacy = self.repo.is_some();
        let file_path = apt_repo_file_path(&self.filename, is_legacy);

        let current_content = match read_file(host_handler, &file_path) {
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
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
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

        let cmd_result = host_handler.run_command(cmd.as_str(), privilege).unwrap();

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

fn read_file<Handler: HostHandler>(
    host_handler: &mut Handler,
    path: &str,
) -> Result<Option<String>, String> {
    match host_handler.run_command(&format!("cat {}", path), &Privilege::None) {
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
