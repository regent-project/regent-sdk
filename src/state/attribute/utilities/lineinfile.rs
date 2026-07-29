//! Line in file management attribute
//!
//! This module provides the `LineInFileBlockExpectedState` type for ensuring specific lines
//! are present or absent in files. Useful for configuration files, environment files, etc.
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::utilities::lineinfile::{LineInFileBlockExpectedState, LineExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Ensure a line exists in /etc/environment
//! let env_line = LineInFileBlockExpectedState::builder("/etc/environment")
//!     .with_state(LineExpectedState::Present)
//!     .with_line("KEY=value")
//!     .with_create(true)
//!     .build()
//!     .unwrap();
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::lineinfile(env_line, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Detail: !LineInFile
//!       FilePath: /etc/environment
//!       State: !Present
//!       Line: "KEY=value"
//!       Create: true
//!       Privilege: !WithSudo
//! ```

use std::time::Duration;

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
use crate::state::expected_state::Parameter;
use serde::{Deserialize, Serialize};

/// Desired state of a line in a file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LineExpectedState {
    /// Line should exist in the file
    Present,
    /// Line should not exist in the file
    Absent,
}

/// Configuration for managing a line in a file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct LineInFileBlockExpectedState {
    /// Absolute path to the managed file.
    file_path: String,
    /// Line to ensure is present or absent. Default state: Present.
    state: Option<LineExpectedState>,
    /// The exact line to insert, or the replacement when regexp/search_string matches.
    line: Option<Parameter<String>>,
    /// Regex that selects the line(s) to replace (last match) or delete. Mutually exclusive with SearchString.
    regexp: Option<String>,
    /// Fixed-string alternative to Regexp for matching whole lines. Mutually exclusive with Regexp.
    search_string: Option<String>,
    /// Insert the line after the last line matching this regex, or after "EOF" / "BOF". Mutually exclusive with InsertBefore.
    insert_after: Option<String>,
    /// Insert the line before the last line matching this regex, or before "BOF". Mutually exclusive with InsertAfter.
    insert_before: Option<String>,
    /// Use regexp capture groups (\\1, \\2, …) in Line as sed replacement. Requires Regexp.
    backrefs: Option<bool>,
    /// When using InsertAfter/InsertBefore, match the first occurrence instead of the last.
    firstmatch: Option<bool>,
    /// Create the file if it does not exist (default: false).
    create: Option<bool>,
}

impl LineInFileBlockExpectedState {
    pub fn builder(file_path: &str) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: None,
            line: None,
            regexp: None,
            search_string: None,
            insert_after: None,
            insert_before: None,
            backrefs: None,
            firstmatch: None,
            create: None,
        }
    }

    pub fn with_state(&mut self, state: LineExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_line(&mut self, line: &str) -> &mut Self {
        self.line = Some(Parameter::Clear(line.to_string()));
        self
    }

    pub fn with_regexp(&mut self, regexp: &str) -> &mut Self {
        self.regexp = Some(regexp.to_string());
        self
    }

    pub fn with_search_string(&mut self, s: &str) -> &mut Self {
        self.search_string = Some(s.to_string());
        self
    }

    pub fn with_insert_after(&mut self, pattern: &str) -> &mut Self {
        self.insert_after = Some(pattern.to_string());
        self
    }

    pub fn with_insert_before(&mut self, pattern: &str) -> &mut Self {
        self.insert_before = Some(pattern.to_string());
        self
    }

    pub fn with_backrefs(&mut self, backrefs: bool) -> &mut Self {
        self.backrefs = Some(backrefs);
        self
    }

    pub fn with_firstmatch(&mut self, firstmatch: bool) -> &mut Self {
        self.firstmatch = Some(firstmatch);
        self
    }

    pub fn with_create(&mut self, create: bool) -> &mut Self {
        self.create = Some(create);
        self
    }

    pub fn build(&self) -> Result<LineInFileBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for LineInFileBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.file_path.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "FilePath cannot be empty.".to_string(),
            ));
        }
        if self.regexp.is_some() && self.search_string.is_some() {
            return Err(RegentError::IncoherentExpectedState(
                "Regexp and SearchString are mutually exclusive.".to_string(),
            ));
        }
        if self.insert_after.is_some() && self.insert_before.is_some() {
            return Err(RegentError::IncoherentExpectedState(
                "InsertAfter and InsertBefore are mutually exclusive.".to_string(),
            ));
        }
        if self.backrefs.unwrap_or(false) && self.regexp.is_none() {
            return Err(RegentError::IncoherentExpectedState(
                "Backrefs requires Regexp.".to_string(),
            ));
        }
        if self.line.is_none() && self.regexp.is_none() && self.search_string.is_none() {
            return Err(RegentError::IncoherentExpectedState(
                "At least one of Line, Regexp, or SearchString must be set.".to_string(),
            ));
        }
        Ok(())
    }
}

impl Timeout for LineInFileBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for LineInFileBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        if !host_handler
            .is_this_command_available("sed", privilege)
            .await
            .unwrap()
        {
            return Err(RegentError::FailedDryRunEvaluation(
                "sed is not available on this host".to_string(),
            ));
        }

        let state = self.state.as_ref().unwrap_or(&LineExpectedState::Present);
        let backrefs = self.backrefs.unwrap_or(false);
        let firstmatch = self.firstmatch.unwrap_or(false);

        let file_exists = host_handler
            .run_command(&format!("test -f {}", self.file_path), &Privilege::None)
            .await
            .unwrap()
            .return_code
            == 0;

        if !file_exists {
            if self.create.unwrap_or(false) {
                if let LineExpectedState::Absent = state {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::LineInFile(LineInFileApiCall {
                        file_path: self.file_path.clone(),
                        line_content: self.line.clone(),
                        regexp: None,
                        api_call: LineInFileModuleInternalApiCall::CreateFile,
                        privilege: privilege.clone(),
                    }),
                ]));
            }
            return Err(RegentError::FailedDryRunEvaluation(format!(
                "{}: file not found (set Create: true to create it)",
                self.file_path
            )));
        }

        let line_content: Option<String> = match &self.line {
            Some(param) => Some(
                param
                    .clone()
                    .inner_raw(optional_secret_provider)
                    .await
                    .unwrap(),
            ),
            None => None,
        };

        match state {
            LineExpectedState::Absent => {
                assess_absent(self, host_handler, privilege, &line_content).await
            }
            LineExpectedState::Present => {
                assess_present(
                    self,
                    host_handler,
                    privilege,
                    &line_content,
                    backrefs,
                    firstmatch,
                )
                .await
            }
        }
    }
}

async fn assess_absent<Handler: HostHandler>(
    block: &LineInFileBlockExpectedState,
    host_handler: &mut Handler,
    privilege: &Privilege,
    line_content: &Option<String>,
) -> Result<AttributeComplianceAssessment, RegentError> {
    if let Some(ref regexp) = block.regexp {
        let matches = grep_lines(host_handler, regexp, &block.file_path, false).await;
        if matches.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        return Ok(AttributeComplianceAssessment::NonCompliant(vec![
            Remediation::LineInFile(LineInFileApiCall {
                file_path: block.file_path.clone(),
                line_content: None,
                regexp: None,
                api_call: LineInFileModuleInternalApiCall::DeleteByRegexp(regexp.clone()),
                privilege: privilege.clone(),
            }),
        ]));
    }

    // search_string or exact line: delete by line numbers
    let needle = block.search_string.as_deref().or(line_content.as_deref());

    if let Some(text) = needle {
        let fixed = block.search_string.is_some() || block.regexp.is_none();
        let matches = if fixed {
            grep_exact_line(host_handler, text, &block.file_path).await
        } else {
            grep_lines(host_handler, text, &block.file_path, false).await
        };
        if matches.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        return Ok(AttributeComplianceAssessment::NonCompliant(vec![
            Remediation::LineInFile(LineInFileApiCall {
                file_path: block.file_path.clone(),
                line_content: None,
                regexp: None,
                api_call: LineInFileModuleInternalApiCall::DeleteLines(matches),
                privilege: privilege.clone(),
            }),
        ]));
    }

    Ok(AttributeComplianceAssessment::Compliant)
}

async fn assess_present<Handler: HostHandler>(
    block: &LineInFileBlockExpectedState,
    host_handler: &mut Handler,
    privilege: &Privilege,
    line_content: &Option<String>,
    backrefs: bool,
    firstmatch: bool,
) -> Result<AttributeComplianceAssessment, RegentError> {
    // ── regexp path ──────────────────────────────────────────────────────────
    if let Some(ref regexp) = block.regexp {
        let matches = grep_lines(host_handler, regexp, &block.file_path, false).await;

        if !matches.is_empty() {
            let target = if firstmatch {
                *matches.first().unwrap()
            } else {
                *matches.last().unwrap()
            };

            if backrefs {
                // Always replace: can't know if current value already equals the
                // backref-expanded replacement without running sed.
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::LineInFile(LineInFileApiCall {
                        file_path: block.file_path.clone(),
                        line_content: block.line.clone(),
                        regexp: Some(regexp.clone()),
                        api_call: LineInFileModuleInternalApiCall::ReplaceWithBackrefs {
                            line_number: target,
                            regexp: regexp.clone(),
                        },
                        privilege: privilege.clone(),
                    }),
                ]));
            }

            if let Some(expected) = &line_content {
                let current = get_line(host_handler, target, &block.file_path).await;
                if current.as_deref() == Some(expected.as_str()) {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::LineInFile(LineInFileApiCall {
                        file_path: block.file_path.clone(),
                        line_content: block.line.clone(),
                        regexp: None,
                        api_call: LineInFileModuleInternalApiCall::ReplaceLine(target),
                        privilege: privilege.clone(),
                    }),
                ]));
            }

            return Ok(AttributeComplianceAssessment::Compliant);
        }

        // No match
        if backrefs {
            // No match + backrefs → leave file unchanged (Ansible behaviour)
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        // Fall through to insert
    }
    // ── search_string path ───────────────────────────────────────────────────
    else if let Some(ref search) = block.search_string {
        let matches = grep_exact_line(host_handler, search, &block.file_path).await;

        if !matches.is_empty() {
            if let Some(expected) = &line_content {
                let target = if firstmatch {
                    *matches.first().unwrap()
                } else {
                    *matches.last().unwrap()
                };
                let current = get_line(host_handler, target, &block.file_path).await;
                if current.as_deref() == Some(expected.as_str()) {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::LineInFile(LineInFileApiCall {
                        file_path: block.file_path.clone(),
                        line_content: block.line.clone(),
                        regexp: None,
                        api_call: LineInFileModuleInternalApiCall::ReplaceLine(target),
                        privilege: privilege.clone(),
                    }),
                ]));
            }
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        // Fall through to insert
    }
    // ── exact line path ──────────────────────────────────────────────────────
    else if let Some(line) = &line_content {
        let matches = grep_exact_line(host_handler, line, &block.file_path).await;
        if !matches.is_empty() {
            return Ok(AttributeComplianceAssessment::Compliant);
        }
        // Fall through to insert
    }

    // ── insert ───────────────────────────────────────────────────────────────
    let insert_call = determine_insert_position(
        host_handler,
        &block.insert_after,
        &block.insert_before,
        firstmatch,
        &block.file_path,
    )
    .await;

    Ok(AttributeComplianceAssessment::NonCompliant(vec![
        Remediation::LineInFile(LineInFileApiCall {
            file_path: block.file_path.clone(),
            line_content: block.line.clone(),
            regexp: None,
            api_call: insert_call,
            privilege: privilege.clone(),
        }),
    ]))
}

async fn determine_insert_position<Handler: HostHandler>(
    host_handler: &mut Handler,
    insert_after: &Option<String>,
    insert_before: &Option<String>,
    firstmatch: bool,
    file_path: &str,
) -> LineInFileModuleInternalApiCall {
    if let Some(pattern) = insert_after {
        return match pattern.as_str() {
            "BOF" => LineInFileModuleInternalApiCall::InsertTop,
            "EOF" | "" => LineInFileModuleInternalApiCall::InsertBottom,
            _ => {
                let matches = grep_lines(host_handler, pattern, file_path, false).await;
                if matches.is_empty() {
                    LineInFileModuleInternalApiCall::InsertBottom
                } else {
                    let n = if firstmatch {
                        *matches.first().unwrap()
                    } else {
                        *matches.last().unwrap()
                    };
                    LineInFileModuleInternalApiCall::InsertAfterLine(n)
                }
            }
        };
    }

    if let Some(pattern) = insert_before {
        return match pattern.as_str() {
            "BOF" => LineInFileModuleInternalApiCall::InsertTop,
            _ => {
                let matches = grep_lines(host_handler, pattern, file_path, false).await;
                if matches.is_empty() {
                    LineInFileModuleInternalApiCall::InsertBottom
                } else {
                    let n = if firstmatch {
                        *matches.first().unwrap()
                    } else {
                        *matches.last().unwrap()
                    };
                    LineInFileModuleInternalApiCall::InsertBeforeLine(n)
                }
            }
        };
    }

    LineInFileModuleInternalApiCall::InsertBottom
}

// ── helpers ──────────────────────────────────────────────────────────────────

async fn grep_lines<Handler: HostHandler>(
    host_handler: &mut Handler,
    pattern: &str,
    file_path: &str,
    fixed: bool,
) -> Vec<u64> {
    let flag = if fixed { "-nF" } else { "-n" };
    let result = host_handler
        .run_command(
            &format!("grep {} '{}' {}", flag, pattern, file_path),
            &Privilege::None,
        )
        .await
        .unwrap();
    if result.return_code != 0 {
        return Vec::new();
    }
    result
        .stdout
        .lines()
        .filter_map(|l| l.split(':').next()?.parse::<u64>().ok())
        .collect()
}

async fn grep_exact_line<Handler: HostHandler>(
    host_handler: &mut Handler,
    line: &str,
    file_path: &str,
) -> Vec<u64> {
    let result = host_handler
        .run_command(
            &format!("grep -nxF '{}' {}", line, file_path),
            &Privilege::None,
        )
        .await
        .unwrap();
    if result.return_code != 0 {
        return Vec::new();
    }
    result
        .stdout
        .lines()
        .filter_map(|l| l.split(':').next()?.parse::<u64>().ok())
        .collect()
}

async fn get_line<Handler: HostHandler>(
    host_handler: &mut Handler,
    line_number: u64,
    file_path: &str,
) -> Option<String> {
    let result = host_handler
        .run_command(
            &format!("sed -n '{}p' {}", line_number, file_path),
            &Privilege::None,
        )
        .await
        .unwrap();
    if result.return_code == 0 {
        Some(result.stdout.trim_end_matches('\n').to_string())
    } else {
        None
    }
}

async fn get_line_count<Handler: HostHandler>(
    host_handler: &mut Handler,
    file_path: &str,
    privilege: &Privilege,
) -> u64 {
    host_handler
        .run_command(&format!("wc -l < {}", file_path), privilege)
        .await
        .unwrap()
        .stdout
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
}

/// Escape content for use inside a sed `i\`, `a\`, or `c\` command (backslash only).
fn escape_sed_text(s: &str) -> String {
    s.replace('\\', "\\\\")
}

/// Escape a string for use as a sed address pattern (between `/…/`).
fn escape_sed_pattern(s: &str) -> String {
    s.replace('/', "\\/")
}

/// Escape a sed replacement string where backreferences must be preserved.
fn escape_sed_replacement_backrefs(s: &str) -> String {
    s.replace('/', "\\/")
}

// ── API call types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LineInFileModuleInternalApiCall {
    InsertTop,
    InsertBottom,
    InsertAfterLine(u64),
    InsertBeforeLine(u64),
    ReplaceLine(u64),
    ReplaceWithBackrefs { line_number: u64, regexp: String },
    DeleteLines(Vec<u64>),
    DeleteByRegexp(String),
    CreateFile,
}

impl std::fmt::Display for LineInFileModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineInFileModuleInternalApiCall::InsertTop => write!(f, "insert line at top"),
            LineInFileModuleInternalApiCall::InsertBottom => write!(f, "insert line at bottom"),
            LineInFileModuleInternalApiCall::InsertAfterLine(n) => {
                write!(f, "insert line after line {}", n)
            }
            LineInFileModuleInternalApiCall::InsertBeforeLine(n) => {
                write!(f, "insert line before line {}", n)
            }
            LineInFileModuleInternalApiCall::ReplaceLine(n) => write!(f, "replace line {}", n),
            LineInFileModuleInternalApiCall::ReplaceWithBackrefs { line_number, .. } => {
                write!(f, "replace line {} using backrefs", line_number)
            }
            LineInFileModuleInternalApiCall::DeleteLines(ns) => {
                write!(f, "delete lines {:?}", ns)
            }
            LineInFileModuleInternalApiCall::DeleteByRegexp(p) => {
                write!(f, "delete lines matching /{}/", p)
            }
            LineInFileModuleInternalApiCall::CreateFile => write!(f, "create file with line"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineInFileApiCall {
    file_path: String,
    line_content: Option<Parameter<String>>,
    regexp: Option<String>,
    pub api_call: LineInFileModuleInternalApiCall,
    privilege: Privilege,
}

impl LineInFileApiCall {
    pub fn display(&self) -> String {
        format!("{} in {}", self.api_call, self.file_path)
    }
}

impl Timeout for LineInFileApiCall {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for LineInFileApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let line: Option<String> = match &self.line_content {
            Some(p) => Some(p.clone().inner_raw(optional_secret_provider).await.unwrap()),
            None => None,
        };

        let cmd: String = match &self.api_call {
            LineInFileModuleInternalApiCall::InsertBottom => {
                let l = line.unwrap_or_default();
                format!(
                    "printf '%s\\n' '{}' >> {}",
                    escape_sed_text(&l),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::InsertTop => {
                let l = line.unwrap_or_default();
                let count = get_line_count(host_handler, &self.file_path, &self.privilege).await;
                if count == 0 {
                    format!(
                        "printf '%s\\n' '{}' > {}",
                        escape_sed_text(&l),
                        self.file_path
                    )
                } else {
                    format!("sed -i '1i\\{}' {}", escape_sed_text(&l), self.file_path)
                }
            }
            LineInFileModuleInternalApiCall::InsertAfterLine(n) => {
                let l = line.unwrap_or_default();
                format!(
                    "sed -i '{}a\\{}' {}",
                    n,
                    escape_sed_text(&l),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::InsertBeforeLine(n) => {
                let l = line.unwrap_or_default();
                format!(
                    "sed -i '{}i\\{}' {}",
                    n,
                    escape_sed_text(&l),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::ReplaceLine(n) => {
                let l = line.unwrap_or_default();
                format!(
                    "sed -i '{}c\\{}' {}",
                    n,
                    escape_sed_text(&l),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::ReplaceWithBackrefs {
                line_number,
                regexp,
            } => {
                let replacement = line.unwrap_or_default();
                format!(
                    "sed -i '{} s/{}/{}/' {}",
                    line_number,
                    escape_sed_pattern(regexp),
                    escape_sed_replacement_backrefs(&replacement),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::DeleteLines(numbers) => {
                let parts: Vec<String> = numbers.iter().map(|n| format!("{}d", n)).collect();
                format!("sed -i '{}' {}", parts.join(";"), self.file_path)
            }
            LineInFileModuleInternalApiCall::DeleteByRegexp(pattern) => {
                format!(
                    "sed -i '/{}/d' {}",
                    escape_sed_pattern(pattern),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::CreateFile => {
                let l = line.unwrap_or_default();
                if l.is_empty() {
                    format!("touch {}", self.file_path)
                } else {
                    format!(
                        "printf '%s\\n' '{}' > {}",
                        escape_sed_text(&l),
                        self.file_path
                    )
                }
            }
        };

        let result = host_handler
            .run_command(cmd.as_str(), &self.privilege)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_lineinfile_module_block_from_yaml_str() {
        let raw = "---
- FilePath: /etc/hosts
  Line: '192.168.1.10 myhost'
  State: !Present

- FilePath: /etc/hosts
  Line: '192.168.1.10 myhost'
  State: !Present
  Insertafter: '^127\\.0\\.0\\.1'

- FilePath: /etc/hosts
  Line: '# managed block'
  State: !Present
  Insertbefore: BOF

- FilePath: /etc/sysctl.conf
  Regexp: '^net\\.ipv4\\.ip_forward'
  Line: 'net.ipv4.ip_forward = 1'
  State: !Present

- FilePath: /etc/sysctl.conf
  Regexp: '^(net\\.ipv4\\.ip_forward)\\s*=.*'
  Line: '\\1 = 1'
  Backrefs: true
  State: !Present

- FilePath: /etc/hosts
  Regexp: '^192\\.168\\.1\\.10'
  State: !Absent

- FilePath: /etc/motd
  Line: 'welcome'
  Create: true
  State: !Present
        ";
        let _: Vec<LineInFileBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }

    #[test]
    fn check_rejects_empty_file_path() {
        let result = LineInFileBlockExpectedState::builder("").build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_regexp_and_search_string_together() {
        let result = LineInFileBlockExpectedState::builder("/etc/hosts")
            .with_regexp("pattern")
            .with_search_string("literal")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_insert_after_and_insert_before_together() {
        let result = LineInFileBlockExpectedState::builder("/etc/hosts")
            .with_line("foo")
            .with_insert_after("^bar")
            .with_insert_before("^baz")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_backrefs_without_regexp() {
        let result = LineInFileBlockExpectedState::builder("/etc/hosts")
            .with_line("foo")
            .with_backrefs(true)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_nothing_set() {
        let result = LineInFileBlockExpectedState::builder("/etc/hosts").build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_valid_configurations() {
        // line only
        assert!(
            LineInFileBlockExpectedState::builder("/f")
                .with_line("hello")
                .build()
                .is_ok()
        );
        // regexp + line
        assert!(
            LineInFileBlockExpectedState::builder("/f")
                .with_regexp("^foo")
                .with_line("foo = 1")
                .build()
                .is_ok()
        );
        // regexp + line + backrefs
        assert!(
            LineInFileBlockExpectedState::builder("/f")
                .with_regexp("^(foo).*")
                .with_line("\\1 = 1")
                .with_backrefs(true)
                .build()
                .is_ok()
        );
        // regexp absent
        assert!(
            LineInFileBlockExpectedState::builder("/f")
                .with_regexp("^foo")
                .with_state(LineExpectedState::Absent)
                .build()
                .is_ok()
        );
    }
}
