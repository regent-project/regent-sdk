//! Line in file management attribute
//!
//! This module provides the `LineInFileBlockExpectedState` type for ensuring specific lines
//! are present or absent in files. Useful for configuration files, environment files, etc.
//!
//! **Compatible OS:** All (cross-platform)
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
//!   - Name: KEY=value must be present in /etc/environment
//!     Privilege: !WithSudo
//!     Detail: !LineInFile
//!       FilePath: /etc/environment
//!       State: !Present
//!         Create: true
//!       Line: !Raw "KEY=value"
//! ```

use std::fmt::Display;
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
use crate::state::attribute::RemediationsList;
use crate::state::compliance::AttributeComplianceAssessment;
use crate::state::expected_state::Parameter;
use serde::{Deserialize, Serialize};

/// Desired state of a line in a file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LineExpectedState {
    /// Line should exist in the file
    #[serde(rename_all = "PascalCase")]
    Present {
        #[serde(default = "default_line_position")]
        position: LinePosition,
        /// When using InsertAfter/InsertBefore, match the first occurrence instead of the last.
        firstmatch: Option<bool>,
        /// Create the file if it does not exist (default: false).
        create: Option<bool>,
    },
    /// Line should not exist in the file
    #[serde(rename_all = "PascalCase")]
    Absent {
        /// Line must be absent but file must be exists anyway. If set to false, no error will be triggered when trying to remove a line from a non-existing file.
        #[serde(default)] // -> false
        file_must_exist_anyway: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Line {
    /// The exact line to insert, or the replacement when regexp/search_string matches.
    Raw(Parameter<String>),
    /// Regex that selects the line(s) to replace (last match) or delete. Mutually exclusive with SearchString.
    Regexp(String),
    #[serde(rename_all = "PascalCase")]
    RegexpWithBackrefs {
        /// The regex to search for. You must include capture groups using parentheses () so the line parameter can reference them.
        regexp: String,
        /// The content to insert. It must contain backreferences like \1, \2, or \g<1> to pull the captured text from the regexp match.
        content_to_insert: String,
    },
    /// Fixed-string alternative to Regexp for matching whole lines. Mutually exclusive with Regexp.
    SearchString(String),
}

impl Display for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Line::Raw(_) => write!(f, "Line::Raw"),
            Line::Regexp(_) => write!(f, "Line::Regexp"),
            Line::RegexpWithBackrefs {
                regexp,
                content_to_insert,
            } => write!(f, "Line::RegexpWithBackrefs"),
            Line::SearchString(_) => write!(f, "Line::SearchString"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LinePosition {
    /// Insert the line after the last line matching this regex, or after "EOF" / "BOF". Mutually exclusive with InsertBefore.
    InsertAfter(String),
    /// Insert the line before the last line matching this regex, or before "BOF". Mutually exclusive with InsertAfter.
    InsertBefore(String),
}

fn default_line_position() -> LinePosition {
    LinePosition::InsertAfter("EOF".to_string())
}

/// Configuration for managing a line in a file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct LineInFileBlockExpectedState {
    /// Absolute path to the managed file.
    file_path: String,
    /// Line to ensure is present or absent. Default state: Present.
    state: LineExpectedState,
    line: Line,
}

impl LineInFileBlockExpectedState {
    // --- Absent State ---

    /// Creates a block for a line that should **not** exist in the file.
    /// - `file_path`: Path to the file.
    /// - `line`: The line (or pattern) to ensure is absent.
    /// - `file_must_exist_anyway`: If `true`, the file must exist (but the line must not).
    ///   If `false`, the file may not exist (and the line is trivially absent).
    pub fn absent(
        file_path: &str,
        line: Line,
        file_must_exist_anyway: bool,
    ) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: LineExpectedState::Absent {
                file_must_exist_anyway,
            },
            line,
        }
    }

    // --- Present State ---

    /// Creates a block for a line that should exist at the **top of the file**.
    /// - `file_path`: Path to the file.
    /// - `line`: The line to insert (or ensure exists).
    /// - `create`: If `true`, the file will be created if it doesn’t exist.
    pub fn present_at_top(
        file_path: &str,
        line: Line,
        create: Option<bool>,
    ) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: LineExpectedState::Present {
                position: LinePosition::InsertBefore("BOF".to_string()),
                firstmatch: None,
                create,
            },
            line,
        }
    }

    /// Creates a block for a line that should exist at the **bottom of the file**.
    /// - `file_path`: Path to the file.
    /// - `line`: The line to insert (or ensure exists).
    /// - `create`: If `true`, the file will be created if it doesn’t exist.
    pub fn present_at_bottom(
        file_path: &str,
        line: Line,
        create: Option<bool>,
    ) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: LineExpectedState::Present {
                position: LinePosition::InsertAfter("EOF".to_string()),
                firstmatch: None,
                create,
            },
            line,
        }
    }

    /// Creates a block for a line that should exist **after a specific pattern**.
    /// - `file_path`: Path to the file.
    /// - `line`: The line to insert (or ensure exists).
    /// - `insert_after`: The pattern to match (e.g., a regex or literal string).
    /// - `firstmatch`: If `true`, use the first match of `insert_after`. If `false`, use the last match.
    /// - `create`: If `true`, the file will be created if it doesn’t exist.
    pub fn present_after(
        file_path: &str,
        line: Line,
        insert_after: &str,
        firstmatch: Option<bool>,
        create: Option<bool>,
    ) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: LineExpectedState::Present {
                position: LinePosition::InsertAfter(insert_after.to_string()),
                firstmatch,
                create,
            },
            line,
        }
    }

    /// Creates a block for a line that should exist **before a specific pattern**.
    /// - `file_path`: Path to the file.
    /// - `line`: The line to insert (or ensure exists).
    /// - `insert_before`: The pattern to match (e.g., a regex or literal string).
    /// - `firstmatch`: If `true`, use the first match of `insert_before`. If `false`, use the last match.
    /// - `create`: If `true`, the file will be created if it doesn’t exist.
    pub fn present_before(
        file_path: &str,
        line: Line,
        insert_before: &str,
        firstmatch: Option<bool>,
        create: Option<bool>,
    ) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: LineExpectedState::Present {
                position: LinePosition::InsertBefore(insert_before.to_string()),
                firstmatch,
                create,
            },
            line,
        }
    }

    /// Creates a block for a line that should exist **somewhere in the file** (no position constraint).
    /// - `file_path`: Path to the file.
    /// - `line`: The line to ensure exists.
    /// - `create`: If `true`, the file will be created if it doesn’t exist.
    pub fn present_anywhere(
        file_path: &str,
        line: Line,
        create: Option<bool>,
    ) -> LineInFileBlockExpectedState {
        LineInFileBlockExpectedState {
            file_path: file_path.to_string(),
            state: LineExpectedState::Present {
                position: LinePosition::InsertAfter("EOF".to_string()), // Default to EOF
                firstmatch: None,
                create,
            },
            line,
        }
    }

    // --- Helper Methods for Line Construction ---

    /// Helper to create a `Line::Raw` from a string.
    pub fn raw_line(content: Parameter<String>) -> Line {
        Line::Raw(content)
    }

    /// Helper to create a `Line::Regexp` from a regex pattern.
    pub fn regexp_line(pattern: &str) -> Line {
        Line::Regexp(pattern.to_string())
    }

    /// Helper to create a `Line::RegexpWithBackrefs` from a regex and replacement.
    pub fn regexp_with_backrefs_line(regexp: &str, content_to_insert: &str) -> Line {
        Line::RegexpWithBackrefs {
            regexp: regexp.to_string(),
            content_to_insert: content_to_insert.to_string(),
        }
    }

    /// Helper to create a `Line::SearchString` from a literal string.
    pub fn search_string_line(pattern: &str) -> Line {
        Line::SearchString(pattern.to_string())
    }
}

impl Check for LineInFileBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if self.file_path.is_empty() {
            return Err(RegentError::IncoherentExpectedState(
                "FilePath cannot be empty.".to_string(),
            ));
        }
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        // Line in file operations are cross-platform compatible
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
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early checks (unchanged)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }
        if !host_handler
            .is_this_command_available("sed", privilege)
            .await
            .unwrap()
        {
            return Err(RegentError::FailedDryRunEvaluation(
                "sed is not available on this host".to_string(),
            ));
        }

        let file_exists = host_handler
            .run_command(&format!("test -f {}", self.file_path), &Privilege::None)
            .await
            .unwrap()
            .return_code
            == 0;

        match &self.state {
            LineExpectedState::Absent {
                file_must_exist_anyway,
            } => match (file_exists, file_must_exist_anyway) {
                (false, true) => Err(RegentError::FailedDryRunEvaluation(format!(
                    "File {} is expected to exist but it does not",
                    self.file_path
                ))),
                (false, false) => Ok(AttributeComplianceAssessment::Compliant),
                (true, _) => {
                    assess_absence(
                        self,
                        host_handler,
                        privilege,
                        &self.line,
                        optional_secret_provider,
                    )
                    .await
                }
            },
            LineExpectedState::Present {
                position,
                firstmatch,
                create,
            } => {
                let create = create.unwrap_or(false);
                let firstmatch = firstmatch.unwrap_or(false);

                match (file_exists, create) {
                    (true, _) => {
                        assess_presence(
                            self,
                            host_handler,
                            privilege,
                            &self.line,
                            firstmatch,
                            optional_secret_provider,
                        )
                        .await
                    }
                    (false, true) => {
                        // File does not exist and must be created
                        match &self.line {
                            Line::Raw(parameter_line) => {
                                let line_content = parameter_line
                                    .clone()
                                    .inner_raw(optional_secret_provider)
                                    .await?;
                                Ok(AttributeComplianceAssessment::NonCompliant(
                                    RemediationsList::from(vec![Remediation::LineInFile(
                                        LineInFileApiCall {
                                            file_path: self.file_path.clone(),
                                            line: self.line.clone(), // Preserve `Line`
                                            api_call: LineInFileModuleInternalApiCall::CreateFile {
                                                line_content: line_content,
                                            },
                                            privilege: privilege.clone(),
                                        },
                                    )])
                                    .unwrap(),
                                ))
                            }
                            _ => Err(RegentError::FailedDryRunEvaluation(format!(
                                "{}: file not found and cannot be created automatically. Only Line::Raw is supported for automatic file creation",
                                self.file_path
                            ))),
                        }
                    }
                    (false, false) => Err(RegentError::FailedDryRunEvaluation(format!(
                        "{}: file not found (set Create: true to create it)",
                        self.file_path
                    ))),
                }
            }
        }
    }
}

async fn assess_absence<Handler: HostHandler>(
    block: &LineInFileBlockExpectedState,
    host_handler: &mut Handler,
    privilege: &Privilege,
    line: &Line, // Now uses `Line` directly
    optional_secret_provider: &Option<SecretProvidersPool>,
) -> Result<AttributeComplianceAssessment, RegentError> {
    match line {
        Line::Raw(parameter_line) => {
            let content_to_search = parameter_line
                .clone()
                .inner_raw(optional_secret_provider)
                .await?;
            let matches = grep_exact_line(host_handler, &content_to_search, &block.file_path).await;
            if matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(vec![Remediation::LineInFile(LineInFileApiCall {
                    file_path: block.file_path.clone(),
                    line: line.clone(), // Preserve `Line`
                    api_call: LineInFileModuleInternalApiCall::DeleteLines {
                        line_numbers: matches,
                    },
                    privilege: privilege.clone(),
                })])
                .unwrap(),
            ))
        }
        Line::Regexp(regexp) => {
            let matches = grep_lines(host_handler, regexp, &block.file_path, false).await;
            if matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(vec![Remediation::LineInFile(LineInFileApiCall {
                    file_path: block.file_path.clone(),
                    line: line.clone(), // Preserve `Line`
                    api_call: LineInFileModuleInternalApiCall::DeleteByRegexp {
                        regexp: regexp.clone(),
                    },
                    privilege: privilege.clone(),
                })])
                .unwrap(),
            ))
        }
        Line::RegexpWithBackrefs {
            regexp,
            content_to_insert,
        } => {
            let matches = grep_lines(host_handler, regexp, &block.file_path, false).await;
            if matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(vec![Remediation::LineInFile(LineInFileApiCall {
                    file_path: block.file_path.clone(),
                    line: line.clone(), // Preserve `Line`
                    api_call: LineInFileModuleInternalApiCall::DeleteByRegexp {
                        regexp: regexp.clone(),
                    },
                    privilege: privilege.clone(),
                })])
                .unwrap(),
            ))
        }
        Line::SearchString(search_string) => {
            let matches = grep_lines(host_handler, search_string, &block.file_path, false).await;
            if matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            Ok(AttributeComplianceAssessment::NonCompliant(
                RemediationsList::from(vec![Remediation::LineInFile(LineInFileApiCall {
                    file_path: block.file_path.clone(),
                    line: line.clone(), // Preserve `Line`
                    api_call: LineInFileModuleInternalApiCall::DeleteLines {
                        line_numbers: matches,
                    },
                    privilege: privilege.clone(),
                })])
                .unwrap(),
            ))
        }
    }
}

async fn assess_presence<Handler: HostHandler>(
    block: &LineInFileBlockExpectedState,
    host_handler: &mut Handler,
    privilege: &Privilege,
    line: &Line, // Now uses `Line` directly
    firstmatch: bool,
    optional_secret_provider: &Option<SecretProvidersPool>,
) -> Result<AttributeComplianceAssessment, RegentError> {
    match line {
        Line::Raw(parameter_line) => {
            let content_to_search = parameter_line
                .clone()
                .inner_raw(optional_secret_provider)
                .await?;
            let matches = grep_exact_line(host_handler, &content_to_search, &block.file_path).await;
            if !matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            // Fall through to insert
        }
        Line::Regexp(regexp) => {
            let matches = grep_lines(host_handler, regexp, &block.file_path, false).await;
            if !matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            // Fall through to insert
        }
        Line::RegexpWithBackrefs {
            regexp,
            content_to_insert,
        } => {
            let matches = grep_lines(host_handler, regexp, &block.file_path, false).await;
            if !matches.is_empty() {
                let target = if firstmatch {
                    *matches.first().unwrap()
                } else {
                    *matches.last().unwrap()
                };
                return Ok(AttributeComplianceAssessment::NonCompliant(
                    RemediationsList::from(vec![Remediation::LineInFile(LineInFileApiCall {
                        file_path: block.file_path.clone(),
                        line: line.clone(), // Preserve `Line`
                        api_call: LineInFileModuleInternalApiCall::ReplaceWithBackrefs {
                            line_content: content_to_insert.clone(),
                            line_number: target,
                            regexp: regexp.clone(),
                        },
                        privilege: privilege.clone(),
                    })])
                    .unwrap(),
                ));
            }
            // Fall through to insert
        }
        Line::SearchString(search_string) => {
            let matches = grep_exact_line(host_handler, search_string, &block.file_path).await;
            if !matches.is_empty() {
                return Ok(AttributeComplianceAssessment::Compliant);
            }
            // Fall through to insert
        }
    }

    // Determine insert position
    let line_content = get_line_content(line, optional_secret_provider).await?;
    let insert_call = match &block.state {
        LineExpectedState::Present {
            position,
            firstmatch,
            ..
        } => {
            let firstmatch = firstmatch.unwrap_or(false);
            match position {
                LinePosition::InsertAfter(pattern) => match pattern.as_str() {
                    "BOF" => LineInFileModuleInternalApiCall::InsertTop {
                        line_content: line_content.clone(),
                    },
                    "EOF" | "" => LineInFileModuleInternalApiCall::InsertBottom {
                        line_content: line_content.clone(),
                    },
                    _ => {
                        let matches =
                            grep_lines(host_handler, pattern, &block.file_path, false).await;
                        if matches.is_empty() {
                            LineInFileModuleInternalApiCall::InsertBottom {
                                line_content: line_content.clone(),
                            }
                        } else {
                            let n = if firstmatch {
                                *matches.first().unwrap()
                            } else {
                                *matches.last().unwrap()
                            };
                            LineInFileModuleInternalApiCall::InsertAfterLine {
                                line_content: line_content.clone(),
                                line_number: n,
                            }
                        }
                    }
                },
                LinePosition::InsertBefore(pattern) => match pattern.as_str() {
                    "BOF" => LineInFileModuleInternalApiCall::InsertTop {
                        line_content: line_content.clone(),
                    },
                    _ => {
                        let matches =
                            grep_lines(host_handler, pattern, &block.file_path, false).await;
                        if matches.is_empty() {
                            LineInFileModuleInternalApiCall::InsertBottom {
                                line_content: line_content.clone(),
                            }
                        } else {
                            let n = if firstmatch {
                                *matches.first().unwrap()
                            } else {
                                *matches.last().unwrap()
                            };
                            LineInFileModuleInternalApiCall::InsertBeforeLine {
                                line_content: line_content.clone(),
                                line_number: n,
                            }
                        }
                    }
                },
            }
        }
        _ => LineInFileModuleInternalApiCall::InsertBottom {
            line_content: line_content.clone(),
        },
    };

    Ok(AttributeComplianceAssessment::NonCompliant(
        RemediationsList::from(vec![Remediation::LineInFile(LineInFileApiCall {
            file_path: block.file_path.clone(),
            line: line.clone(), // Preserve `Line`
            api_call: insert_call,
            privilege: privilege.clone(),
        })])
        .unwrap(),
    ))
}

/// Helper function to extract line content from `Line` enum
async fn get_line_content(
    line: &Line,
    optional_secret_provider: &Option<SecretProvidersPool>,
) -> Result<String, RegentError> {
    match line {
        Line::Raw(parameter_line) => {
            parameter_line
                .clone()
                .inner_raw(optional_secret_provider)
                .await
        }
        Line::RegexpWithBackrefs {
            content_to_insert, ..
        } => Ok(content_to_insert.clone()),
        Line::Regexp(regexp) => Ok(regexp.clone()),
        Line::SearchString(search_string) => Ok(search_string.clone()),
    }
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
    InsertTop {
        line_content: String,
    },
    InsertBottom {
        line_content: String,
    },
    InsertAfterLine {
        line_content: String,
        line_number: u64,
    },
    InsertBeforeLine {
        line_content: String,
        line_number: u64,
    },
    ReplaceLine {
        line_content: String,
        line_number: u64,
    },
    ReplaceWithBackrefs {
        line_content: String,
        line_number: u64,
        regexp: String,
    },
    DeleteLines {
        line_numbers: Vec<u64>,
    },
    DeleteByRegexp {
        regexp: String,
    },
    CreateFile {
        line_content: String,
    },
}

impl std::fmt::Display for LineInFileModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineInFileModuleInternalApiCall::InsertTop { line_content } => {
                write!(f, "insert line at top: '{}'", line_content)
            }
            LineInFileModuleInternalApiCall::InsertBottom { line_content } => {
                write!(f, "insert line at bottom: '{}'", line_content)
            }
            LineInFileModuleInternalApiCall::InsertAfterLine {
                line_content,
                line_number,
            } => {
                write!(
                    f,
                    "insert line '{}' after line {}",
                    line_content, line_number
                )
            }
            LineInFileModuleInternalApiCall::InsertBeforeLine {
                line_content,
                line_number,
            } => {
                write!(
                    f,
                    "insert line '{}' before line {}",
                    line_content, line_number
                )
            }
            LineInFileModuleInternalApiCall::ReplaceLine {
                line_content,
                line_number,
            } => {
                write!(f, "replace line {} with '{}'", line_number, line_content)
            }
            LineInFileModuleInternalApiCall::ReplaceWithBackrefs {
                line_content,
                line_number,
                regexp,
            } => {
                write!(
                    f,
                    "replace line {} using backrefs with regexp '{}' and content '{}'",
                    line_number, regexp, line_content
                )
            }
            LineInFileModuleInternalApiCall::DeleteLines { line_numbers } => {
                write!(f, "delete lines {:?}", line_numbers)
            }
            LineInFileModuleInternalApiCall::DeleteByRegexp { regexp } => {
                write!(f, "delete lines matching /{}/", regexp)
            }
            LineInFileModuleInternalApiCall::CreateFile { line_content } => {
                write!(f, "create file with line: '{}'", line_content)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineInFileApiCall {
    pub file_path: String,
    pub line: Line, // Preserve `Line` (which may contain `Parameter<String>`)
    pub api_call: LineInFileModuleInternalApiCall,
    pub privilege: Privilege,
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

impl Check for LineInFileApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        _host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        // Line in file operations are cross-platform compatible
        Ok(())
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for LineInFileApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify host compatibility (always passes for lineinfile)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let cmd: String = match &self.api_call {
            LineInFileModuleInternalApiCall::InsertBottom { line_content } => {
                format!(
                    "printf '%s\\n' '{}' >> {}",
                    escape_sed_text(line_content),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::InsertTop { line_content } => {
                let count = get_line_count(host_handler, &self.file_path, &self.privilege).await;
                if count == 0 {
                    format!(
                        "printf '%s\\n' '{}' > {}",
                        escape_sed_text(line_content),
                        self.file_path
                    )
                } else {
                    format!(
                        "sed -i '1i\\{}' {}",
                        escape_sed_text(line_content),
                        self.file_path
                    )
                }
            }
            LineInFileModuleInternalApiCall::InsertAfterLine {
                line_content,
                line_number,
            } => {
                format!(
                    "sed -i '{}a\\{}' {}",
                    line_number,
                    escape_sed_text(&line_content),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::InsertBeforeLine {
                line_content,
                line_number,
            } => {
                format!(
                    "sed -i '{}i\\{}' {}",
                    line_number,
                    escape_sed_text(line_content),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::ReplaceLine {
                line_content,
                line_number,
            } => {
                format!(
                    "sed -i '{}c\\{}' {}",
                    line_number,
                    escape_sed_text(line_content),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::ReplaceWithBackrefs {
                line_content,
                line_number,
                regexp,
            } => {
                format!(
                    "sed -i '{} s/{}/{}/' {}",
                    line_number,
                    escape_sed_pattern(regexp),
                    escape_sed_replacement_backrefs(line_content),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::DeleteLines { line_numbers } => {
                let parts: Vec<String> = line_numbers.iter().map(|n| format!("{}d", n)).collect();
                format!("sed -i '{}' {}", parts.join(";"), self.file_path)
            }
            LineInFileModuleInternalApiCall::DeleteByRegexp { regexp } => {
                format!(
                    "sed -i '/{}/d' {}",
                    escape_sed_pattern(regexp),
                    self.file_path
                )
            }
            LineInFileModuleInternalApiCall::CreateFile { line_content } => {
                if line_content.is_empty() {
                    format!("touch {}", self.file_path)
                } else {
                    format!(
                        "printf '%s\\n' '{}' > {}",
                        escape_sed_text(line_content),
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
            // Post-application verification: verify the change was actually applied
            let verification_result = verify_file_state(
                host_handler,
                &self.file_path,
                &self.api_call,
                &self.privilege,
            )
            .await;

            if verification_result {
                Ok(InternalApiCallOutcome::Success(None))
            } else {
                Ok(InternalApiCallOutcome::Failure(
                    "Command succeeded but post-verification failed: file state does not match expected".to_string(),
                ))
            }
        } else {
            Ok(InternalApiCallOutcome::Failure(format!(
                "RC: {}, STDOUT: {}, STDERR: {}",
                result.return_code, result.stdout, result.stderr
            )))
        }
    }
}

/// Verify that the file state matches the expected state after a modification.
/// This implements post-application verification for idempotency.
async fn verify_file_state<Handler: HostHandler>(
    host_handler: &mut Handler,
    file_path: &str,
    api_call: &LineInFileModuleInternalApiCall,
    privilege: &Privilege,
) -> bool {
    match api_call {
        LineInFileModuleInternalApiCall::InsertTop { line_content } => {
            // Verify the line exists at the beginning of the file
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                content
                    .lines()
                    .next()
                    .map_or(false, |first_line| first_line.trim() == line_content.trim())
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::InsertBottom { line_content } => {
            // Verify the line exists at the end of the file
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                content
                    .lines()
                    .last()
                    .map_or(false, |last_line| last_line.trim() == line_content.trim())
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::InsertAfterLine {
            line_content,
            line_number,
        } => {
            // Verify the line exists after the specified line number
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                let lines: Vec<&str> = content.lines().collect();
                let insert_pos = *line_number as usize;
                if insert_pos < lines.len() {
                    let next_pos = insert_pos + 1;
                    if next_pos < lines.len() {
                        return lines[next_pos].trim() == line_content.trim();
                    }
                }
                false
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::InsertBeforeLine {
            line_content,
            line_number,
        } => {
            // Verify the line exists before the specified line number
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                let lines: Vec<&str> = content.lines().collect();
                let insert_pos = *line_number as usize;
                if insert_pos > 0 && insert_pos <= lines.len() {
                    return lines[insert_pos - 1].trim() == line_content.trim();
                }
                false
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::ReplaceLine {
            line_content,
            line_number,
        } => {
            // Verify the line at position `line_number` matches the expected line
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                let lines: Vec<&str> = content.lines().collect();
                let pos = *line_number as usize;
                if pos > 0 && pos <= lines.len() {
                    return lines[pos - 1].trim() == line_content.trim();
                }
                false
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::ReplaceWithBackrefs {
            line_content,
            line_number,
            regexp,
        } => {
            // For backrefs, check that the line exists at the expected position
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                let lines: Vec<&str> = content.lines().collect();
                let pos = *line_number as usize;
                if pos > 0 && pos <= lines.len() {
                    return lines[pos - 1].trim() == line_content.trim();
                }
                false
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::DeleteLines { line_numbers } => {
            // Verify the lines were actually deleted
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                let lines: Vec<&str> = content.lines().collect();
                // Check that none of the deleted line numbers exist
                for &n in line_numbers {
                    let pos = n as usize;
                    if pos > 0 && pos <= lines.len() {
                        return false; // Line still exists
                    }
                }
                true
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::DeleteByRegexp { regexp } => {
            // Verify no lines matching the pattern exist
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                !content.lines().any(|line| line.contains(regexp.as_str()))
            } else {
                false
            }
        }
        LineInFileModuleInternalApiCall::CreateFile { line_content } => {
            // Verify the file exists and contains the expected line
            if let Some(content) = read_file_content(host_handler, file_path, privilege).await {
                content
                    .lines()
                    .next()
                    .map_or(false, |first_line| first_line.trim() == line_content.trim())
            } else {
                false
            }
        }
    }
}

/// Read the content of a file from the remote host.
async fn read_file_content<Handler: HostHandler>(
    host_handler: &mut Handler,
    file_path: &str,
    privilege: &Privilege,
) -> Option<String> {
    let result = host_handler
        .run_command(&format!("cat {}", file_path), privilege)
        .await
        .unwrap();
    if result.return_code == 0 {
        Some(result.stdout)
    } else {
        None
    }
}

use std::assert_matches;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_lineinfile_module_block_from_yaml_str() {
        let raw = "---
- FilePath: /etc/hosts
  Line: !Raw '192.168.1.10 myhost'
  State: !Present

- FilePath: /etc/hosts
  Line: !Raw '192.168.1.10 myhost'
  State: !Present
    Position: !InsertAfter '^127\\.0\\.0\\.1'

- FilePath: /etc/hosts
  Line: !Raw '# managed block'
  State: !Present
    Position: !InsertBefore BOF

- FilePath: /etc/sysctl.conf
  Line: !Regexp '^net\\.ipv4\\.ip_forward'
  State: !Present

- FilePath: /etc/sysctl.conf
  Line: !RegexpWithBackrefs
    Regexp: '^(net\\.ipv4\\.ip_forward)\\s*=.*'
    ContentToInsert: '\\1 = 1'
  State: !Present

- FilePath: /etc/hosts
  Line: !Regexp '^192\\.168\\.1\\.10'
  State: !Absent

- FilePath: /etc/motd
  Line: !Raw 'welcome'
  State: !Present
    Create: true
        ";
        let _: Vec<LineInFileBlockExpectedState> = yaml_serde::from_str(raw).unwrap();
    }
    #[test]
    fn test_deserialize_line_in_file_block_expected_state_present_raw() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
          Position: !InsertAfter EOF
          Firstmatch: true
          Create: false
        Line: !Raw
          "hello world"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(result.file_path, "/tmp/test.txt");
        assert_matches!(
            result.state,
            LineExpectedState::Present {
                position: LinePosition::InsertAfter(_),
                firstmatch: Some(true),
                create: Some(false),
            }
        );
        assert_matches!(result.line, Line::Raw(_));
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_absent() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Absent
          FileMustExistAnyway: false
        Line: !Raw
          "hello world"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(result.file_path, "/tmp/test.txt");
        assert_matches!(
            result.state,
            LineExpectedState::Absent {
                file_must_exist_anyway: false,
            }
        );
        assert_matches!(result.line, Line::Raw(_));
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_regexp() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
          Position: !InsertBefore BOF
          Firstmatch: false
          Create: true
        Line: !Regexp
          "^hello.*$"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(result.file_path, "/tmp/test.txt");
        assert_matches!(
            result.state,
            LineExpectedState::Present {
                position: LinePosition::InsertBefore(_),
                firstmatch: Some(false),
                create: Some(true),
            }
        );
        assert_matches!(result.line, Line::Regexp(_));
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_regexp_with_backrefs() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
        Line: !RegexpWithBackrefs
          Regexp: "^hello (\\w+)$"
          ContentToInsert: "hi \\1"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(result.file_path, "/tmp/test.txt");
        assert_matches!(result.state, LineExpectedState::Present { .. });
        assert_matches!(
            result.line,
            Line::RegexpWithBackrefs {
                regexp: _,
                content_to_insert: _,
            }
        );
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_search_string() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
        Line: !SearchString
          "hello world"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(result.file_path, "/tmp/test.txt");
        assert_matches!(result.state, LineExpectedState::Present { .. });
        assert_matches!(result.line, Line::SearchString(_));
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_position_bof() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
          Position: !InsertBefore
            BOF
        Line: !Raw
          "hello world"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_matches!(
            result.state,
            LineExpectedState::Present {
                position: LinePosition::InsertBefore(_),
                ..
            }
        );
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_position_eof() {
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
          Position: !InsertAfter EOF
        Line: !Raw
          "hello world"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_matches!(
            result.state,
            LineExpectedState::Present {
                position: LinePosition::InsertAfter(_),
                ..
            }
        );
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_minimal() {
        // Test minimal YAML (all optional fields omitted)
        let yaml = r#"
        FilePath: /tmp/test.txt
        Line: !Raw "hello world"
    "#;

        let result = yaml_serde::from_str::<LineInFileBlockExpectedState>(yaml);
        assert!(result.is_err()); // Missing required State field
    }

    #[test]
    fn test_deserialize_line_in_file_block_expected_state_invalid() {
        // Test invalid YAML (e.g., unknown fields at top level)
        let yaml = r#"
        FilePath: /tmp/test.txt
        UnknownField: true
        Line: !Raw
          "hello world"
    "#;

        let result = yaml_serde::from_str::<LineInFileBlockExpectedState>(yaml);
        assert!(result.is_err()); // Should fail due to unknown field at top level
    }

    #[test]
    fn test_line_in_file_block_expected_state_defaults() {
        // Test default values for optional fields
        let yaml = r#"
        FilePath: /tmp/test.txt
        State: !Present
        Line: !Raw
          "hello world"
    "#;

        let result: LineInFileBlockExpectedState = yaml_serde::from_str(yaml).unwrap();
        assert_matches!(
            result.state,
            LineExpectedState::Present {
                position: _,
                firstmatch: None,
                create: None,
            }
        );
    }
}
