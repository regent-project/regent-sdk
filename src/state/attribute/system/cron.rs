//! Cron job management attribute
//!
//! This module provides the `CronBlockExpectedState` type for managing cron jobs
//! on Unix-like systems, supporting both user crontabs and system cron.d files.
//!
//! **Compatible OS:** Linux (all distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::cron::{
//!     CronBlockExpectedState, CronExpectedState, CronSpecialTime, CronSchedule, CronCommand, CronTarget
//! };
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Schedule a daily backup job for the root user's crontab
//! let backup = CronBlockExpectedState::present(
//!     CronSchedule::SpecialTime(CronSpecialTime::Daily),
//!     CronCommand::Specific("/usr/local/bin/backup.sh".to_string()),
//!     Some("backup".to_string()),
//!     CronTarget::Crontab(None),
//! );
//!
//! // Schedule a weekly cleanup job in /etc/cron.d/ for a specific user
//! let cleanup = CronBlockExpectedState::present(
//!     CronSchedule::SpecialTime(CronSpecialTime::Weekly),
//!     CronCommand::Specific("/usr/local/bin/cleanup.sh".to_string()),
//!     Some("cleanup".to_string()),
//!     CronTarget::CronDFile("backupuser".to_string(), "cleanup_jobs".to_string()),
//! );
//!
//! // Ensure a cron job is absent
//! let remove_old_job = CronBlockExpectedState::absent(
//!     CronSchedule::SpecialTime(CronSpecialTime::Daily),
//!     CronCommand::Any,
//!     Some("old_job".to_string()),
//!     CronTarget::Crontab(Some("user".to_string())),
//! );
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::cron(backup, Privilege::WithSudo, None))
//!     .with_attribute(Attribute::cron(cleanup, Privilege::WithSudo, None))
//!     .with_attribute(Attribute::cron(remove_old_job, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   # User crontab example
//!   - Name: Daily backup job must be present
//!     Privilege: !WithSudo
//!     Detail: !Cron
//!       Name: backup
//!       Job: /usr/local/bin/backup.sh
//!       SpecialTime: !Daily
//!       Target: !Crontab null
//!
//!   # System cron.d file example
//!   - Name: Weekly cleanup job must be present
//!     Privilege: !WithSudo
//!     Detail: !Cron
//!       Name: cleanup
//!       Job: /usr/local/bin/cleanup.sh
//!       SpecialTime: !Weekly
//!       Target: !CronDFile ["backupuser", "cleanup_jobs"]
//!
//!   # Ensure a job is absent
//!   - Name: Old job must be absent
//!     Privilege: !WithSudo
//!     Detail: !Cron
//!       Name: old_job
//!       State: !Absent
//!       Target: !Crontab ["user"]
//! ```

/// Configuration for a cron job
///
/// Use the `present` or `absent` constructors to create cron jobs with the desired state.
/// Each cron job must have a unique name and a job command when state is Present.
/// You can specify timing using either individual time fields (minute, hour, day, month, weekday)
/// or special_time shortcuts like Daily, Weekly, etc.
///
/// For system-wide cron jobs, use `CronTarget::CronDFile(user, filename)` to specify a file in /etc/cron.d/.
/// For user-specific jobs, use `CronTarget::Crontab(user)` to specify the username (or None for current user).
use crate::error::RegentError;
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
use serde::{Deserialize, Serialize};
use std::time::Duration;

const REGENT_MARKER_PREFIX: &str = "# regent: ";

/// Desired state of a cron job
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronExpectedState {
    /// Cron job should exist
    Present,
    /// Cron job should not exist
    Absent,
}

/// Special time strings for cron schedules
///
/// These are shortcuts for common scheduling patterns like @daily, @weekly, etc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronSpecialTime {
    /// Run at boot time
    Reboot,
    /// Run once a year at midnight on Jan 1
    Yearly,
    /// Run once a year at midnight on Jan 1 (alias for Yearly)
    Annually,
    /// Run once a month at midnight on the first day
    Monthly,
    /// Run once a week at midnight on Sunday
    Weekly,
    /// Run once a day at midnight
    Daily,
    /// Run once an hour at the beginning of the hour
    Hourly,
}

impl std::fmt::Display for CronSpecialTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CronSpecialTime::Reboot => "reboot",
            CronSpecialTime::Yearly => "yearly",
            CronSpecialTime::Annually => "annually",
            CronSpecialTime::Monthly => "monthly",
            CronSpecialTime::Weekly => "weekly",
            CronSpecialTime::Daily => "daily",
            CronSpecialTime::Hourly => "hourly",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronSchedule {
    Custom {
        /// Minute field (0-59, or * for any)
        minute: Option<String>,
        /// Hour field (0-23, or * for any)
        hour: Option<String>,
        /// Day of month field (1-31, or * for any)
        day: Option<String>,
        /// Month field (1-12, or * for any)
        month: Option<String>,
        /// Weekday field (0-6, where 0 is Sunday, or * for any)
        weekday: Option<String>,
    },
    SpecialTime(CronSpecialTime),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronCommand {
    Any,
    #[serde(untagged)]
    Specific(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronFile {
    All,
    #[serde(untagged)]
    Specific(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronTarget {
    Crontab(Option<String>), // potential user
    /// User to run the cron job as, and file to work on
    #[serde(untagged)]
    CronDFile(String, String), // user, file
}

/// Configuration for a cron job
///
/// Use the builder pattern to create cron jobs with various scheduling options.
/// Each cron job must have a unique name and a job command when state is Present.
/// You can specify timing using either individual time fields (minute, hour, day, month, weekday)
/// or special_time shortcuts like Daily, Weekly, etc.
///
/// For system-wide cron jobs, use cron_file to specify a file in /etc/cron.d/.
/// For user-specific jobs, use user to specify the username.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct CronBlockExpectedState {
    /// What schedule for this cron job
    schedule: CronSchedule,
    /// Command to execute
    command: CronCommand,
    /// Desired state of the cron job
    state: CronExpectedState,
    /// Unique identifier for this cron job (used in marker comment)
    name: Option<String>,
    target: CronTarget,
}

impl Timeout for CronBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl CronBlockExpectedState {
    pub fn absent(
        schedule: CronSchedule,
        command: CronCommand,
        name: Option<String>,
        target: CronTarget,
    ) -> CronBlockExpectedState {
        CronBlockExpectedState {
            schedule,
            command,
            state: CronExpectedState::Absent,
            name,
            target,
        }
    }

    pub fn present(schedule: CronSchedule,
        command: CronCommand,
        name: Option<String>,
        target: CronTarget,) -> CronBlockExpectedState {
        CronBlockExpectedState {
            schedule,
            command,
            state: CronExpectedState::Present,
            name,
            target,
        }
    }
}

impl Check for CronBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but cron management is only supported on Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for CronBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        // Early check: verify we're on a compatible host (Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        // Check if crontab or cron.d file is available based on target
        match &self.target {
            CronTarget::Crontab(_) => {
                if !host_handler
                    .is_this_command_available("crontab", privilege)
                    .await
                    .unwrap()
                {
                    return Err(RegentError::FailedDryRunEvaluation(
                        "crontab not available on this host".to_string(),
                    ));
                }
            }
            CronTarget::CronDFile(_, _) => {
                // No additional check needed for cron.d files
            }
        }

        // Get cron content based on target
        let content = match get_cron_content(host_handler, &self.target).await {
            Ok(c) => c,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        // Find existing entry
        let name = self.name.as_ref().map_or("", |n| n.as_str());
        let existing_entry = find_cron_entry(&content, name);

        // Determine if this is a cron.d target
        let cron_d_user = match &self.target {
            CronTarget::Crontab(_) => None,
            CronTarget::CronDFile(user, _) => Some(user.clone()),
        };

        // Extract command for building the cron line
        let command = match &self.command {
            CronCommand::Any => String::new(),
            CronCommand::Specific(cmd) => cmd.clone(),
        };

        match &self.state {
            CronExpectedState::Absent => {
                if existing_entry.is_none() {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                // Build remove API call
                let (name, user, cron_file) = match &self.target {
                    CronTarget::Crontab(user) => {
                        (self.name.clone().unwrap_or_default(), user.clone(), None)
                    }
                    CronTarget::CronDFile(user, file) => (
                        self.name.clone().unwrap_or_default(),
                        Some(user.clone()),
                        Some(file.clone()),
                    ),
                };
                Ok(AttributeComplianceAssessment::NonCompliant(
                    RemediationsList::from(vec![Remediation::Cron(CronApiCall::from(
                        CronModuleInternalApiCall::Remove {
                            name,
                            user,
                            cron_file,
                        },
                        privilege.clone(),
                    ))])
                    .unwrap(),
                ))
            }
            CronExpectedState::Present => {
                let expected_line = build_cron_line(&self.schedule, cron_d_user, command);
                let needs_upsert = match existing_entry {
                    None => true,
                    Some(ref current) => current != &expected_line,
                };

                if needs_upsert {
                    // Build upsert API call
                    let (name, user, cron_file) = match &self.target {
                        CronTarget::Crontab(user) => {
                            (self.name.clone().unwrap_or_default(), user.clone(), None)
                        }
                        CronTarget::CronDFile(user, file) => (
                            self.name.clone().unwrap_or_default(),
                            Some(user.clone()),
                            Some(file.clone()),
                        ),
                    };
                    return Ok(AttributeComplianceAssessment::NonCompliant(
                        RemediationsList::from(vec![Remediation::Cron(CronApiCall::from(
                            CronModuleInternalApiCall::Upsert {
                                name,
                                cron_line: expected_line,
                                user,
                                cron_file,
                            },
                            privilege.clone(),
                        ))])
                        .unwrap(),
                    ));
                }

                Ok(AttributeComplianceAssessment::Compliant)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CronModuleInternalApiCall {
    // Creates or updates a named cron entry (identified by its regent marker comment)
    Upsert {
        name: String,
        cron_line: String,
        user: Option<String>,
        cron_file: Option<String>,
    },
    Remove {
        name: String,
        user: Option<String>,
        cron_file: Option<String>,
    },
}

impl std::fmt::Display for CronModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CronModuleInternalApiCall::Upsert { name, .. } => {
                write!(f, "upsert cron entry '{}'", name)
            }
            CronModuleInternalApiCall::Remove { name, .. } => {
                write!(f, "remove cron entry '{}'", name)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CronApiCall {
    pub api_call: CronModuleInternalApiCall,
    privilege: Privilege,
}

impl CronApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            CronModuleInternalApiCall::Upsert { name, .. } => {
                format!("Upsert cron entry '{}'", name)
            }
            CronModuleInternalApiCall::Remove { name, .. } => {
                format!("Remove cron entry '{}'", name)
            }
        }
    }

    fn from(api_call: CronModuleInternalApiCall, privilege: Privilege) -> CronApiCall {
        CronApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for CronApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but cron management is only supported on Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for CronApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        // Early check: verify we're on a compatible host (Linux)
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        let (cmd, privilege) = match &self.api_call {
            CronModuleInternalApiCall::Upsert {
                name,
                cron_line,
                user,
                cron_file,
            } => {
                let cmd = if let Some(file) = cron_file {
                    // /etc/cron.d/ approach: remove existing entry (if any) then append
                    format!(
                        "touch /etc/cron.d/{f} && sed -i '/^# regent: {n}$/{{N;d;}}' /etc/cron.d/{f} && printf '# regent: {n}\\n{l}\\n' >> /etc/cron.d/{f}",
                        f = file,
                        n = name,
                        l = cron_line
                    )
                } else {
                    // User crontab approach: rebuild crontab minus old entry, then append new one
                    let uf = user_flag(user);
                    format!(
                        "(crontab -l {uf}2>/dev/null | sed '/^# regent: {n}$/{{N;d;}}'; printf '# regent: {n}\\n{l}\\n') | crontab {uf}-",
                        uf = uf,
                        n = name,
                        l = cron_line
                    )
                };
                (cmd, &self.privilege)
            }
            CronModuleInternalApiCall::Remove {
                name,
                user,
                cron_file,
            } => {
                let cmd = if let Some(file) = cron_file {
                    format!(
                        "sed -i '/^# regent: {n}$/{{N;d;}}' /etc/cron.d/{f}",
                        n = name,
                        f = file
                    )
                } else {
                    let uf = user_flag(user);
                    format!(
                        "crontab -l {uf}2>/dev/null | sed '/^# regent: {n}$/{{N;d;}}' | crontab {uf}-",
                        uf = uf,
                        n = name
                    )
                };
                (cmd, &self.privilege)
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

fn user_flag(user: &Option<String>) -> String {
    match user {
        Some(u) => format!("-u {} ", u),
        None => String::new(),
    }
}

async fn get_cron_content<Handler: HostHandler>(
    host_handler: &mut Handler,
    target: &CronTarget,
) -> Result<String, String> {
    match target {
        CronTarget::Crontab(potential_user) => {
            let cmd = match potential_user {
                Some(u) => format!("crontab -l -u {}", u),
                None => "crontab -l".to_string(),
            };
            let result = host_handler
                .run_command(&cmd, &Privilege::None)
                .await
                .map_err(|e| format!("Failed to read crontab: {:?}", e))?;
            // rc=1 means "no crontab for user" — treat as empty
            Ok(if result.return_code == 0 {
                result.stdout
            } else {
                String::new()
            })
        }
        CronTarget::CronDFile(user, filename) => {
            let result = host_handler
                .run_command(&format!("cat /etc/cron.d/{}", filename), &Privilege::None)
                .await
                .map_err(|e| format!("Failed to read cron file: {:?}", e))?;
            Ok(if result.return_code == 0 {
                result.stdout
            } else {
                String::new()
            })
        }
    }
}

fn find_cron_entry(content: &str, name: &str) -> Option<String> {
    let marker = format!("{}{}", REGENT_MARKER_PREFIX, name);
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        if line == marker {
            // Skip empty lines to find the actual cron job line
            // Note: We don't skip lines starting with # because disabled cron jobs start with #
            return lines
                .skip_while(|l| l.trim().is_empty())
                .next()
                .map(|l| l.to_string());
        }
    }
    None
}

fn build_cron_line(
    schedule: &CronSchedule,
    cron_d_user: Option<String>,
    command: String,
) -> String {
    let timing = match schedule {
        CronSchedule::Custom {
            minute,
            hour,
            day,
            month,
            weekday,
        } => {
            format!(
                "{} {} {} {} {}",
                minute.as_deref().unwrap_or("*"),
                hour.as_deref().unwrap_or("*"),
                day.as_deref().unwrap_or("*"),
                month.as_deref().unwrap_or("*"),
                weekday.as_deref().unwrap_or("*"),
            )
        }
        CronSchedule::SpecialTime(cron_special_time) => {
            format!("@{}", cron_special_time)
        }
    };

    let body = match cron_d_user {
        Some(user) => {
            // /etc/cron.d/ entries require an explicit username field
            format!("{} {} {}", timing, user, command)
        }
        None => {
            format!("{} {}", timing, command)
        }
    };

    body
}

#[cfg(test)]
mod tests {
    use super::*;

    //     #[test]
    //     fn parsing_cron_module_block_from_yaml_str() {
    //         let raw_attributes = "---
    // - Name: backup
    //   Job: /usr/local/bin/backup.sh
    //   Minute: '0'
    //   Hour: '2'

    // - Name: cleanup
    //   State: !Present
    //   Job: /usr/local/bin/cleanup.sh
    //   SpecialTime: !Daily

    // - Name: oldtask
    //   State: !Absent
    //         ";

    //         let _attributes: Vec<CronBlockExpectedState> =
    //             yaml_serde::from_str(raw_attributes).unwrap();
    //     }

    //     #[test]
    //     fn check_rejects_present_without_job() {
    //         let result = CronBlockExpectedState::builder("test")
    //             .with_state(CronExpectedState::Present)
    //             .build();
    //         assert!(result.is_err());
    //     }

    //     #[test]
    //     fn check_rejects_special_time_with_time_fields() {
    //         let result = CronBlockExpectedState::builder("test")
    //             .with_job("/bin/true")
    //             .with_special_time(CronSpecialTime::Daily)
    //             .with_minute("0")
    //             .build();
    //         assert!(result.is_err());
    //     }

    //     #[test]
    //     fn check_accepts_absent_without_job() {
    //         let result = CronBlockExpectedState::builder("test")
    //             .with_state(CronExpectedState::Absent)
    //             .build();
    //         assert!(result.is_ok());
    //     }

    //     #[test]
    //     fn build_cron_line_standard() {
    //         let block = CronBlockExpectedState::builder("test")
    //             .with_job("/usr/bin/backup.sh")
    //             .with_minute("0")
    //             .with_hour("2")
    //             .build()
    //             .unwrap();
    //         assert_eq!(
    //             build_cron_line(&block, false),
    //             "0 2 * * * /usr/bin/backup.sh"
    //         );
    //     }

    //     #[test]
    //     fn build_cron_line_special_time() {
    //         let block = CronBlockExpectedState::builder("test")
    //             .with_job("/usr/bin/backup.sh")
    //             .with_special_time(CronSpecialTime::Daily)
    //             .build()
    //             .unwrap();
    //         assert_eq!(build_cron_line(&block, false), "@daily /usr/bin/backup.sh");
    //     }

    //     #[test]
    //     fn build_cron_line_cron_d_with_user() {
    //         let block = CronBlockExpectedState::builder("test")
    //             .with_job("/usr/bin/backup.sh")
    //             .with_minute("30")
    //             .with_hour("3")
    //             .with_user("backup")
    //             .build()
    //             .unwrap();
    //         assert_eq!(
    //             build_cron_line(&block, true),
    //             "30 3 * * * backup /usr/bin/backup.sh"
    //         );
    //     }

    //     #[test]
    //     fn build_cron_line_disabled() {
    //         let block = CronBlockExpectedState::builder("test")
    //             .with_job("/usr/bin/backup.sh")
    //             .with_minute("0")
    //             .with_hour("1")
    //             .with_disabled(true)
    //             .build()
    //             .unwrap();
    //         assert_eq!(
    //             build_cron_line(&block, false),
    //             "# 0 1 * * * /usr/bin/backup.sh"
    //         );
    //     }

    #[test]
    fn find_cron_entry_found() {
        let content = "# regent: backup\n0 2 * * * /usr/local/bin/backup.sh\n";
        assert_eq!(
            find_cron_entry(content, "backup"),
            Some("0 2 * * * /usr/local/bin/backup.sh".to_string())
        );
    }

    #[test]
    fn find_cron_entry_not_found() {
        let content = "# regent: other\n0 2 * * * /usr/local/bin/other.sh\n";
        assert!(find_cron_entry(content, "backup").is_none());
    }
}
