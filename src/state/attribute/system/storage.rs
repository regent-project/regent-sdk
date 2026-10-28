//! Storage monitoring attribute
//!
//! This module provides the `StorageExpectedState` type for monitoring filesystem
//! or mount point storage capacity against configurable thresholds. When the
//! threshold is breached (e.g. disk usage exceeds a percentage), optional cleanup
//! commands are triggered to free up space.
//!
//! **Compatible OS:** Linux (uses `df`)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::storage::{
//!     StorageExpectedState, Threshold,
//! };
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Watch root filesystem: trigger cleanup when usage exceeds 95%
//! let mut storage = StorageExpectedState::watch_filesystem("/", Threshold::PercentUsed(95));
//! storage.with_cleanup(vec![
//!     "docker system prune -af".to_string(),
//!     "journalctl --vacuum-time=3d".to_string(),
//! ]);
//!
//! // Watch a mount point: trigger cleanup when less than 10GB remain
//! let mut storage_mnt = StorageExpectedState::watch_mountpoint(
//!     "/var/lib/docker",
//!     Threshold::AbsoluteAvailable(10_485_760), // 10 GB in 1K blocks
//! );
//! storage_mnt.with_cleanup(vec!["docker system prune -af".to_string()]);
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::storage(storage, Privilege::WithSudo, None))
//!     .build();
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Root filesystem has at least 5% free
//!     Privilege: !WithSudo
//!     Detail: !Storage
//!       Target: !FileSystem /
//!       Threshold: !PercentUsed 95
//!       Cleanup:
//!         - docker system prune -af
//!         - journalctl --vacuum-time=3d
//! ```

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
use tracing::info;

/// Threshold that triggers the storage watch when breached.
///
/// Values are compared against `df --output=pcent,used,avail` results.
/// `used` and `avail` are expressed in 1K blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Threshold {
    /// `PercentUsed(95)` triggers when 95% or more of the storage is used
    PercentUsed(u8),
    /// Trigger when the used space (in 1K blocks, from `df --output=used`) is greater than or equal to this value.
    AbsoluteUsed(u64),
    /// Trigger when the percentage of the remaining available space is less than or equal to this value.
    PercentAvailable(u8),
    /// Trigger when the remaining available space (in 1K blocks, from `df --output=avail`) is less than or equal to this value.
    AbsoluteAvailable(u64),
}

/// Target of the storage watch: either a filesystem path or a mount point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageTarget {
    /// A filesystem path (e.g. `/`, `/var`).
    FileSystem(String),
    /// A mount point path (e.g. `/mnt/data`).
    MountPoint(String),
}

impl StorageTarget {
    fn path(&self) -> &str {
        match self {
            StorageTarget::FileSystem(p) => p,
            StorageTarget::MountPoint(p) => p,
        }
    }
}

/// Expected state for storage monitoring on a filesystem or mount point.
///
/// When the storage usage breaches the configured [`Threshold`], the optional
/// cleanup commands are executed one by one to free up space.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StorageExpectedState {
    target: StorageTarget,
    threshold: Threshold,
    /// List of shell commands, executed sequentially, to clean up storage
    cleanup: Option<Vec<String>>,
}

impl Timeout for StorageExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

impl StorageExpectedState {
    /// Watch a filesystem path (e.g. `/`, `/var`) against a threshold.
    pub fn watch_filesystem(fs: &str, threshold: Threshold) -> StorageExpectedState {
        StorageExpectedState {
            target: StorageTarget::FileSystem(fs.to_string()),
            threshold,
            cleanup: None,
        }
    }

    /// Watch a mount point path (e.g. `/mnt/data`) against a threshold.
    pub fn watch_mountpoint(mountpoint: &str, threshold: Threshold) -> StorageExpectedState {
        StorageExpectedState {
            target: StorageTarget::MountPoint(mountpoint.to_string()),
            threshold,
            cleanup: None,
        }
    }

    /// Attach cleanup commands to run when the threshold is breached.
    pub fn with_cleanup(&mut self, cleanup: Vec<String>) {
        self.cleanup = Some(cleanup);
    }
}

impl Check for StorageExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            _ => Err(RegentError::IncompatibleHost(format!(
                "Storage management is only supported on Linux (df)",
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for StorageExpectedState {
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

        // Verify that `df` is available on the host
        let df_available = host_handler
            .is_this_command_available("df", privilege)
            .await
            .unwrap_or(false);

        if !df_available {
            return Err(RegentError::FailedDryRunEvaluation(
                "Storage management command (df) is not available on this host".to_string(),
            ));
        }

        let path = self.target.path();

        // Run df to get usage percentage, used (1K blocks), and available (1K blocks)
        let cmd = format!("df --output=pcent,used,avail {}", path);
        let result = host_handler.run_command(&cmd, privilege).await?;

        if result.return_code != 0 {
            return Err(RegentError::FailedTaskDryRun(format!(
                "Unable to check storage usage for {}: RC: {}, STDOUT: {}, STDERR: {}",
                path, result.return_code, result.stdout, result.stderr
            )));
        }

        // Parse df output: header line then data line
        // Example:
        //   Use%  Used  Avail
        //    45% 12345 67890
        let lines: Vec<&str> = result.stdout.lines().collect();
        if lines.len() < 2 {
            return Err(RegentError::FailedTaskDryRun(format!(
                "Unexpected df output for {}: {}",
                path, result.stdout
            )));
        }

        let data_line = lines[1].trim();
        let fields: Vec<&str> = data_line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(RegentError::FailedTaskDryRun(format!(
                "Unable to parse df output for {}: {}",
                path, result.stdout
            )));
        }

        // Parse percentage (strip trailing '%')
        let pcent_str = fields[0].trim_end_matches('%');
        let pcent: u8 = pcent_str.parse().map_err(|_| {
            RegentError::FailedTaskDryRun(format!(
                "Unable to parse usage percentage from df output: {}",
                fields[0]
            ))
        })?;

        // Parse used and available (in 1K blocks)
        let used: u64 = fields[1].parse().map_err(|_| {
            RegentError::FailedTaskDryRun(format!(
                "Unable to parse used blocks from df output: {}",
                fields[1]
            ))
        })?;

        let avail: u64 = fields[2].parse().map_err(|_| {
            RegentError::FailedTaskDryRun(format!(
                "Unable to parse available blocks from df output: {}",
                fields[2]
            ))
        })?;

        // Check if the threshold is breached
        let breached = match &self.threshold {
            Threshold::PercentUsed(limit) => pcent >= *limit,
            Threshold::AbsoluteUsed(limit) => used >= *limit,
            Threshold::PercentAvailable(limit) => (100 - pcent) <= *limit,
            Threshold::AbsoluteAvailable(limit) => avail <= *limit,
        };

        if breached {
            if let Some(cleanup_cmds) = &self.cleanup {
                if !cleanup_cmds.is_empty() {
                    let remediation = Remediation::Storage(StorageApiCall::from(
                        StorageModuleInternalApiCall::from(cleanup_cmds.clone()),
                        self.target.clone(),
                        self.threshold.clone(),
                        privilege.clone(),
                    ));
                    return Ok(AttributeComplianceAssessment::NonCompliant(
                        RemediationsList::from(vec![remediation])?,
                    ));
                }
            }
            // Threshold breached but no cleanup commands: report as non-compliant fatal
            // since there is nothing actionable to remediate
            return Ok(AttributeComplianceAssessment::NonCompliantFatal(format!(
                "Storage threshold breached for {} (use%: {}%, used: {}K, avail: {}K) but no cleanup commands configured",
                path, pcent, used, avail
            )));
        }

        Ok(AttributeComplianceAssessment::Compliant)
    }
}

/// Internal API call representation for the storage module.
///
/// Holds the list of cleanup commands to execute when the storage threshold is breached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StorageModuleInternalApiCall {
    cleanup: Vec<String>,
}

impl std::fmt::Display for StorageModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Clean up with {:?}", self.cleanup)
    }
}

impl StorageModuleInternalApiCall {
    fn from(cleanup: Vec<String>) -> StorageModuleInternalApiCall {
        StorageModuleInternalApiCall { cleanup }
    }
}

impl Check for StorageModuleInternalApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            _ => Err(RegentError::IncompatibleHost(format!(
                "Storage management is only supported on Linux (df)",
            ))),
        }
    }
}

/// API call for the storage module: executes cleanup commands one by one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageApiCall {
    target: StorageTarget,
    threshold: Threshold,
    pub api_call: StorageModuleInternalApiCall,
    privilege: Privilege,
}

impl StorageApiCall {
    pub fn display(&self) -> String {
        format!("Run storage cleanup commands: {:?}", self.api_call.cleanup)
    }

    fn from(
        api_call: StorageModuleInternalApiCall,
        target: StorageTarget,
        threshold: Threshold,
        privilege: Privilege,
    ) -> StorageApiCall {
        StorageApiCall {
            target,
            threshold,
            api_call,
            privilege,
        }
    }
}

impl Check for StorageApiCall {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            _ => Err(RegentError::IncompatibleHost(format!(
                "Storage management is only supported on Linux (df)",
            ))),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for StorageApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        // Run each cleanup command one by one
        for cmd in &self.api_call.cleanup {
            let result = host_handler.run_command(cmd, &self.privilege).await;

            match result {
                Ok(r) => {
                    if r.return_code != 0 {
                        return Ok(InternalApiCallOutcome::Failure(format!(
                            "Cleanup command '{}' failed - RC: {}, STDOUT: {}, STDERR: {}",
                            cmd, r.return_code, r.stdout, r.stderr
                        )));
                    }
                }
                Err(e) => {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "Cleanup command '{}' execution failed: {:?}",
                        cmd, e
                    )));
                }
            }
        }

        // Check that the clean up commands did their job and compliance is actually reached
        // Run df to get usage percentage, used (1K blocks), and available (1K blocks)
        let cmd = format!("df --output=pcent,used,avail {}", self.target.path());
        let result = host_handler.run_command(&cmd, &self.privilege).await?;

        if result.return_code != 0 {
            return Err(RegentError::FailedTaskDryRun(format!(
                "Unable to check storage usage for {}: RC: {}, STDOUT: {}, STDERR: {}",
                self.target.path(),
                result.return_code,
                result.stdout,
                result.stderr
            )));
        }

        // Parse output the same way the assesment step does
        let lines: Vec<&str> = result.stdout.lines().collect();
        if lines.len() < 2 {
            return Err(RegentError::FailedTaskDryRun(format!(
                "Unexpected df output for {}: {}",
                self.target.path(),
                result.stdout
            )));
        }

        let data_line = lines[1].trim();
        let fields: Vec<&str> = data_line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(RegentError::FailedTaskDryRun(format!(
                "Unable to parse df output for {}: {}",
                self.target.path(),
                result.stdout
            )));
        }

        // Parse percentage (strip trailing '%')
        let pcent_str = fields[0].trim_end_matches('%');
        let pcent: u8 = pcent_str.parse().map_err(|_| {
            RegentError::FailedTaskDryRun(format!(
                "Unable to parse usage percentage from df output: {}",
                fields[0]
            ))
        })?;

        // Parse used and available (in 1K blocks)
        let used: u64 = fields[1].parse().map_err(|_| {
            RegentError::FailedTaskDryRun(format!(
                "Unable to parse used blocks from df output: {}",
                fields[1]
            ))
        })?;

        let avail: u64 = fields[2].parse().map_err(|_| {
            RegentError::FailedTaskDryRun(format!(
                "Unable to parse available blocks from df output: {}",
                fields[2]
            ))
        })?;

        // Check if the threshold is breached
        let fixed = match &self.threshold {
            Threshold::PercentUsed(limit) => pcent <= *limit,
            Threshold::AbsoluteUsed(limit) => used <= *limit,
            Threshold::PercentAvailable(limit) => (100 - pcent) >= *limit,
            Threshold::AbsoluteAvailable(limit) => avail >= *limit,
        };

        info!(pcent, used, avail, fixed);

        if fixed {
            Ok(InternalApiCallOutcome::Success(None))
        } else {
            let details: String = match &self.threshold {
                Threshold::PercentUsed(limit) => format!(
                    "Current PercentUsed ({}%) still above threshold ({}%)",
                    pcent, limit
                ),
                Threshold::AbsoluteUsed(limit) => format!(
                    "Current AbsoluteUsed ({}%) still above threshold ({}%)",
                    used, limit
                ),
                Threshold::PercentAvailable(limit) => format!(
                    "Current PercentAvailable ({}%) still below threshold ({}%)",
                    (100 - pcent),
                    limit
                ),
                Threshold::AbsoluteAvailable(limit) => format!(
                    "Current AbsoluteAvailable ({}%) still below threshold ({}%)",
                    avail, limit
                ),
            };
            Ok(InternalApiCallOutcome::Failure(details))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_storage_module_block_from_yaml_str() {
        let raw = "---
Target: !FileSystem /
Threshold: !PercentUsed 95
Cleanup:
  - docker system prune -af
  - journalctl --vacuum-time=3d
";
        let storage: StorageExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(storage.target, StorageTarget::FileSystem("/".to_string()));
        assert_eq!(storage.threshold, Threshold::PercentUsed(95));
        assert_eq!(
            storage.cleanup,
            Some(vec![
                "docker system prune -af".to_string(),
                "journalctl --vacuum-time=3d".to_string(),
            ])
        );
    }

    #[test]
    fn parsing_storage_mountpoint_with_absolute_remaining() {
        let raw = "---
Target: !MountPoint /var/lib/docker
Threshold: !AbsoluteAvailable 10485760
";
        let storage: StorageExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(
            storage.target,
            StorageTarget::MountPoint("/var/lib/docker".to_string())
        );
        assert_eq!(storage.threshold, Threshold::AbsoluteAvailable(10485760));
        assert_eq!(storage.cleanup, None);
    }

    #[test]
    fn parsing_storage_with_absolute_used() {
        let raw = "---
Target: !FileSystem /data
Threshold: !AbsoluteUsed 51200000
";
        let storage: StorageExpectedState = yaml_serde::from_str(raw).unwrap();
        assert_eq!(
            storage.target,
            StorageTarget::FileSystem("/data".to_string())
        );
        assert_eq!(storage.threshold, Threshold::AbsoluteUsed(51200000));
    }

    #[test]
    fn builder_watch_filesystem() {
        let storage = StorageExpectedState::watch_filesystem("/", Threshold::PercentUsed(90));
        assert_eq!(storage.target, StorageTarget::FileSystem("/".to_string()));
        assert_eq!(storage.threshold, Threshold::PercentUsed(90));
        assert!(storage.cleanup.is_none());
    }

    #[test]
    fn builder_watch_mountpoint_with_cleanup() {
        let mut storage =
            StorageExpectedState::watch_mountpoint("/mnt/data", Threshold::AbsoluteAvailable(1024));
        storage.with_cleanup(vec!["rm -rf /mnt/data/tmp/*".to_string()]);
        assert_eq!(
            storage.target,
            StorageTarget::MountPoint("/mnt/data".to_string())
        );
        assert_eq!(
            storage.cleanup,
            Some(vec!["rm -rf /mnt/data/tmp/*".to_string()])
        );
    }
}
