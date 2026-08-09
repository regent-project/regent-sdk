//! Group management attribute
//!
//! This module provides the `GroupBlockExpectedState` type for managing Unix system groups
//! using the groupadd, groupmod, and groupdel commands (or lgroupadd, lgroupdel for local groups).
//!
//! **Compatible OS:** Linux (all distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::group::{GroupBlockExpectedState, GroupExpectedState};
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Create a group with a specific GID
//! let developers = GroupBlockExpectedState::present("developers", Some(1500), Some(vec!["daniel".to_string(), "chris".to_string()]), None, None);
//!
//!
//! let group_cleaning = GroupBlockExpectedState::absent("oldgroup", None);
//! ```
//!
//! ## YAML API
//!
//! ```yaml
//! Attributes:
//!   - Name: Developers group must be present
//!     Privilege: !WithSudo
//!     Detail: !Group
//!       Name: developers
//!       State: !Present
//!         Gid: 1500
//!         Members:
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

/// Desired state of a group
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum GroupExpectedState {
    Absent,
    /// Group should exist
    #[serde(rename_all = "PascalCase")]
    Present {
        /// Group ID to assign (optional)
        gid: Option<u32>,
        /// List of users that should be members of this group
        members: Option<Vec<String>>,
        /// Whether this is a system group (uses -r flag with groupadd)
        system: Option<bool>,
    },
}

/// Configuration for a system group
///
/// Use the builder pattern to create group configurations. Each group must have a name.
/// You can specify the desired state (Present/Absent), GID, and whether it's a system or local group.
///
/// When state is Absent, gid and system fields are not allowed.
/// When state is Present (or None, which defaults to Present), you can optionally specify:
/// - gid: The numeric group ID
/// - system: Whether to create a system group (uses -r flag)
/// - local: Whether to use local commands (lgroupadd/lgroupdel instead of groupadd/groupdel)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct GroupBlockExpectedState {
    /// Unique name of the group
    name: String,
    /// Desired state of the group
    state: GroupExpectedState,
    /// Whether to use local commands (lgroupadd/lgroupdel) instead of system commands
    local: Option<bool>,
}

impl Timeout for GroupBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl GroupBlockExpectedState {
    pub fn absent(name: &str, local: Option<bool>) -> GroupBlockExpectedState {
        GroupBlockExpectedState {
            name: name.to_string(),
            state: GroupExpectedState::Absent,
            local,
        }
    }

    pub fn present(
        name: &str,
        gid: Option<u32>,
        members: Option<Vec<String>>,
        system: Option<bool>,
        local: Option<bool>,
    ) -> GroupBlockExpectedState {
        GroupBlockExpectedState {
            name: name.to_string(),
            state: GroupExpectedState::Present {
                gid,
                members,
                system,
            },
            local,
        }
    }
}

impl Check for GroupBlockExpectedState {
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
                "Host is {:?} but group management is only supported on Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for GroupBlockExpectedState {
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

        let local = self.local.unwrap_or(false);

        let opt_group_info = match get_group_info(host_handler, &self.name).await {
            Ok(opt_group_info) => opt_group_info,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        let mut remediations: Vec<Remediation> = Vec::new();

        match &self.state {
            GroupExpectedState::Absent => {
                if let Some(_group_info) = opt_group_info {
                    remediations.push(Remediation::Group(GroupApiCall::from(
                        GroupModuleInternalApiCall::Delete {
                            groupname: self.name.clone(),
                            local,
                        },
                        privilege.clone(),
                    )));
                };
            }
            GroupExpectedState::Present {
                gid,
                members,
                system,
            } => {
                match opt_group_info {
                    Some(current_group_info) => {
                        // Group exists: check GID if specified
                        if let Some(expected_gid) = gid {
                            if current_group_info.gid != *expected_gid {
                                return Ok(AttributeComplianceAssessment::NonCompliant(
                                    RemediationsList::from(vec![Remediation::Group(
                                        GroupApiCall::from(
                                            GroupModuleInternalApiCall::ModifyGid {
                                                groupname: self.name.clone(),
                                                gid: *expected_gid,
                                            },
                                            privilege.clone(),
                                        ),
                                    )])
                                    .unwrap(),
                                ));
                            }
                        }

                        // Group exists: check members if specified
                        if let Some(expected_members) = members {
                            // Sort both lists for comparison (order doesn't matter for group members)
                            let mut expected_sorted = expected_members.clone();
                            let mut current_sorted = current_group_info.members.clone();
                            expected_sorted.sort();
                            current_sorted.sort();

                            if expected_sorted != current_sorted {
                                remediations.push(Remediation::Group(GroupApiCall::from(
                                    GroupModuleInternalApiCall::ModifyMembers {
                                        groupname: self.name.clone(),
                                        members: expected_members.clone(),
                                    },
                                    privilege.clone(),
                                )));
                            }
                        }
                    }
                    None => {
                        remediations.push(Remediation::Group(GroupApiCall::from(
                            GroupModuleInternalApiCall::Add {
                                groupname: self.name.clone(),
                                gid: *gid,
                                members: members.clone(),
                                system: system.unwrap_or(false),
                                local,
                            },
                            privilege.clone(),
                        )));
                    }
                }
            }
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

/// Internal API calls for group management
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum GroupModuleInternalApiCall {
    /// Create a new group
    Add {
        groupname: String,
        gid: Option<u32>,
        members: Option<Vec<String>>,
        system: bool,
        /// Uses lgroupadd instead of groupadd (shadow-utils local command)
        local: bool,
    },
    /// Modify an existing group's GID
    ModifyGid { groupname: String, gid: u32 },
    /// Modify an existing group's members
    ModifyMembers {
        groupname: String,
        members: Vec<String>,
    },
    /// Remove a group
    Delete { groupname: String, local: bool },
}

impl std::fmt::Display for GroupModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupModuleInternalApiCall::Add { groupname, .. } => {
                write!(f, "add group {}", groupname)
            }
            GroupModuleInternalApiCall::ModifyGid { groupname, gid } => {
                write!(f, "modify group {} gid to {}", groupname, gid)
            }
            GroupModuleInternalApiCall::ModifyMembers { groupname, members } => {
                write!(f, "modify group {} members to {:?}", groupname, members)
            }
            GroupModuleInternalApiCall::Delete { groupname, .. } => {
                write!(f, "delete group {}", groupname)
            }
        }
    }
}

/// A group API call with its associated privilege level
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupApiCall {
    /// The internal API call to execute
    pub api_call: GroupModuleInternalApiCall,
    /// Privilege level required for this call
    privilege: Privilege,
}

impl GroupApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            GroupModuleInternalApiCall::Add { groupname, .. } => {
                format!("Add group {}", groupname)
            }
            GroupModuleInternalApiCall::ModifyGid { groupname, gid } => {
                format!("Modify group {} GID to {}", groupname, gid)
            }
            GroupModuleInternalApiCall::ModifyMembers { groupname, members } => {
                format!("Modify group {} members to {:?}", groupname, members)
            }
            GroupModuleInternalApiCall::Delete { groupname, .. } => {
                format!("Delete group {}", groupname)
            }
        }
    }

    fn from(api_call: GroupModuleInternalApiCall, privilege: Privilege) -> GroupApiCall {
        GroupApiCall {
            api_call,
            privilege,
        }
    }
}

impl Check for GroupApiCall {
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
                "Host is {:?} but group management is only supported on Linux",
                incompatible_os_kind
            ))),
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for GroupApiCall {
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
            GroupModuleInternalApiCall::Add {
                groupname,
                gid,
                members,
                system,
                local,
            } => {
                let base = if *local { "lgroupadd" } else { "groupadd" };
                let mut args: Vec<String> = Vec::new();
                if let Some(g) = gid {
                    args.push(format!("-g {}", g));
                }
                if *system {
                    args.push("-r".to_string());
                }

                let mut cmds = Vec::new();
                // Create the group
                cmds.push(format!("{} {} {}", base, args.join(" "), groupname));

                // Add members if specified
                if let Some(member_list) = members {
                    for member in member_list {
                        cmds.push(format!("usermod -aG {} {}", groupname, member));
                    }
                }

                (cmds.join(" && "), &self.privilege)
            }
            GroupModuleInternalApiCall::ModifyGid { groupname, gid } => (
                format!("groupmod -g {} {}", gid, groupname),
                &self.privilege,
            ),
            GroupModuleInternalApiCall::ModifyMembers { groupname, members } => {
                // Get current members to calculate differences
                let current_members = match get_group_info(host_handler, groupname).await {
                    Ok(opt_group_info) => match opt_group_info {
                        Some(group_info) => group_info.members,
                        None => {
                            return Ok(InternalApiCallOutcome::Failure(format!(
                                "Failed to get current group members: group does not exist anymore"
                            )));
                        }
                    },
                    Err(e) => {
                        return Ok(InternalApiCallOutcome::Failure(format!(
                            "Failed to get current group members: {}",
                            e
                        )));
                    }
                };

                // Convert to sets for easier difference calculation
                use std::collections::HashSet;
                let expected_set: HashSet<&str> = members.iter().map(|s| s.as_str()).collect();
                let current_set: HashSet<&str> =
                    current_members.iter().map(|s| s.as_str()).collect();

                // Calculate users to add and remove
                let users_to_add: Vec<&str> =
                    expected_set.difference(&current_set).cloned().collect();
                let users_to_remove: Vec<&str> =
                    current_set.difference(&expected_set).cloned().collect();

                let mut cmds = Vec::new();

                // Add users who should be in the group but aren't
                for user in users_to_add {
                    cmds.push(format!("usermod -aG {} {}", groupname, user));
                }

                // Remove users who shouldn't be in the group
                // Note: Removing users from a group requires gpasswd or similar
                // For now, we'll use gpasswd --delete to remove users
                for user in users_to_remove {
                    cmds.push(format!("gpasswd --delete {} {}", user, groupname));
                }

                if cmds.is_empty() {
                    // No changes needed
                    return Ok(InternalApiCallOutcome::Success(None));
                }

                (cmds.join(" && "), &self.privilege)
            }
            GroupModuleInternalApiCall::Delete { groupname, local } => {
                let base = if *local { "lgroupdel" } else { "groupdel" };
                (format!("{} {}", base, groupname), &self.privilege)
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

struct Group {
    name: String,
    gid: u32,
    members: Vec<String>,
}

async fn get_group_info<Handler: HostHandler>(
    host_handler: &mut Handler,
    groupname: &str,
) -> Result<Option<Group>, String> {
    match host_handler
        .run_command(&format!("getent group {}", groupname), &Privilege::None)
        .await
    {
        Ok(result) => {
            if result.return_code == 0 {
                // Group exists
                // Format: groupname:x:gid:members
                let fields: Vec<&str> = result.stdout.trim().splitn(4, ':').collect();
                if fields.len() < 4 {
                    return Err(format!(
                        "Unexpected getent group output for {}: {}",
                        groupname, result.stdout
                    ));
                }
                let gid = match fields[2].parse::<u32>() {
                    Ok(gid) => gid,
                    Err(e) => {
                        return Err(format!("Invalid GID '{}': {}", fields[2], e));
                    }
                };
                let members = fields[3]
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().to_string())
                    .collect();

                Ok(Some(Group {
                    name: groupname.to_string(),
                    gid,
                    members,
                }))
            } else {
                // Group does not exist
                Ok(None)
            }
        }
        Err(e) => Err(format!("Unable to check if group exists: {:?}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_group_module_block_from_yaml_str() {
        let raw_attributes = "---
- Name: developers
  State: !Present
    Gid: 1500
    Members:
        - daniel
        - chris

- Name: oldgroup
  State: !Absent
        ";

        let attributes: Vec<GroupBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();

        println!("{:#?}", attributes);
    }
}
