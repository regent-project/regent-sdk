//! Group management attribute
//!
//! This module provides the `GroupExpectedState` type for managing Unix system groups
//! using the groupadd, groupmod, and groupdel commands (or lgroupadd, lgroupdel for local groups).
//!
//! **Compatible OS:** Linux (all distributions)
//!
//! # Examples
//!
//! ## Rust API
//!
//! ```no_run
//! use regent_sdk::state::attribute::system::group::GroupExpectedState;
//! use regent_sdk::{Attribute, ExpectedState, Privilege};
//!
//! // Create a group with a specific GID
//! let developers = GroupExpectedState::present("developers", Some(1500), Some(vec!["daniel".to_string(), "chris".to_string()]), None, None);
//!
//! let group_cleaning = GroupExpectedState::absent("oldgroup", None);
//!
//! let expected_state = ExpectedState::new()
//!     .with_attribute(Attribute::group(developers, Privilege::WithSudo, None))
//!     .with_attribute(Attribute::group(group_cleaning, Privilege::WithSudo, None))
//!     .build();
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GroupExpectedStatus {
    Absent,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GroupExpectedState {
    name: String,
    state: GroupExpectedStatus,
    /// Whether to use local commands (lgroupadd/lgroupdel) instead of system commands
    local: Option<bool>,
}

impl Timeout for GroupExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl GroupExpectedState {
    pub fn absent(name: &str, local: Option<bool>) -> GroupExpectedState {
        GroupExpectedState {
            name: name.to_string(),
            state: GroupExpectedStatus::Absent,
            local,
        }
    }

    pub fn present(
        name: &str,
        gid: Option<u32>,
        members: Option<Vec<String>>,
        system: Option<bool>,
        local: Option<bool>,
    ) -> GroupExpectedState {
        GroupExpectedState {
            name: name.to_string(),
            state: GroupExpectedStatus::Present {
                gid,
                members,
                system,
            },
            local,
        }
    }
}

impl Check for GroupExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        Ok(())
    }

    fn check_host_compatibility(
        &self,
        host_properties: &HostProperties,
    ) -> Result<(), RegentError> {
        match host_properties.os_kind() {
            OsKind::Linux(_) => Ok(()),
            // local groups (Microsoft.PowerShell.LocalAccounts)
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => {
                let unix_only = match &self.state {
                    GroupExpectedStatus::Present { gid, system, .. } => {
                        gid.is_some() || system.unwrap_or(false)
                    }
                    GroupExpectedStatus::Absent => false,
                } || self.local.unwrap_or(false);
                if unix_only {
                    Err(RegentError::IncoherentExpectedState(format!(
                        "group {}: Gid, System and Local have no meaning on Windows",
                        self.name
                    )))
                } else {
                    Ok(())
                }
            }
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but group management is only supported on Linux and Windows (windows feature)",
                incompatible_os_kind
            ))),
        }
    }
}

/// Whether the host is Windows (feature `windows`).
fn is_windows(host_properties: &Option<HostProperties>) -> bool {
    #[cfg(feature = "windows")]
    if let Some(props) = host_properties {
        return matches!(props.os_kind(), OsKind::Windows(_));
    }
    let _ = host_properties;
    false
}

impl<Handler: HostHandler> AssessCompliance<Handler> for GroupExpectedState {
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

        let local = self.local.unwrap_or(false);

        let info = if is_windows(host_properties) {
            windows_group_info(host_handler, &self.name).await
        } else {
            get_group_info(host_handler, &self.name).await
        };
        let opt_group_info = match info {
            Ok(opt_group_info) => opt_group_info,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        let mut remediations: Vec<Remediation> = Vec::new();

        match &self.state {
            GroupExpectedStatus::Absent => {
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
            GroupExpectedStatus::Present {
                gid,
                members,
                system,
            } => {
                match opt_group_info {
                    Some(current_group_info) => {
                        if let Some(expected_gid) = gid
                            && current_group_info.gid != *expected_gid
                        {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum GroupModuleInternalApiCall {
    Add {
        groupname: String,
        gid: Option<u32>,
        members: Option<Vec<String>>,
        system: bool,
        /// Uses lgroupadd instead of groupadd (shadow-utils local command)
        local: bool,
    },
    ModifyGid {
        groupname: String,
        gid: u32,
    },
    ModifyMembers {
        groupname: String,
        members: Vec<String>,
    },
    Delete {
        groupname: String,
        local: bool,
    },
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupApiCall {
    pub api_call: GroupModuleInternalApiCall,
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
            #[cfg(feature = "windows")]
            OsKind::Windows(_) => Ok(()),
            incompatible_os_kind => Err(RegentError::IncompatibleHost(format!(
                "Host is {:?} but group management is only supported on Linux and Windows (windows feature)",
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
        if let Some(props) = host_properties {
            self.check_host_compatibility(props)?;
        }

        #[cfg(feature = "windows")]
        if is_windows(host_properties) {
            return windows_call(host_handler, &self.api_call).await;
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
                cmds.push(format!("{} {} {}", base, args.join(" "), groupname));

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
                let current_members = match get_group_info(host_handler, groupname).await {
                    Ok(opt_group_info) => {
                        match opt_group_info {
                            Some(group_info) => group_info.members,
                            None => {
                                return Ok(InternalApiCallOutcome::Failure("Failed to get current group members: group does not exist anymore".to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        return Ok(InternalApiCallOutcome::Failure(format!(
                            "Failed to get current group members: {}",
                            e
                        )));
                    }
                };

                use std::collections::HashSet;
                let expected_set: HashSet<&str> = members.iter().map(|s| s.as_str()).collect();
                let current_set: HashSet<&str> =
                    current_members.iter().map(|s| s.as_str()).collect();

                let users_to_add: Vec<&str> =
                    expected_set.difference(&current_set).cloned().collect();
                let users_to_remove: Vec<&str> =
                    current_set.difference(&expected_set).cloned().collect();

                let mut cmds = Vec::new();

                for user in users_to_add {
                    cmds.push(format!("usermod -aG {} {}", groupname, user));
                }

                for user in users_to_remove {
                    cmds.push(format!("gpasswd --delete {} {}", user, groupname));
                }

                if cmds.is_empty() {
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
    #[allow(dead_code)]
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

        let attributes: Vec<GroupExpectedState> = yaml_serde::from_str(raw_attributes).unwrap();

        println!("{:#?}", attributes);
    }
}

#[cfg(feature = "proto")]
#[path = "../../../proto/conv/state__attribute__system__group.rs"]
mod proto_conv;

/// Local group of a Windows host: `None` when it does not exist; members by
/// account name (the `COMPUTER\` or `DOMAIN\` prefix removed).
#[cfg(feature = "windows")]
async fn windows_group_info<Handler: HostHandler>(
    host_handler: &mut Handler,
    groupname: &str,
) -> Result<Option<Group>, String> {
    use crate::hosts::windows::{ps_quote, run_powershell};
    let script = format!(
        "$g = Get-LocalGroup -Name {name} -ErrorAction SilentlyContinue\nif (-not $g) {{ exit 3 }}\nGet-LocalGroupMember -Group {name} | ForEach-Object {{ $_.Name }}",
        name = ps_quote(groupname)
    );
    let result = run_powershell(host_handler, &script)
        .await
        .map_err(|e| format!("Unable to read local group {groupname}: {e:?}"))?;
    match result.return_code {
        0 => Ok(Some(Group {
            name: groupname.to_string(),
            gid: 0,
            members: windows_member_names(&result.stdout),
        })),
        3 => Ok(None),
        code => Err(format!(
            "Unable to read local group {groupname} (exit code {code}): {}",
            result.stderr.trim()
        )),
    }
}

#[cfg(not(feature = "windows"))]
async fn windows_group_info<Handler: HostHandler>(
    _host_handler: &mut Handler,
    _groupname: &str,
) -> Result<Option<Group>, String> {
    Err("Windows hosts need regent-sdk's windows feature".to_string())
}

/// `HOST\alice` -> `alice` (one name per line).
#[cfg_attr(not(feature = "windows"), allow(dead_code))]
fn windows_member_names(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.rsplit('\\').next().unwrap_or(l).to_string())
        .collect()
}

#[cfg(feature = "windows")]
async fn windows_call<Handler: HostHandler>(
    host_handler: &mut Handler,
    api_call: &GroupModuleInternalApiCall,
) -> Result<InternalApiCallOutcome, RegentError> {
    use crate::hosts::windows::{ps_quote, run_powershell};
    let script = match api_call {
        GroupModuleInternalApiCall::Add {
            groupname, members, ..
        } => {
            let mut lines = vec![format!(
                "New-LocalGroup -Name {} | Out-Null",
                ps_quote(groupname)
            )];
            for member in members.iter().flatten() {
                lines.push(format!(
                    "Add-LocalGroupMember -Group {} -Member {}",
                    ps_quote(groupname),
                    ps_quote(member)
                ));
            }
            lines.join("\n")
        }
        GroupModuleInternalApiCall::ModifyGid { groupname, .. } => {
            return Ok(InternalApiCallOutcome::Failure(format!(
                "group {groupname}: Windows groups have no GID"
            )));
        }
        GroupModuleInternalApiCall::ModifyMembers { groupname, members } => {
            let current = match windows_group_info(host_handler, groupname).await {
                Ok(Some(group)) => group.members,
                Ok(None) => {
                    return Ok(InternalApiCallOutcome::Failure(format!(
                        "group {groupname} does not exist anymore"
                    )));
                }
                Err(e) => return Ok(InternalApiCallOutcome::Failure(e)),
            };
            let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
            let mut lines = Vec::new();
            for member in members {
                if !current.iter().any(|c| same(c, member)) {
                    lines.push(format!(
                        "Add-LocalGroupMember -Group {} -Member {}",
                        ps_quote(groupname),
                        ps_quote(member)
                    ));
                }
            }
            for member in &current {
                if !members.iter().any(|m| same(m, member)) {
                    lines.push(format!(
                        "Remove-LocalGroupMember -Group {} -Member {}",
                        ps_quote(groupname),
                        ps_quote(member)
                    ));
                }
            }
            if lines.is_empty() {
                return Ok(InternalApiCallOutcome::Success(None));
            }
            lines.join("\n")
        }
        GroupModuleInternalApiCall::Delete { groupname, .. } => {
            format!("Remove-LocalGroup -Name {}", ps_quote(groupname))
        }
    };
    match run_powershell(host_handler, &script).await {
        Ok(result) if result.return_code == 0 => Ok(InternalApiCallOutcome::Success(None)),
        Ok(result) => Ok(InternalApiCallOutcome::Failure(format!(
            "RC: {}, STDOUT: {}, STDERR: {}",
            result.return_code, result.stdout, result.stderr
        ))),
        Err(e) => Ok(InternalApiCallOutcome::Failure(format!("{e:?}"))),
    }
}

#[cfg(test)]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_member_names_drop_the_domain() {
        assert_eq!(
            windows_member_names("WIN-01\\alice\r\nCORP\\bob\r\n\r\n"),
            vec!["alice", "bob"]
        );
    }
}
