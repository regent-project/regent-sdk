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
pub enum GroupExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct GroupBlockExpectedState {
    name: String,
    state: Option<GroupExpectedState>,
    gid: Option<u32>,
    system: Option<bool>,
    local: Option<bool>,
}

impl Timeout for GroupBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl GroupBlockExpectedState {
    pub fn builder(groupname: &str) -> GroupBlockExpectedState {
        GroupBlockExpectedState {
            name: groupname.to_string(),
            state: None,
            gid: None,
            system: None,
            local: None,
        }
    }

    pub fn with_state(&mut self, state: GroupExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_gid(&mut self, gid: u32) -> &mut Self {
        self.gid = Some(gid);
        self
    }

    pub fn with_system(&mut self, system: bool) -> &mut Self {
        self.system = Some(system);
        self
    }

    pub fn with_local(&mut self, local: bool) -> &mut Self {
        self.local = Some(local);
        self
    }

    pub fn build(&self) -> Result<GroupBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for GroupBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if let Some(GroupExpectedState::Absent) = &self.state {
            if self.gid.is_some() || self.system.is_some() {
                return Err(RegentError::IncoherentExpectedState(
                    "Gid and System are incompatible with state Absent.".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for GroupBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        let expected_state = self.state.as_ref().unwrap_or(&GroupExpectedState::Present);
        let local = self.local.unwrap_or(false);

        let group_exists = match group_exists(host_handler, &self.name).await {
            Ok(exists) => exists,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        match expected_state {
            GroupExpectedState::Absent => {
                if !group_exists {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::Group(GroupApiCall::from(
                        GroupModuleInternalApiCall::Delete {
                            groupname: self.name.clone(),
                            local,
                        },
                        privilege.clone(),
                    )),
                ]));
            }
            GroupExpectedState::Present => {
                if !group_exists {
                    return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                        Remediation::Group(GroupApiCall::from(
                            GroupModuleInternalApiCall::Add {
                                groupname: self.name.clone(),
                                gid: self.gid,
                                system: self.system.unwrap_or(false),
                                local,
                            },
                            privilege.clone(),
                        )),
                    ]));
                }

                // Group exists: check GID if specified
                if let Some(expected_gid) = self.gid {
                    let current_gid = match get_group_gid(host_handler, &self.name).await {
                        Ok(gid) => gid,
                        Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
                    };
                    if current_gid != expected_gid {
                        return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                            Remediation::Group(GroupApiCall::from(
                                GroupModuleInternalApiCall::ModifyGid {
                                    groupname: self.name.clone(),
                                    gid: expected_gid,
                                },
                                privilege.clone(),
                            )),
                        ]));
                    }
                }

                Ok(AttributeComplianceAssessment::Compliant)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum GroupModuleInternalApiCall {
    Add {
        groupname: String,
        gid: Option<u32>,
        system: bool,
        // Uses lgroupadd/lgroupdel instead of groupadd/groupdel (shadow-utils local commands)
        local: bool,
    },
    ModifyGid {
        groupname: String,
        gid: u32,
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

impl<Handler: HostHandler> ReachCompliance<Handler> for GroupApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let (cmd, privilege) = match &self.api_call {
            GroupModuleInternalApiCall::Add {
                groupname,
                gid,
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
                (
                    format!("{} {} {}", base, args.join(" "), groupname),
                    &self.privilege,
                )
            }
            GroupModuleInternalApiCall::ModifyGid { groupname, gid } => (
                format!("groupmod -g {} {}", gid, groupname),
                &self.privilege,
            ),
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

async fn group_exists<Handler: HostHandler>(
    host_handler: &mut Handler,
    groupname: &str,
) -> Result<bool, String> {
    match host_handler
        .run_command(&format!("getent group {}", groupname), &Privilege::None)
        .await
    {
        Ok(result) => Ok(result.return_code == 0),
        Err(e) => Err(format!("Unable to check if group exists: {:?}", e)),
    }
}

async fn get_group_gid<Handler: HostHandler>(
    host_handler: &mut Handler,
    groupname: &str,
) -> Result<u32, String> {
    match host_handler
        .run_command(&format!("getent group {}", groupname), &Privilege::None)
        .await
    {
        Ok(result) => {
            if result.return_code != 0 {
                return Err(format!("getent group failed for group {}", groupname));
            }
            // Format: groupname:x:gid:members
            let fields: Vec<&str> = result.stdout.trim().splitn(4, ':').collect();
            if fields.len() < 3 {
                return Err(format!(
                    "Unexpected getent group output for {}: {}",
                    groupname, result.stdout
                ));
            }
            fields[2]
                .parse::<u32>()
                .map_err(|e| format!("Invalid GID '{}': {}", fields[2], e))
        }
        Err(e) => Err(format!(
            "Unable to get GID for group {}: {:?}",
            groupname, e
        )),
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

- Name: oldgroup
  State: !Absent
        ";

        let _attributes: Vec<GroupBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();
    }

    #[test]
    fn check_rejects_absent_with_gid() {
        let result = GroupBlockExpectedState::builder("testgroup")
            .with_state(GroupExpectedState::Absent)
            .with_gid(1500)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_rejects_absent_with_system() {
        let result = GroupBlockExpectedState::builder("testgroup")
            .with_state(GroupExpectedState::Absent)
            .with_system(true)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_absent_with_local() {
        let result = GroupBlockExpectedState::builder("testgroup")
            .with_state(GroupExpectedState::Absent)
            .with_local(true)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_present_with_all_properties() {
        let result = GroupBlockExpectedState::builder("testgroup")
            .with_state(GroupExpectedState::Present)
            .with_gid(1500)
            .with_system(false)
            .with_local(false)
            .build();
        assert!(result.is_ok());
    }
}
