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
pub enum UserExpectedState {
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct UserBlockExpectedState {
    name: String,
    state: Option<UserExpectedState>,
    uid: Option<u32>,
    group: Option<String>,
    groups: Option<Vec<String>>,
    append: Option<bool>,
    shell: Option<String>,
    home: Option<String>,
    comment: Option<String>,
    password: Option<String>,
    system: Option<bool>,
    create_home: Option<bool>,
    remove_home: Option<bool>,
}

impl Timeout for UserBlockExpectedState {
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

impl UserBlockExpectedState {
    pub fn builder(username: &str) -> UserBlockExpectedState {
        UserBlockExpectedState {
            name: username.to_string(),
            state: None,
            uid: None,
            group: None,
            groups: None,
            append: None,
            shell: None,
            home: None,
            comment: None,
            password: None,
            system: None,
            create_home: None,
            remove_home: None,
        }
    }

    pub fn with_state(&mut self, state: UserExpectedState) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn with_uid(&mut self, uid: u32) -> &mut Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_group(&mut self, group: &str) -> &mut Self {
        self.group = Some(group.to_string());
        self
    }

    pub fn with_groups(&mut self, groups: Vec<String>) -> &mut Self {
        self.groups = Some(groups);
        self
    }

    pub fn with_append(&mut self, append: bool) -> &mut Self {
        self.append = Some(append);
        self
    }

    pub fn with_shell(&mut self, shell: &str) -> &mut Self {
        self.shell = Some(shell.to_string());
        self
    }

    pub fn with_home(&mut self, home: &str) -> &mut Self {
        self.home = Some(home.to_string());
        self
    }

    pub fn with_comment(&mut self, comment: &str) -> &mut Self {
        self.comment = Some(comment.to_string());
        self
    }

    pub fn with_password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }

    pub fn with_system(&mut self, system: bool) -> &mut Self {
        self.system = Some(system);
        self
    }

    pub fn with_create_home(&mut self, create_home: bool) -> &mut Self {
        self.create_home = Some(create_home);
        self
    }

    pub fn with_remove_home(&mut self, remove_home: bool) -> &mut Self {
        self.remove_home = Some(remove_home);
        self
    }

    pub fn build(&self) -> Result<UserBlockExpectedState, RegentError> {
        self.check()?;
        Ok(self.clone())
    }
}

impl Check for UserBlockExpectedState {
    fn check(&self) -> Result<(), RegentError> {
        if let Some(UserExpectedState::Absent) = &self.state {
            let has_incompatible = self.uid.is_some()
                || self.group.is_some()
                || self.groups.is_some()
                || self.append.is_some()
                || self.shell.is_some()
                || self.home.is_some()
                || self.comment.is_some()
                || self.password.is_some()
                || self.system.is_some()
                || self.create_home.is_some();
            if has_incompatible {
                return Err(RegentError::IncoherentExpectedState(
                    "User property specifications are incompatible with state Absent.".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl<Handler: HostHandler> AssessCompliance<Handler> for UserBlockExpectedState {
    async fn assess_compliance(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        privilege: &Privilege,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<AttributeComplianceAssessment, RegentError> {
        let expected_state = self.state.as_ref().unwrap_or(&UserExpectedState::Present);

        let user_exists = match user_exists(host_handler, &self.name).await {
            Ok(exists) => exists,
            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
        };

        match expected_state {
            UserExpectedState::Absent => {
                if !user_exists {
                    return Ok(AttributeComplianceAssessment::Compliant);
                }
                return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                    Remediation::User(UserApiCall::from(
                        UserModuleInternalApiCall::Delete {
                            username: self.name.clone(),
                            remove_home: self.remove_home.unwrap_or(false),
                        },
                        privilege.clone(),
                    )),
                ]));
            }
            UserExpectedState::Present => {
                if !user_exists {
                    return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                        Remediation::User(UserApiCall::from(
                            UserModuleInternalApiCall::Add {
                                username: self.name.clone(),
                                uid: self.uid,
                                group: self.group.clone(),
                                groups: self.groups.clone(),
                                shell: self.shell.clone(),
                                home: self.home.clone(),
                                comment: self.comment.clone(),
                                password: self.password.clone(),
                                system: self.system.unwrap_or(false),
                                create_home: self.create_home.unwrap_or(true),
                            },
                            privilege.clone(),
                        )),
                    ]));
                }

                // User exists: determine which properties need updating
                let mut mod_uid: Option<u32> = None;
                let mut mod_group: Option<String> = None;
                let mut mod_groups: Option<Vec<String>> = None;
                let mut mod_shell: Option<String> = None;
                let mut mod_home: Option<String> = None;
                let mut mod_comment: Option<String> = None;
                // Password hash cannot be read without root access; always enforce if specified.
                let mod_password = self.password.clone();
                let append = self.append.unwrap_or(false);

                let passwd_entry = match get_passwd_entry(host_handler, &self.name).await {
                    Ok(entry) => entry,
                    Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
                };

                if let Some(expected_uid) = self.uid {
                    if passwd_entry.uid != expected_uid {
                        mod_uid = Some(expected_uid);
                    }
                }

                if let Some(ref expected_shell) = self.shell {
                    if &passwd_entry.shell != expected_shell {
                        mod_shell = Some(expected_shell.clone());
                    }
                }

                if let Some(ref expected_home) = self.home {
                    if &passwd_entry.home != expected_home {
                        mod_home = Some(expected_home.clone());
                    }
                }

                if let Some(ref expected_comment) = self.comment {
                    if &passwd_entry.comment != expected_comment {
                        mod_comment = Some(expected_comment.clone());
                    }
                }

                if let Some(ref expected_group) = self.group {
                    let current_group = match get_primary_group(host_handler, &self.name).await {
                        Ok(g) => g,
                        Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
                    };
                    if &current_group != expected_group {
                        mod_group = Some(expected_group.clone());
                    }
                }

                if let Some(ref expected_groups) = self.groups {
                    let current_supp_groups =
                        match get_supplementary_groups(host_handler, &self.name).await {
                            Ok(g) => g,
                            Err(e) => return Err(RegentError::FailedDryRunEvaluation(e)),
                        };

                    let groups_compliant = if append {
                        // All expected groups must already be present
                        expected_groups
                            .iter()
                            .all(|g| current_supp_groups.contains(g))
                    } else {
                        // Exact match required
                        let mut expected_sorted = expected_groups.clone();
                        let mut current_sorted = current_supp_groups.clone();
                        expected_sorted.sort();
                        current_sorted.sort();
                        expected_sorted == current_sorted
                    };

                    if !groups_compliant {
                        mod_groups = Some(expected_groups.clone());
                    }
                }

                let needs_modification = mod_uid.is_some()
                    || mod_group.is_some()
                    || mod_groups.is_some()
                    || mod_shell.is_some()
                    || mod_home.is_some()
                    || mod_comment.is_some()
                    || mod_password.is_some();

                if needs_modification {
                    return Ok(AttributeComplianceAssessment::NonCompliant(vec![
                        Remediation::User(UserApiCall::from(
                            UserModuleInternalApiCall::Modify {
                                username: self.name.clone(),
                                uid: mod_uid,
                                group: mod_group,
                                groups: mod_groups,
                                append,
                                shell: mod_shell,
                                home: mod_home,
                                comment: mod_comment,
                                password: mod_password,
                            },
                            privilege.clone(),
                        )),
                    ]));
                }

                Ok(AttributeComplianceAssessment::Compliant)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum UserModuleInternalApiCall {
    Add {
        username: String,
        uid: Option<u32>,
        group: Option<String>,
        groups: Option<Vec<String>>,
        shell: Option<String>,
        home: Option<String>,
        comment: Option<String>,
        password: Option<String>,
        system: bool,
        create_home: bool,
    },
    Modify {
        username: String,
        uid: Option<u32>,
        group: Option<String>,
        groups: Option<Vec<String>>,
        append: bool,
        shell: Option<String>,
        home: Option<String>,
        comment: Option<String>,
        password: Option<String>,
    },
    Delete {
        username: String,
        remove_home: bool,
    },
}

impl std::fmt::Display for UserModuleInternalApiCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserModuleInternalApiCall::Add { username, .. } => {
                write!(f, "add user {}", username)
            }
            UserModuleInternalApiCall::Modify { username, .. } => {
                write!(f, "modify user {}", username)
            }
            UserModuleInternalApiCall::Delete { username, .. } => {
                write!(f, "delete user {}", username)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserApiCall {
    pub api_call: UserModuleInternalApiCall,
    privilege: Privilege,
}

impl UserApiCall {
    pub fn display(&self) -> String {
        match &self.api_call {
            UserModuleInternalApiCall::Add { username, .. } => format!("Add user {}", username),
            UserModuleInternalApiCall::Modify { username, .. } => {
                format!("Modify user {}", username)
            }
            UserModuleInternalApiCall::Delete { username, .. } => {
                format!("Delete user {}", username)
            }
        }
    }

    fn from(api_call: UserModuleInternalApiCall, privilege: Privilege) -> UserApiCall {
        UserApiCall {
            api_call,
            privilege,
        }
    }
}

impl<Handler: HostHandler> ReachCompliance<Handler> for UserApiCall {
    async fn call(
        &self,
        host_handler: &mut Handler,
        _host_properties: &Option<HostProperties>,
        _optional_secret_provider: &Option<SecretProvidersPool>,
    ) -> Result<InternalApiCallOutcome, RegentError> {
        let (cmd, privilege) = match &self.api_call {
            UserModuleInternalApiCall::Add {
                username,
                uid,
                group,
                groups,
                shell,
                home,
                comment,
                password,
                system,
                create_home,
            } => {
                let mut args: Vec<String> = Vec::new();
                if let Some(u) = uid {
                    args.push(format!("-u {}", u));
                }
                if let Some(g) = group {
                    args.push(format!("-g {}", g));
                }
                if let Some(gs) = groups {
                    if !gs.is_empty() {
                        args.push(format!("-G {}", gs.join(",")));
                    }
                }
                if let Some(s) = shell {
                    args.push(format!("-s {}", s));
                }
                if let Some(h) = home {
                    args.push(format!("-d {}", h));
                }
                if let Some(c) = comment {
                    args.push(format!("-c '{}'", c));
                }
                if let Some(p) = password {
                    args.push(format!("-p '{}'", p));
                }
                if *system {
                    args.push("-r".to_string());
                }
                if *create_home {
                    args.push("-m".to_string());
                } else {
                    args.push("-M".to_string());
                }
                (
                    format!("useradd {} {}", args.join(" "), username),
                    &self.privilege,
                )
            }
            UserModuleInternalApiCall::Modify {
                username,
                uid,
                group,
                groups,
                append,
                shell,
                home,
                comment,
                password,
            } => {
                let mut args: Vec<String> = Vec::new();
                if let Some(u) = uid {
                    args.push(format!("-u {}", u));
                }
                if let Some(g) = group {
                    args.push(format!("-g {}", g));
                }
                if let Some(gs) = groups {
                    // Quote the value to handle empty list (removes all supplementary groups)
                    args.push(format!("-G \"{}\"", gs.join(",")));
                    if *append && !gs.is_empty() {
                        args.push("-a".to_string());
                    }
                }
                if let Some(s) = shell {
                    args.push(format!("-s {}", s));
                }
                if let Some(h) = home {
                    args.push(format!("-d {}", h));
                }
                if let Some(c) = comment {
                    args.push(format!("-c '{}'", c));
                }
                if let Some(p) = password {
                    args.push(format!("-p '{}'", p));
                }
                (
                    format!("usermod {} {}", args.join(" "), username),
                    &self.privilege,
                )
            }
            UserModuleInternalApiCall::Delete {
                username,
                remove_home,
            } => {
                let flags = if *remove_home { "-r " } else { "" };
                (format!("userdel {}{}", flags, username), &self.privilege)
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

struct PasswdEntry {
    uid: u32,
    comment: String,
    home: String,
    shell: String,
}

async fn user_exists<Handler: HostHandler>(
    host_handler: &mut Handler,
    username: &str,
) -> Result<bool, String> {
    match host_handler
        .run_command(&format!("id {}", username), &Privilege::None)
        .await
    {
        Ok(result) => Ok(result.return_code == 0),
        Err(e) => Err(format!("Unable to check if user exists: {:?}", e)),
    }
}

async fn get_passwd_entry<Handler: HostHandler>(
    host_handler: &mut Handler,
    username: &str,
) -> Result<PasswdEntry, String> {
    match host_handler
        .run_command(&format!("getent passwd {}", username), &Privilege::None)
        .await
    {
        Ok(result) => {
            if result.return_code != 0 {
                return Err(format!("getent passwd failed for user {}", username));
            }
            // Format: username:x:uid:gid:comment:home:shell
            let fields: Vec<&str> = result.stdout.trim().splitn(7, ':').collect();
            if fields.len() < 7 {
                return Err(format!(
                    "Unexpected getent passwd output for {}: {}",
                    username, result.stdout
                ));
            }
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|e| format!("Invalid UID '{}': {}", fields[2], e))?;
            Ok(PasswdEntry {
                uid,
                comment: fields[4].to_string(),
                home: fields[5].to_string(),
                shell: fields[6].to_string(),
            })
        }
        Err(e) => Err(format!(
            "Unable to get passwd entry for {}: {:?}",
            username, e
        )),
    }
}

async fn get_primary_group<Handler: HostHandler>(
    host_handler: &mut Handler,
    username: &str,
) -> Result<String, String> {
    match host_handler
        .run_command(&format!("id -gn {}", username), &Privilege::None)
        .await
    {
        Ok(result) => {
            if result.return_code != 0 {
                return Err(format!("id -gn failed for user {}", username));
            }
            Ok(result.stdout.trim().to_string())
        }
        Err(e) => Err(format!(
            "Unable to get primary group for {}: {:?}",
            username, e
        )),
    }
}

async fn get_supplementary_groups<Handler: HostHandler>(
    host_handler: &mut Handler,
    username: &str,
) -> Result<Vec<String>, String> {
    let primary_group = get_primary_group(host_handler, username).await?;

    match host_handler
        .run_command(&format!("id -Gn {}", username), &Privilege::None)
        .await
    {
        Ok(result) => {
            if result.return_code != 0 {
                return Err(format!("id -Gn failed for user {}", username));
            }
            // id -Gn returns all groups (primary + supplementary); subtract primary
            Ok(result
                .stdout
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .filter(|g| g != &primary_group)
                .collect())
        }
        Err(e) => Err(format!(
            "Unable to get supplementary groups for {}: {:?}",
            username, e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_user_module_block_from_yaml_str() {
        let raw_attributes = "---
- Name: alice
  State: !Present
  Shell: /bin/bash
  Comment: Alice Smith
  Groups:
    - sudo
    - docker

- Name: bob
  State: !Absent
        ";

        let _attributes: Vec<UserBlockExpectedState> =
            yaml_serde::from_str(raw_attributes).unwrap();
    }

    #[test]
    fn check_rejects_absent_with_properties() {
        let result = UserBlockExpectedState::builder("testuser")
            .with_state(UserExpectedState::Absent)
            .with_shell("/bin/bash")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn check_accepts_absent_without_properties() {
        let result = UserBlockExpectedState::builder("testuser")
            .with_state(UserExpectedState::Absent)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn check_accepts_present_with_properties() {
        let result = UserBlockExpectedState::builder("testuser")
            .with_state(UserExpectedState::Present)
            .with_uid(1001)
            .with_shell("/bin/bash")
            .with_comment("Test User")
            .build();
        assert!(result.is_ok());
    }
}
