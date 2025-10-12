use crate::connection::connectionmode::localhost::WhichUser;
use crate::connection::connectionmode::ssh2mode::Ssh2AuthMode;
use crate::connection::specification::Credentials;
use pem::Pem;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum HostConnectionInfo {
    Unset,
    LocalHost(WhichUser),
    Ssh2(Ssh2AuthMode),
    // Ssh3
}

impl HostConnectionInfo {
    /// Commands will be run locally as the current user (user used to run the program calling this method)
    pub fn localhost_current_user() -> HostConnectionInfo {
        HostConnectionInfo::LocalHost(WhichUser::CurrentUser)
    }

    /// Commands will be run locally as this given user. Password is optional for passwordless cases.
    pub fn localhost_as_user(username: String, password: Option<String>) -> HostConnectionInfo {
        match password {
            Some(password_content) => HostConnectionInfo::LocalHost(WhichUser::UsernamePassword(
                Credentials::from(username, password_content),
            )),
            None => HostConnectionInfo::LocalHost(WhichUser::PasswordLessUser(username)),
        }
    }

    /// Commands will be run on a remote host through SSH2, with username/password authentication
    pub fn ssh2_with_username_password(username: String, password: String) -> HostConnectionInfo {
        HostConnectionInfo::Ssh2(Ssh2AuthMode::UsernamePassword(Credentials::from(
            username, password,
        )))
    }

    /// Commands will be run on a remote host through SSH2, using a key
    pub fn ssh2_with_key_file(username: &str, key_file_path: &str) -> HostConnectionInfo {
        HostConnectionInfo::Ssh2(Ssh2AuthMode::KeyFile((
            username.to_string(),
            PathBuf::from(key_file_path),
        )))
    }

    /// Commands will be run on a remote host through SSH2, using an in-memory pem key
    pub fn ssh2_with_key_in_memory(username: String, key_content: Pem) -> HostConnectionInfo {
        HostConnectionInfo::Ssh2(Ssh2AuthMode::KeyMemory((username, key_content)))
    }

    /// Commands will be run on a remote host through SSH2, using SSH agent
    pub fn ssh2_with_agent(agent_name: String) -> HostConnectionInfo {
        HostConnectionInfo::Ssh2(Ssh2AuthMode::Agent(agent_name))
    }
}
