pub mod localhost;
pub mod ssh2;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::Error;
use crate::hosts::handlers::localhost::WhichUser;
use crate::secrets::SecretsManagementSolution;
use crate::{LocalHostHandler, Ssh2HostHandler};
use crate::{command::CommandResult, hosts::privilege::Privilege};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetUserKind {
    CurrentUser,
    User(String),
}

pub struct TargetUser {
    pub user_kind: TargetUserKind,
}

impl TargetUser {
    pub fn current_user() -> Self {
        Self {
            user_kind: TargetUserKind::CurrentUser,
        }
    }

    pub fn user(secret_reference: &str) -> Self {
        Self {
            user_kind: TargetUserKind::User(secret_reference.to_string()),
        }
    }
}

pub enum ConnectionMethod {
    Localhost(TargetUser),
    Ssh2,
}

pub trait HostHandler: Sized {
    fn connect(
        &mut self,
        endpoint: &str,
        secret_provider: &SecretsManagementSolution,
    ) -> Result<(), Error>;

    fn is_connected(&mut self) -> bool;

    fn disconnect(&mut self) -> Result<(), Error>;

    fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, Error>;

    fn run_command(&mut self, command: &str, privilege: &Privilege)
    -> Result<CommandResult, Error>;

    fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, Error>;

    fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, Error>;
}

#[derive(Clone, Debug)]
pub enum Handler {
    LocalHost(LocalHostHandler),
    Ssh2(Ssh2HostHandler),
}

impl Handler {
    pub fn localhost(localhost_handler: LocalHostHandler) -> Self {
        Handler::LocalHost(localhost_handler)
    }

    pub fn ss2(ss2_handler: Ssh2HostHandler) -> Self {
        Handler::Ssh2(ss2_handler)
    }
}

impl HostHandler for Handler {
    fn connect(
        &mut self,
        endpoint: &str,
        secret_provider: &SecretsManagementSolution,
    ) -> Result<(), Error> {
        match self {
            Handler::LocalHost(handler) => handler.connect(endpoint, secret_provider),
            Handler::Ssh2(handler) => handler.connect(endpoint, secret_provider),
        }
    }

    fn is_connected(&mut self) -> bool {
        match self {
            Handler::LocalHost(handler) => handler.is_connected(),
            Handler::Ssh2(handler) => handler.is_connected(),
        }
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        match self {
            Handler::LocalHost(handler) => handler.disconnect(),
            Handler::Ssh2(handler) => handler.disconnect(),
        }
    }

    fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, Error> {
        match self {
            Handler::LocalHost(handler) => handler.is_this_command_available(command, privilege),
            Handler::Ssh2(handler) => handler.is_this_command_available(command, privilege),
        }
    }

    fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, Error> {
        match self {
            Handler::LocalHost(handler) => handler.run_command(command, privilege),
            Handler::Ssh2(handler) => handler.run_command(command, privilege),
        }
    }

    fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, Error> {
        match self {
            Handler::LocalHost(handler) => handler.run_windows_command(command),
            Handler::Ssh2(handler) => handler.run_windows_command(command),
        }
    }

    fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, Error> {
        match self {
            Handler::LocalHost(handler) => handler.get_file(path),
            Handler::Ssh2(handler) => handler.get_file(path),
        }
    }
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub enum ConnectionDetails {
//     // LocalHost(WhichUser),
//     // Ssh2(NewSsh2ConnectionDetails),
// }

// TODO : add some syntax checks
pub fn final_command(cmd: &str, privilege: &Privilege, user: &WhichUser) -> String {
    match user {
        WhichUser::CurrentUser => match privilege {
            Privilege::None => format!("{} 2>&1", cmd),
            Privilege::WithSudo => format!("sudo {} 2>&1", cmd),
            Privilege::WithSudoRs => format!("sudo-rs {} 2>&1", cmd),
        },
        WhichUser::UsernamePassword(credentials) => match privilege {
            Privilege::None => format!(
                "echo {} | su - {} -c \"{}\" 2>&1", // echo <otherpwd> | su - otheruser -c "my command line"
                credentials.password(),
                credentials.username(),
                cmd
            ),
            Privilege::WithSudo => format!(
                "echo {} | sudo -S -u {} {} 2>&1",
                credentials.password(),
                credentials.username(),
                cmd
            ),
            Privilege::WithSudoRs => format!(
                "echo {} | sudo-rs -S -u {} {} 2>&1",
                credentials.password(),
                credentials.username(),
                cmd
            ),
        },
    }

    // match privilege {
    //     Privilege::None => {
    //         let final_cmd = format!("{} 2>&1", cmd);
    //         return final_cmd;
    //     }
    //     // Privilege::WithSuAsUser(credentials) => {
    //     //     let final_cmd = format!("echo {} | su - {} -c {} 2>&1", credentials.password(), credentials.username(), cmd);
    //     //     return final_cmd;
    //     // }
    //     Privilege::WithSudo => {
    //         let final_cmd = format!("sudo {} 2>&1", cmd);
    //         return final_cmd;
    //     }
    //     // Privilege::WithSudoAsUser(credentials) => {
    //     //     let final_cmd = format!("echo {} | sudo -S -u {} {} 2>&1", credentials.password(), credentials.username(), cmd);
    //     //     return final_cmd;
    //     // }
    //     Privilege::WithSudoRs => {
    //         let final_cmd = format!("sudo-rs {} 2>&1", cmd);
    //         return final_cmd;
    //     }
    //     // Privilege::WithSudoRsAsUser(credentials) => {
    //     //     let final_cmd = format!("echo {} | sudo-rs -u {} {} 2>&1", credentials.password(), credentials.username(), cmd);
    //     //     return final_cmd;
    //     // }
    // }
}
