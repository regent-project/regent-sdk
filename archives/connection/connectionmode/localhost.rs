use crate::connection::specification::Credentials;
use crate::error::Error;
use crate::result::cmd::CmdResult;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostConnectionDetails {
    pub user: WhichUser,
}

impl LocalHostConnectionDetails {
    pub fn user(user: WhichUser) -> LocalHostConnectionDetails {
        LocalHostConnectionDetails { user }
    }
    pub fn current_user() -> LocalHostConnectionDetails {
        LocalHostConnectionDetails {
            user: WhichUser::CurrentUser,
        }
    }
}

#[derive(Clone)]
pub struct LocalHostHandler {
    pub user: WhichUser,
}

impl LocalHostHandler {
    // By default, commands are run with current user.
    pub fn new() -> LocalHostHandler {
        LocalHostHandler {
            user: WhichUser::CurrentUser,
        }
    }

    // However, we can run tasks as another local user.
    pub fn from(user: WhichUser) -> LocalHostHandler {
        LocalHostHandler { user }
    }

    pub fn is_this_cmd_available(&self, cmd: &str) -> Result<bool, Error> {
        let check_cmd_result = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {}", cmd))
            .output();

        match check_cmd_result {
            Ok(cmd_result) => {
                if cmd_result.status.code().unwrap() == 0 {
                    return Ok(true);
                } else {
                    return Ok(false);
                }
            }
            Err(e) => {
                return Err(Error::FailureToRunCommand(format!("{:?}", e)));
            }
        }
    }

    pub fn run_cmd(&self, cmd: &str) -> Result<CmdResult, Error> {
        let result = match &self.user {
            WhichUser::CurrentUser => Command::new("sh").arg("-c").arg(cmd).output(),
            WhichUser::PasswordLessUser(username) => Command::new("su")
                .arg("-")
                .arg(username)
                .arg("-c")
                .arg("sh")
                .arg("-c")
                .arg(cmd)
                .output(),
            WhichUser::UsernamePassword(credentials) => {
                let command_content = format!(
                    "echo \"{}\" | su - {} -c \"{}\"",
                    credentials.password, credentials.username, cmd
                );

                Command::new("sh").arg("-c").arg(command_content).output()
            }
        };

        match result {
            Ok(output) => Ok(CmdResult {
                rc: output.status.code().unwrap(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            }),
            Err(e) => Err(Error::FailureToRunCommand(format!("{}", e))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhichUser {
    CurrentUser,
    PasswordLessUser(String), // The String being the username
    UsernamePassword(Credentials),
}
