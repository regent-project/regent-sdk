use crate::command::CommandResult;
use crate::error::Error;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::Privilege;
use crate::secrets::SecretsManagementSolution;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostHandler {
    pub user: WhichUser
}

impl LocalHostHandler {
    pub fn from(user: WhichUser) -> Self {
        Self {
            user
        }
    }
}

impl HostHandler for LocalHostHandler {
    fn connect(&mut self,_endpoint: &str, _secret_provider: &SecretsManagementSolution) -> Result<(), Error> {
        Ok(())
    }

    fn is_connected(&mut self) -> bool {
        true
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn is_this_command_available(
        &mut self,
        command: &str,
        _privilege: &Privilege,
    ) -> Result<bool, Error> {
        // TODO : use privilege (some commands do no exist for every user (PATH and so on...))
        let check_cmd_result = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {}", command))
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

    fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, Error> {
        let final_command = final_command(command, privilege, &self.user);

        let result = Command::new("sh").arg("-c").arg(final_command).output();

        match result {
            Ok(output) => Ok(CommandResult {
                return_code: output.status.code().unwrap(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            }),
            Err(e) => Err(Error::FailureToRunCommand(format!("{}", e))),
        }
    }

    fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, Error> {
        match Command::new("cmd").args(&["/C", command]).output() {
            Ok(output) => Ok(CommandResult {
                return_code: output.status.code().unwrap(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            }),
            Err(e) => Err(Error::FailureToRunCommand(format!("{}", e))),
        }
    }

    fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, Error> {
        if !self.is_connected() {
            return Err(Error::FailedInitialization(
                "Not connected to host".to_string(),
            ));
        }

        match std::fs::read(path) {
            Ok(file_content) => Ok(file_content),
            Err(error_detail) => {
                return Err(Error::FailureToRunCommand(format!("{:?}", error_detail)));
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhichUser {
    CurrentUser,
    UsernamePassword(Credentials),
}
