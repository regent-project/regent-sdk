use crate::command::CommandResult;
use crate::error::RegentError;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::Privilege;
use crate::secrets::SecretProvider;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostHandler {
    pub user: WhichUser,
}

impl LocalHostHandler {
    pub fn from(user: WhichUser) -> Self {
        Self { user }
    }
}

impl HostHandler for LocalHostHandler {
    fn connect(
        &mut self,
        _endpoint: &str,
        _secret_provider: &SecretProvider,
    ) -> Result<(), RegentError> {
        Ok(())
    }

    fn is_connected(&mut self) -> bool {
        true
    }

    fn disconnect(&mut self) -> Result<(), RegentError> {
        Ok(())
    }

    fn is_this_command_available(
        &mut self,
        command: &str,
        _privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        // TODO : use privilege (some commands do no exist for every user (PATH and so on...))
        let check_cmd_result = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {}", command))
            .output();

        match check_cmd_result {
            Ok(cmd_result) => {
                match cmd_result.status.code() {
                    Some(code) => {
                        if code == 0 {
                            return Ok(true);
                        } else {
                            return Ok(false);
                        }
                    }
                    None => {
                        // Process terminated by a signal -> consider this as a failure to run the command to completion
                        Err(RegentError::FailureToRunCommand(format!(
                            "Process terminated by a signal : {:?}",
                            cmd_result
                        )))
                    }
                }
            }
            Err(e) => {
                return Err(RegentError::FailureToRunCommand(format!("{:?}", e)));
            }
        }
    }

    fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError> {
        let final_command = final_command(command, privilege, &self.user);

        let result = Command::new("sh").arg("-c").arg(final_command).output();

        match result {
            Ok(output) => {
                match output.status.code() {
                    Some(code) => Ok(CommandResult {
                        return_code: code,
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    }),
                    None => {
                        // Process terminated by a signal -> consider this as a failure to run the command to completion
                        Err(RegentError::FailureToRunCommand(format!(
                            "Process terminated by a signal : {:?}",
                            output
                        )))
                    }
                }
            }
            Err(e) => Err(RegentError::FailureToRunCommand(format!("{}", e))),
        }
    }

    fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match Command::new("cmd").args(&["/C", command]).output() {
            Ok(output) => match output.status.code() {
                Some(code) => Ok(CommandResult {
                    return_code: code,
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                }),
                None => {
                    // Process terminated by a signal -> consider this as a failure to run the command to completion
                    Err(RegentError::FailureToRunCommand(format!(
                        "Process terminated by a signal : {:?}",
                        output
                    )))
                }
            },
            Err(e) => Err(RegentError::FailureToRunCommand(format!("{}", e))),
        }
    }

    fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        if !self.is_connected() {
            return Err(RegentError::FailedInitialization(
                "Not connected to host".to_string(),
            ));
        }

        match std::fs::read(path) {
            Ok(file_content) => Ok(file_content),
            Err(RegentError_detail) => {
                return Err(RegentError::FailureToRunCommand(format!(
                    "{:?}",
                    RegentError_detail
                )));
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhichUser {
    CurrentUser,
    UsernamePassword(Credentials),
}
