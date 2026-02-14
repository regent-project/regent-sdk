use crate::command::CommandResult;
use crate::error::Error;
use crate::host_handler::host_handler::HostHandler;
use crate::host_handler::host_handler::final_command;
use crate::host_handler::privilege::Credentials;
use crate::host_handler::privilege::Privilege;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Clone)]
pub struct LocalHostHandler {
    pub user: WhichUser,
}

impl LocalHostHandler {
    pub fn new(user: WhichUser) -> Self {
        Self { user }
    }
}

impl HostHandler for LocalHostHandler {
    fn connect(&mut self, _endpoint: &str) -> Result<(), Error> {
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

        let result = match &self.user {
            WhichUser::CurrentUser => Command::new("sh").arg("-c").arg(final_command).output(),
            WhichUser::PasswordLessUser(username) => Command::new("su")
                .arg("-")
                .arg(username)
                .arg("-c")
                .arg("sh")
                .arg("-c")
                .arg(final_command)
                .output(),
            WhichUser::UsernamePassword(credentials) => {
                let command_content = format!(
                    "echo \"{}\" | su - {} -c \"{}\"",
                    credentials.password(),
                    credentials.username(),
                    final_command
                );

                Command::new("sh").arg("-c").arg(command_content).output()
            }
        };

        match result {
            Ok(output) => Ok(CommandResult {
                return_code: output.status.code().unwrap(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
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
