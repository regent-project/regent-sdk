//! Local host connection handler
//!
//! This module provides the [`LocalHostHandler`] for executing operations
//! on the local machine. It implements the [`HostHandler`] trait and provides
//! command execution, file retrieval, and connection management for local operations.

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::Privilege;
use crate::secrets::SecretProvider;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::process::Command;
// use std::process::Command;

/// Handler for executing operations on the local machine.
///
/// This handler provides the ability to run commands, check for command availability,
/// and retrieve files from the local filesystem. Unlike remote handlers, the local
/// handler doesn't require actual connection/disconnection as it operates directly
/// on the current machine.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::{LocalHostHandler, command::CommandResult};
/// use regent_sdk::hosts::handlers::localhost::WhichUser;
/// use regent_sdk::hosts::privilege::Privilege;
///
/// let mut handler = LocalHostHandler::from(WhichUser::CurrentUser);
/// // Local handler is always "connected"
/// assert!(handler.is_connected());
///
/// // Run a command
/// let result = handler.run_command("echo hello", &Privilege::None).unwrap();
/// assert_eq!(result.stdout, "hello\n");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostHandler {
    /// The user context for command execution.
    ///
    /// This determines how commands are executed (as current user or with credentials).
    pub user: WhichUser,
}

impl LocalHostHandler {
    /// Create a new local host handler with the specified user context.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::{LocalHostHandler};
    /// use regent_sdk::hosts::handlers::localhost::WhichUser;
    ///
    /// // Create handler for current user
    /// let handler = LocalHostHandler::from(WhichUser::CurrentUser);
    ///
    /// // Create handler with specific credentials
    /// // let handler = LocalHostHandler::from(WhichUser::UsernamePassword(creds));
    /// ```
    pub fn from(user: WhichUser) -> Self {
        Self { user }
    }
}

impl HostHandler for LocalHostHandler {
    async fn connect(
        &mut self,
        _endpoint: &str,
        // _secret_provider: &Option<SecretProvider>,
    ) -> Result<(), RegentError> {
        Ok(())
    }

    async fn is_connected(&mut self) -> bool {
        true
    }

    async fn disconnect(&mut self) -> Result<(), RegentError> {
        Ok(())
    }

    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        let check_cmd_content = format!("command -v {}", command);

        let check_cmd_result = self
            .run_command(check_cmd_content.as_str(), &Privilege::None)
            .await;

        match check_cmd_result {
            Ok(cmd_result) => {
                if cmd_result.return_code == 0 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                return Err(RegentError::FailureToRunCommand(format!("{:?}", e)));
            }
        }
    }

    async fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError> {
        let final_command = final_command(command, privilege, &self.user);

        let result = Command::new("sh")
            .arg("-c")
            .arg(final_command)
            .output()
            .await;

        match result {
            Ok(output) => {
                match output.status.code() {
                    Some(code) => Ok(CommandResult {
                        return_code: code.into(),
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

    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match Command::new("cmd").args(&["/C", command]).output().await {
            Ok(output) => match output.status.code() {
                Some(code) => Ok(CommandResult {
                    return_code: code.into(),
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

    async fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        if !self.is_connected().await {
            return Err(RegentError::FailedInitialization(
                "Not connected to host".to_string(),
            ));
        }

        match std::fs::read(path) {
            Ok(file_content) => Ok(file_content),
            Err(details) => {
                return Err(RegentError::FailureToRunCommand(format!("{:?}", details)));
            }
        }
    }
}

/// Specifies which user to execute commands as on the local machine.
///
/// # Variants
///
/// - `CurrentUser`: Execute commands as the current process user
/// - `UsernamePassword`: Execute commands as a specific user with credentials
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::handlers::localhost::WhichUser;
/// use regent_sdk::hosts::privilege::Credentials;
///
/// // Execute as current user
/// let user = WhichUser::CurrentUser;
///
/// // Execute as specific user
/// let creds = Credentials::new("admin", "password");
/// let user = WhichUser::UsernamePassword(creds);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhichUser {
    /// Execute commands as the current user.
    CurrentUser,
    /// Execute commands as a specific user with provided credentials.
    UsernamePassword(Credentials),
}
