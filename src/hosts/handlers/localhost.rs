//! Local host connection handler
//!
//! This module provides the [LocalHostHandler] for executing operations
//! on the local machine. It implements the [HostHandler] trait and provides
//! command execution, file retrieval, and connection management for local operations.

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::HostHandler;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::Privilege;
use crate::secrets::SecretProvider;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

use crate::hosts::handlers::shell_quote;
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
/// no_run
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
///
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
    /// no_run
    /// use regent_sdk::{LocalHostHandler};
    /// use regent_sdk::hosts::handlers::localhost::WhichUser;
    ///
    /// // Create handler for current user
    /// let handler = LocalHostHandler::from(WhichUser::CurrentUser);
    ///
    /// // Create handler with specific credentials
    /// // let handler = LocalHostHandler::from(WhichUser::UsernamePassword(creds));
    ///
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
        let check_cmd_content = format!("command -v {}", shell_quote(command));

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
        let result = match (privilege, &self.user) {
            (Privilege::None, _) => {
                Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .kill_on_drop(true)
                    .output()
                    .await
            }
            (Privilege::WithSudo | Privilege::WithSudoRs, WhichUser::CurrentUser) => {
                // Expecting a working NOPASSD sudoers file here
                Command::new(match privilege {
                    Privilege::WithSudoRs => "sudo-rs",
                    _ => "sudo",
                })
                .arg("-n")
                .arg("sh")
                .arg("-c")
                .arg(command)
                .env_remove("DISPLAY")
                .env_remove("WAYLAND_DISPLAY")
                .env_remove("DBUS_SESSION_BUS_ADDRESS")
                .env_remove("XDG_RUNTIME_DIR")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
            }
            (Privilege::WithSudo, WhichUser::CurrentUserWithSudoPassword(password)) => {
                run_with_sudo("sudo", password, command).await
            }
            (Privilege::WithSudoRs, WhichUser::CurrentUserWithSudoPassword(password)) => {
                run_with_sudo("sudo-rs", password, command).await
            }
            (Privilege::WithSudo, WhichUser::UsernamePassword(credentials)) => {
                run_with_sudo("sudo", credentials.password(), command).await
            }
            (Privilege::WithSudoRs, WhichUser::UsernamePassword(credentials)) => {
                run_with_sudo("sudo-rs", credentials.password(), command).await
            }
        };

        match result {
            Ok(output) => match output.status.code() {
                Some(code) => Ok(CommandResult {
                    return_code: code.into(),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                }),
                None => Err(RegentError::FailureToRunCommand(format!(
                    "Process terminated by a signal : {:?}",
                    output
                ))),
            },
            Err(e) => Err(RegentError::FailureToRunCommand(format!("{}", e))),
        }
    }

    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match Command::new("cmd")
            .args(&["/C", command])
            .kill_on_drop(true)
            .output()
            .await
        {
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

/// Specifies which user to execute commands as, and how to authenticate privilege escalation.
///
/// # Variants
///
/// - CurrentUser: Execute commands as the current process/session user. Privilege escalation
///   (sudo/sudo-rs) is attempted non-interactively and must be passwordless (NOPASSWD).
/// - CurrentUserWithSudoPassword: Same identity as CurrentUser (no su), but this password
///   is piped to sudo/sudo-rs non-interactively for privilege escalation.
/// - UsernamePassword: Switch to a specific, different user via su using these credentials,
///   also used with sudo/sudo-rs if required.
///
/// # Example
///
/// no_run
/// use regent_sdk::hosts::handlers::localhost::WhichUser;
/// use regent_sdk::hosts::privilege::Credentials;
///
/// // Execute as current user
/// let user = WhichUser::CurrentUser;
///
/// // Execute as specific user
/// let creds = Credentials::from("admin", "password");
/// let user = WhichUser::UsernamePassword(creds);
///
#[derive(Clone, Serialize, Deserialize)]
pub enum WhichUser {
    /// Execute commands as the current user.
    CurrentUser,
    /// Execute as the current user, but use this password to escalate via sudo/sudo-rs.
    CurrentUserWithSudoPassword(String),
    /// Execute commands as a specific user with provided credentials.
    UsernamePassword(Credentials),
}

impl std::fmt::Debug for WhichUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WhichUser::CurrentUser => write!(f, "CurrentUser"),
            WhichUser::CurrentUserWithSudoPassword(_) => {
                write!(f, "CurrentUserWithSudoPassword(*REDACTED*)")
            }
            WhichUser::UsernamePassword(credentials) => {
                write!(f, "UsernamePassword({:?})", credentials)
            }
        }
    }
}

async fn run_with_sudo(
    sudo_binary: &str,
    password: &str,
    command: &str,
) -> Result<std::process::Output, std::io::Error> {
    let mut child = Command::new(sudo_binary)
        .arg("-S") // Read password from stdin
        .arg("sh")
        .arg("-c")
        .arg(command)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
    }

    child.wait_with_output().await
}
