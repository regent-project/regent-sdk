//! Host connection handlers
//!
//! This module provides the connection handling infrastructure for Regent SDK.
//! It includes handlers for different connection methods (SSH, localhost) and
//! the traits that define the interface for host operations.

pub mod localhost;
pub mod ssh2;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::RegentError;
use crate::hosts::handlers::localhost::WhichUser;
use crate::hosts::handlers::ssh2::Ssh2Auth;
use crate::secrets::SecretProvider;
use crate::secrets::SecretReference;
use crate::{LocalHostHandler, Ssh2HostHandler};
use crate::hosts::command::CommandResult;
use crate::hosts::privilege::Privilege;

// Intermediary representation of a WhichUser
// WhichUser holds secrets, TargetUser holds references to secrets

/// Defines the type of user for a connection.
///
/// - `CurrentUser`: Use the currently authenticated user
/// - `User`: Use a specific user identified by a secret reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetUserKind {
    /// Use the currently authenticated user for the connection.
    CurrentUser,
    /// Use a specific user, identified by a secret reference.
    User(SecretReference),
}

/// Specifies the target user for a host connection.
///
/// This struct is used during the connection setup phase and holds references
/// to secrets rather than the secrets themselves. The actual secrets are
/// retrieved from the secret provider when the connection is established.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
///
/// // Connect as the current user
/// let target = TargetUser::current_user();
///
/// // Connect as a specific user (secret will be retrieved from provider)
/// let target = TargetUser::user("admin_credentials", Some("files".to_string()));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "PascalCase")]
pub struct TargetUser {
    /// The kind of user to connect as.
    pub user_kind: TargetUserKind,
}

impl TargetUser {
    /// Create a target user for the current user.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::handlers::TargetUser;
    ///
    /// let target = TargetUser::current_user();
    /// ```
    pub fn current_user() -> Self {
        Self {
            user_kind: TargetUserKind::CurrentUser,
        }
    }

    /// Create a target user for a specific user.
    ///
    /// # Arguments
    ///
    /// * `sec_ref` - Reference to the secret containing credentials
    /// * `provider` - Optional name of the secret provider to use
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::handlers::TargetUser;
    ///
    /// let target = TargetUser::user("admin_password", Some("files".to_string()));
    /// ```
    pub fn user(sec_ref: &str, provider: Option<String>) -> Self {
        Self {
            user_kind: TargetUserKind::User(SecretReference::from(sec_ref, provider)),
        }
    }
}

/// Defines the method used to connect to a host.
///
/// # Variants
///
/// - `Localhost`: Connect to the local machine
/// - `Ssh2`: Connect via SSH protocol
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser, Ssh2Auth};
///
/// // Localhost connection
/// let method = ConnectionMethod::Localhost(TargetUser::current_user());
///
/// // SSH connection
/// let method = ConnectionMethod::Ssh2(Ssh2Auth::username_password("creds", Some("files")));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ConnectionMethod {
    /// Connect to the local machine.
    Localhost(TargetUser),
    /// Connect via SSH protocol.
    Ssh2(Ssh2Auth),
}

/// Trait defining the interface for host connection handlers.
///
/// All host handlers must implement this trait to provide the basic operations
/// needed for managing connections and executing commands on remote hosts.
///
/// # Methods
///
/// - `connect`: Establish a connection to the host
/// - `is_connected`: Check if currently connected
/// - `disconnect`: Close the connection
/// - `is_this_command_available`: Check if a command exists on the host
/// - `run_command`: Execute a command on the host
/// - `run_windows_command`: Execute a Windows command (available when the `windows` feature is enabled)
/// - `get_file`: Retrieve a file from the host
///
/// # Example
///
/// Implementers of this trait can be used interchangeably through the [`Handler`] enum.
pub trait HostHandler: Sized {
    /// Establish a connection to the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The host address to connect to (e.g., "192.168.1.100:22")
    ///
    /// # Returns
    ///
    /// `Ok(())` if connection was successful, or a [`RegentError`] if it failed.
    async fn connect(
        &mut self,
        endpoint: &str,
        // secret_provider: &Option<SecretProvider>,
    ) -> Result<(), RegentError>;

    /// Check if the handler is currently connected to a host.
    ///
    /// # Returns
    ///
    /// `true` if connected, `false` otherwise.
    async fn is_connected(&mut self) -> bool;

    /// Disconnect from the host.
    ///
    /// # Returns
    ///
    /// `Ok(())` if disconnection was successful, or a [`RegentError`] if it failed.
    async fn disconnect(&mut self) -> Result<(), RegentError>;

    /// Check if a specific command is available on the host.
    ///
    /// # Arguments
    ///
    /// * `command` - The command name to check
    /// * `privilege` - The privilege level to check with
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the command exists, `Ok(false)` if it doesn't,
    /// or a [`RegentError`] if the check failed.
    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError>;

    /// Execute a command on the host.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    /// * `privilege` - The privilege level to use
    ///
    /// # Returns
    ///
    /// A [`CommandResult`] containing the exit code, stdout, and stderr,
    /// or a [`RegentError`] if execution failed.
    async fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError>;

    /// Execute a Windows command on the host.
    ///
    /// This method is specifically for Windows command execution.
    ///
    /// # Arguments
    ///
    /// * `command` - The Windows command to execute
    ///
    /// # Returns
    ///
    /// A [`CommandResult`] or a [`RegentError`] if execution failed.
    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError>;

    /// Retrieve the contents of a file from the host.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file to retrieve
    ///
    /// # Returns
    ///
    /// The file contents as a byte vector, or a [`RegentError`] if retrieval failed.
    async fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError>;
}

/// Enum that can hold any type of host handler.
///
/// This enum provides a unified interface for working with different types
/// of host handlers (local or SSH) through the [`HostHandler`] trait.
///
/// # Variants
///
/// - `LocalHost`: Handler for local machine connections
/// - `Ssh2`: Handler for SSH connections
///
/// # Example
///
/// ```no_run
/// use regent_sdk::{Handler, LocalHostHandler, Ssh2HostHandler, hosts::handlers::localhost::WhichUser};
///
/// // Create a local host handler
/// let local = Handler::localhost(LocalHostHandler::from(WhichUser::CurrentUser));
///
/// // Create an SSH handler (requires connection details)
/// // let ssh = Handler::ss2(Ssh2HostHandler::from(...).unwrap());
/// ```
// #[derive(Clone, Debug)]
pub enum Handler {
    /// Handler for local machine connections.
    LocalHost(LocalHostHandler),
    /// Handler for SSH connections.
    Ssh2(Ssh2HostHandler),
}

impl Clone for Handler {
    fn clone(&self) -> Self {
        match self {
            Handler::LocalHost(h) => Handler::LocalHost(h.clone()),
            Handler::Ssh2(h) => Handler::Ssh2(h.clone()),
        }
    }
}

impl Handler {
    /// Create a [`Handler`] from a [`LocalHostHandler`].
    ///
    /// # Arguments
    ///
    /// * `localhost_handler` - The local host handler to wrap
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::{Handler, LocalHostHandler, hosts::handlers::localhost::WhichUser};
    ///
    /// let handler = Handler::localhost(LocalHostHandler::from(WhichUser::CurrentUser));
    /// ```
    pub fn localhost(localhost_handler: LocalHostHandler) -> Self {
        Handler::LocalHost(localhost_handler)
    }

    /// Create a [`Handler`] from a [`Ssh2HostHandler`].
    ///
    /// # Arguments
    ///
    /// * `ss2_handler` - The SSH host handler to wrap
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::{Handler, Ssh2HostHandler, hosts::handlers::ssh2::Ssh2AuthMethod};
    ///
    /// // Assuming we have valid auth details
    /// // let ssh_handler = Ssh2HostHandler::from(Ssh2AuthMethod::Key(...)).unwrap();
    /// // let handler = Handler::ss2(ssh_handler);
    /// ```
    pub fn ss2(ss2_handler: Ssh2HostHandler) -> Self {
        Handler::Ssh2(ss2_handler)
    }
}

impl HostHandler for Handler {
    async fn connect(
        &mut self,
        endpoint: &str,
        // secret_provider: &Option<SecretProvider>,
    ) -> Result<(), RegentError> {
        match self {
            Handler::LocalHost(handler) => handler.connect(endpoint).await,
            Handler::Ssh2(handler) => handler.connect(endpoint).await,
        }
    }

    async fn is_connected(&mut self) -> bool {
        match self {
            Handler::LocalHost(handler) => handler.is_connected().await,
            Handler::Ssh2(handler) => handler.is_connected().await,
        }
    }

    async fn disconnect(&mut self) -> Result<(), RegentError> {
        match self {
            Handler::LocalHost(handler) => handler.disconnect().await,
            Handler::Ssh2(handler) => handler.disconnect().await,
        }
    }

    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        match self {
            Handler::LocalHost(handler) => {
                handler.is_this_command_available(command, privilege).await
            }
            Handler::Ssh2(handler) => handler.is_this_command_available(command, privilege).await,
        }
    }

    async fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError> {
        match self {
            Handler::LocalHost(handler) => handler.run_command(command, privilege).await,
            Handler::Ssh2(handler) => handler.run_command(command, privilege).await,
        }
    }

    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match self {
            Handler::LocalHost(handler) => handler.run_windows_command(command).await,
            Handler::Ssh2(handler) => handler.run_windows_command(command).await,
        }
    }

    async fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        match self {
            Handler::LocalHost(handler) => handler.get_file(path).await,
            Handler::Ssh2(handler) => handler.get_file(path).await,
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
