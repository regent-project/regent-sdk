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
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::localhost::WhichUser;
use crate::hosts::handlers::ssh2::Ssh2Auth;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::Privilege;
use crate::secrets::SecretProvider;
use crate::secrets::SecretReference;
use crate::{LocalHostHandler, Ssh2HostHandler};

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
    /// Use a specific user, identified by its direct login/password values.
    RawUser(Credentials),
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
    /// let target = TargetUser::current_user();
    /// ```
    pub fn current_user() -> Self {
        Self {
            user_kind: TargetUserKind::CurrentUser,
        }
    }

    /// Create a target user for a specific user using a secret reference.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let target = TargetUser::user("admin_password", Some("files".to_string()));
    /// ```
    pub fn user(sec_ref: &str, provider: Option<String>) -> Self {
        Self {
            user_kind: TargetUserKind::User(SecretReference::from(sec_ref, provider)),
        }
    }

    /// Create a target user for a specific user using its direct credentials.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let target = TargetUser::user_raw("login", "some_password");
    /// ```
    pub fn user_raw(login: &str, password: &str) -> Self {
        Self {
            user_kind: TargetUserKind::RawUser(Credentials::from(login, password)),
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
    async fn connect(
        &mut self,
        endpoint: &str,
        // secret_provider: &Option<SecretProvider>,
    ) -> Result<(), RegentError>;

    /// Check if the handler is currently connected to a host.
    async fn is_connected(&mut self) -> bool;

    /// Disconnect from the host.
    async fn disconnect(&mut self) -> Result<(), RegentError>;

    /// Check if a specific command is available on the host.
    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError>;

    /// Execute a command on the host.
    async fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError>;

    /// Execute a Windows command on the host.
    ///
    /// This method is specifically for Windows command execution.
    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError>;

    /// Retrieve the contents of a file from the host.
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

/// Quote a string as a single, literal POSIX shell word.
///
/// Wraps `input` in single quotes and escapes any embedded single quote using the
/// standard `'\''` trick (close the quoted string, emit an escaped quote, reopen the
/// quoted string). The result is always safe to splice into a shell command line as
/// one argument, regardless of what bytes `input` contains (spaces, `$`, backticks,
/// `"`, `;`, `|`, newlines, other embedded single quotes, etc.) — none of it will be
/// interpreted by the shell.
pub fn shell_quote(input: &str) -> String {
    let mut quoted = String::with_capacity(input.len() + 2);
    quoted.push('\'');
    for c in input.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

// Note: `su` has no askpass equivalent (it reads only from the controlling tty or stdin), so
// this cannot be used for the plain `WhichUser::UsernamePassword` + `Privilege::None` (`su`)
// case — that one still pipes the password via stdin.
fn sudo_via_askpass(
    sudo_binary: &str,
    target_user: Option<&str>,
    password: &str,
    cmd: &str,
) -> String {
    let user_flag = match target_user {
        Some(username) => format!("-u {} ", shell_quote(username)),
        None => String::new(),
    };

    // Relying on ASKPASS means creating a temporary script which must provide the actual password
    // What is does :
    // - creates temporary script file with mktemp and deletes it ASAP with trap
    // - in this file, use printf to output actual password
    // - this file is given 700 permissions
    // - runs sudo/sudo-rs with SUDO_ASKPASS env var set
    // - avoid GUI prompts wiht "-n" option for sudo and "unset DISPLAY WAYLAND_DISPLAY"
    let inner = format!(
        "ASKPASS_HELPER=$(mktemp) && trap 'rm -f \"$ASKPASS_HELPER\"' EXIT && \
printf '#!/bin/sh\\nprintf %%s \"${var}\"\\n' > \"$ASKPASS_HELPER\" && chmod 700 \"$ASKPASS_HELPER\" && \
unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR && \
{var}={pw} SUDO_ASKPASS=\"$ASKPASS_HELPER\" SUDO_FORCE_ASKPASS=1 {sudo} -n -A {user_flag}sh -c {cmd}",
        var = "REGENT_SUDO_PASSWORD", // temporary environment variable used to pass password to sudo (avoids insecure "echo $PASSWORD | sudo -S ...")
        pw = shell_quote(password),
        sudo = sudo_binary,
        user_flag = user_flag,
        cmd = shell_quote(cmd),
    );

    format!("sh -c {} 2>&1", shell_quote(&inner))
}

pub fn final_command(cmd: &str, privilege: &Privilege, user: &WhichUser) -> String {
    match user {
        WhichUser::CurrentUser => match privilege {
            Privilege::None => format!("{} 2>&1", cmd),
            Privilege::WithSudo => format!("sudo -n sh -c {} 2>&1", shell_quote(cmd)),
            Privilege::WithSudoRs => format!("sudo-rs -n sh -c {} 2>&1", shell_quote(cmd)),
        },
        WhichUser::CurrentUserWithSudoPassword(password) => match privilege {
            Privilege::None => format!("{} 2>&1", cmd),
            Privilege::WithSudo => sudo_via_askpass("sudo", None, password, cmd),
            Privilege::WithSudoRs => sudo_via_askpass("sudo-rs", None, password, cmd),
        },
        WhichUser::UsernamePassword(credentials) => {
            let quoted_username = shell_quote(credentials.username());
            let quoted_password = shell_quote(credentials.password());
            let quoted_cmd = shell_quote(cmd);
            match privilege {
                // su - otheruser -c 'my command line', password piped in non-interactively.
                // (su has no askpass mechanism, unlike sudo/sudo-rs below.)
                Privilege::None => format!(
                    "printf '%s\\n' {} | su - {} -c {} 2>&1",
                    quoted_password, quoted_username, quoted_cmd
                ),
                Privilege::WithSudo => sudo_via_askpass(
                    "sudo",
                    Some(credentials.username()),
                    credentials.password(),
                    cmd,
                ),
                Privilege::WithSudoRs => sudo_via_askpass(
                    "sudo-rs",
                    Some(credentials.username()),
                    credentials.password(),
                    cmd,
                ),
            }
        }
    }
}
