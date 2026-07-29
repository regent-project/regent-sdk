//! Privilege escalation and credentials
//!
//! This module provides types for specifying privilege levels and credentials
//! for command execution on managed hosts.

use serde::{Deserialize, Serialize};

use crate::secrets::SecretReference;

/// Specifies the privilege level for command execution.
///
/// This enum determines how commands are executed on the target host,
/// including whether privilege escalation is used.
///
/// # Variants
///
/// - `None`: Execute as the currently authenticated user
/// - `WithSudo`: Execute with `sudo` for root privileges
/// - `WithSudoRs`: Execute with `sudo-rs` for root privileges
///
/// # Example
///
/// ```no_run
/// use regent_sdk::Privilege;
///
/// // Execute as current user
/// let privilege = Privilege::None;
///
/// // Execute with sudo
/// let privilege = Privilege::WithSudo;
///
/// // Execute with sudo-rs
/// let privilege = Privilege::WithSudoRs;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Privilege {
    /// Run command as the current authenticated user (no privilege escalation).
    None,
    // /// Run cmd as another user using su
    // WithSuAsUser(Credentials),
    /// Run command with sudo for root privileges.
    WithSudo,
    // /// Run cmd as another user using sudo
    // WithSudoAsUser(Credentials),
    /// Run command with sudo-rs for root privileges.
    WithSudoRs,
    // /// Run cmd as another user using sudo-rs
    // WithSudoRsAsUser(Credentials),
}

/// User credentials for authentication.
///
/// Contains username and password for authenticating to a host.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::privilege::Credentials;
///
/// let creds = Credentials::from("admin", "secret_password");
/// assert_eq!(creds.username(), "admin");
/// assert_eq!(creds.password(), "secret_password");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Credentials {
    /// The username for authentication.
    username: String,
    /// The password for authentication.
    password: String,
}

impl Credentials {
    /// Create new credentials from username and password.
    ///
    /// # Arguments
    ///
    /// * `username` - The username
    /// * `password` - The password
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::privilege::Credentials;
    ///
    /// let creds = Credentials::from("admin", "password123");
    /// ```
    pub fn from(username: &str, password: &str) -> Credentials {
        Credentials {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Get the username.
    ///
    /// # Returns
    ///
    /// A reference to the username string.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password.
    ///
    /// **Warning**: Be cautious with this method as it exposes the password in plain text.
    ///
    /// # Returns
    ///
    /// A reference to the password string.
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// SSH login key for authentication.
///
/// Contains username and SSH private key for authenticating to a host via SSH.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::privilege::LoginKey;
///
/// let login_key = LoginKey::from(
///     "admin".to_string(),
///     "-----BEGIN RSA PRIVATE KEY-----\n...".to_string()
/// );
/// assert_eq!(login_key.username(), "admin");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoginKey {
    /// The username for SSH authentication.
    username: String,
    /// The private key for SSH authentication.
    key: String,
}

impl LoginKey {
    /// Create a new login key from username and private key.
    ///
    /// # Arguments
    ///
    /// * `username` - The SSH username
    /// * `key` - The SSH private key (PEM format)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::privilege::LoginKey;
    ///
    /// let login_key = LoginKey::from("admin".to_string(), "private_key_pem".to_string());
    /// ```
    pub fn from(username: String, key: String) -> Self {
        Self { username, key }
    }

    /// Get the username.
    ///
    /// # Returns
    ///
    /// A reference to the username string.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the private key.
    ///
    /// **Warning**: Be cautious with this method as it exposes the private key in plain text.
    ///
    /// # Returns
    ///
    /// A reference to the private key string.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Reference to an SSH login key stored in a secret provider.
///
/// Unlike [`LoginKey`], this struct doesn't contain the actual private key,
/// but rather a reference to where the key can be retrieved from a secret provider.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::privilege::LoginKeyRef;
/// use regent_sdk::secrets::SecretReference;
///
/// let key_ref = SecretReference::from("ssh_key_path", Some("files".to_string()));
/// let login_key_ref = LoginKeyRef::from("admin".to_string(), key_ref);
/// assert_eq!(login_key_ref.username(), "admin");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct LoginKeyRef {
    /// The username for SSH authentication.
    username: String,
    /// Reference to the secret containing the SSH private key.
    key: SecretReference,
}

impl LoginKeyRef {
    /// Create a new login key reference from username and secret reference.
    ///
    /// # Arguments
    ///
    /// * `username` - The SSH username
    /// * `key` - Reference to the secret containing the private key
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::privilege::LoginKeyRef;
    /// use regent_sdk::secrets::SecretReference;
    ///
    /// let key_ref = SecretReference::from("my_ssh_key", Some("vault".to_string()));
    /// let login_key_ref = LoginKeyRef::from("admin".to_string(), key_ref);
    /// ```
    pub fn from(username: String, key: SecretReference) -> Self {
        Self { username, key }
    }

    /// Get the username.
    ///
    /// # Returns
    ///
    /// A reference to the username string.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the secret reference for the SSH key.
    ///
    /// # Returns
    ///
    /// A reference to the secret reference.
    pub fn key_ref(&self) -> &SecretReference {
        &self.key
    }
}
