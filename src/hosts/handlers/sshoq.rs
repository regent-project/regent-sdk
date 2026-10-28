//! SSHOQ (SSH over QUIC / HTTP/3) host connection handler
//!
//! This module provides the [`SshoqHostHandler`] for connecting to hosts
//! running an SSHOQ server. SSHOQ is an SSH2-like protocol running over
//! QUIC (HTTP/3), providing encrypted, multiplexed command execution.
//!
//! # Example
//!
//! ```no_run
//! use regent_sdk::hosts::handlers::sshoq::{SshoqAuth, SshoqTlsConfig};
//! use regent_sdk::secrets::SecretReference;
//!
//! let auth = SshoqAuth::username_password(SecretReference::from("creds", None))
//!     .with_tls_config(SshoqTlsConfig::insecure());
//! ```

use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use shhoq::{AuthMethod, Client, ClientTlsConfig, Config};

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::handlers::localhost::WhichUser;
use crate::hosts::handlers::shell_quote;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::LoginKey;
use crate::hosts::privilege::LoginKeyRef;
use crate::hosts::privilege::Privilege;
use crate::secrets::SecretReference;

/// Default SSHOQ server port (QUIC/HTTP3 over TLS).
const DEFAULT_SSHOQ_PORT: u16 = 443;

/// Timeout for establishing an SSHOQ connection.
const SSHOQ_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default URL path of an SSHOQ server endpoint.
const DEFAULT_SSHOQ_URL_PATH: &str = "/sshoq-server";

// ---------------------------------------------------------------------------
// TLS configuration (serializable wrapper)
// ---------------------------------------------------------------------------

/// TLS configuration for SSHOQ connections.
///
/// Serializable wrapper around [`shhoq::ClientTlsConfig`]. Since
/// `ClientTlsConfig` is not serializable, this enum captures the common
/// configurations in a YAML/JSON-friendly form and converts to the real type
/// at connection time.
///
/// Defaults to [`SshoqTlsConfig::SystemRoots`] when not specified.
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::handlers::sshoq::SshoqTlsConfig;
///
/// // Default: trust system root certificates
/// let tls = SshoqTlsConfig::system_roots();
///
/// // Insecure: skip certificate verification (like `sshoq -insecure`)
/// let tls = SshoqTlsConfig::insecure();
///
/// // Trust system roots + certificates pinned in a known_hosts file
/// let tls = SshoqTlsConfig::known_hosts_file("/etc/regent/sshoq_known_hosts");
///
/// // Custom: known_hosts file + additional DER-encoded root certificate files
/// let tls = SshoqTlsConfig::custom(
///     Some("/etc/regent/sshoq_known_hosts"),
///     vec!["/etc/regent/my-ca.der"],
/// );
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum SshoqTlsConfig {
    /// Trust the system root certificates (default).
    #[default]
    SystemRoots,
    /// Disable certificate verification entirely (insecure, mirrors `sshoq -insecure`).
    ///
    /// **Warning**: this accepts any certificate, including MITM attacks.
    Insecure,
    /// Trust system roots plus certificates pinned in a known_hosts file.
    KnownHostsFile(String),
    /// Trust system roots plus an optional known_hosts file and additional
    /// DER-encoded root certificate files.
    #[serde(rename_all = "PascalCase")]
    Custom {
        /// Path to a known_hosts file with pinned certificates.
        known_hosts_file: Option<String>,
        /// Paths to additional DER-encoded root certificate files.
        additional_roots: Vec<String>,
    },
}

impl SshoqTlsConfig {
    /// Trust the system root certificates (default).
    pub fn system_roots() -> Self {
        SshoqTlsConfig::SystemRoots
    }

    /// Disable certificate verification entirely (insecure).
    ///
    /// **Warning**: this accepts any certificate, including MITM attacks.
    pub fn insecure() -> Self {
        SshoqTlsConfig::Insecure
    }

    /// Trust system roots plus certificates pinned in a known_hosts file.
    pub fn known_hosts_file(path: impl Into<String>) -> Self {
        SshoqTlsConfig::KnownHostsFile(path.into())
    }

    /// Trust system roots plus an optional known_hosts file and additional
    /// DER-encoded root certificate files.
    pub fn custom(
        known_hosts_file: Option<impl Into<String>>,
        additional_roots: Vec<impl Into<String>>,
    ) -> Self {
        SshoqTlsConfig::Custom {
            known_hosts_file: known_hosts_file.map(Into::into),
            additional_roots: additional_roots.into_iter().map(Into::into).collect(),
        }
    }

    /// Convert to a [`shhoq::ClientTlsConfig`].
    ///
    /// Additional root certificate files are read from disk at conversion time.
    pub fn to_client_tls_config(&self) -> Result<ClientTlsConfig, RegentError> {
        match self {
            SshoqTlsConfig::SystemRoots => Ok(ClientTlsConfig::with_system_roots()),
            SshoqTlsConfig::Insecure => Ok(ClientTlsConfig::insecure()),
            SshoqTlsConfig::KnownHostsFile(path) => {
                Ok(ClientTlsConfig::with_system_roots().with_known_hosts_file(path.clone()))
            }
            SshoqTlsConfig::Custom {
                known_hosts_file,
                additional_roots,
            } => {
                let mut config = ClientTlsConfig::with_system_roots();
                if let Some(path) = known_hosts_file {
                    config = config.with_known_hosts_file(path.clone());
                }
                for root_path in additional_roots {
                    let bytes = std::fs::read(root_path).map_err(|e| {
                        RegentError::FailedInitialization(format!(
                            "Failed to read root certificate file '{}': {}",
                            root_path, e
                        ))
                    })?;
                    config = config.with_root_certificate(CertificateDer::from(bytes));
                }
                Ok(config)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection parameters (resolved, non-serializable)
// ---------------------------------------------------------------------------

/// Resolved connection parameters for an SSHOQ handler.
///
/// Groups the auth method, optional URL path, and TLS configuration that are
/// needed to establish a connection. This is the runtime (non-serializable)
/// counterpart of [`SshoqAuth`].
///
/// Construct via [`SshoqConnectionParams::from`] or the convenience constructors
/// ([`SshoqConnectionParams::username_password`], [`SshoqConnectionParams::key`],
/// [`SshoqConnectionParams::bearer_token`]), then customize with
/// [`SshoqConnectionParams::with_path`].
#[derive(Clone)]
pub struct SshoqConnectionParams {
    auth_method: SshoqAuthMethod,
    path: Option<String>,
    tls_config: ClientTlsConfig,
}

impl SshoqConnectionParams {
    /// Create connection params from all fields.
    pub fn from(
        auth_method: SshoqAuthMethod,
        path: Option<String>,
        tls_config: ClientTlsConfig,
    ) -> Self {
        Self {
            auth_method,
            path,
            tls_config,
        }
    }

    /// Create connection params with username + password auth.
    pub fn username_password(credentials: Credentials, tls_config: ClientTlsConfig) -> Self {
        Self::from(
            SshoqAuthMethod::UsernamePassword(credentials),
            None,
            tls_config,
        )
    }

    /// Create connection params with private key auth.
    pub fn key(login_key: LoginKey, tls_config: ClientTlsConfig) -> Self {
        Self::from(SshoqAuthMethod::Key(login_key), None, tls_config)
    }

    /// Create connection params with bearer token auth.
    pub fn bearer_token(token: String, tls_config: ClientTlsConfig) -> Self {
        Self::from(SshoqAuthMethod::BearerToken(token), None, tls_config)
    }

    /// Set a custom URL path for the SSHOQ server endpoint.
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }
}

impl std::fmt::Debug for SshoqConnectionParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshoqConnectionParams")
            .field("auth_method", &self.auth_method)
            .field("path", &self.path)
            .field("tls_config", &self.tls_config)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Host handler
// ---------------------------------------------------------------------------

/// Handler for SSHOQ (SSH over QUIC) connections.
///
/// Like [`crate::hosts::handlers::ssh2::Ssh2HostHandler`], this handler uses a
/// two-state enum: [`SshoqHostHandler::NotConnected`] holds the resolved
/// connection parameters, and [`SshoqHostHandler::Connected`] holds the same
/// plus the live [`shhoq::Client`].
pub enum SshoqHostHandler {
    /// Not yet connected — holds the resolved connection parameters.
    NotConnected(SshoqConnectionParams),
    /// Connected — holds the connection parameters and the live SSHOQ client.
    Connected(SshoqConnectionParams, Arc<Client>),
}

impl Clone for SshoqHostHandler {
    fn clone(&self) -> Self {
        match self {
            SshoqHostHandler::NotConnected(params) => {
                SshoqHostHandler::NotConnected(params.clone())
            }
            SshoqHostHandler::Connected(params, _) => {
                // When cloning a connected handler, return a new NotConnected handler.
                // The caller will need to reconnect.
                SshoqHostHandler::NotConnected(params.clone())
            }
        }
    }
}

impl std::fmt::Debug for SshoqHostHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshoqHostHandler::NotConnected(params) => {
                f.debug_tuple("NotConnected").field(params).finish()
            }
            SshoqHostHandler::Connected(params, _) => f
                .debug_tuple("Connected")
                .field(params)
                .field(&"*SSHOQ CLIENT*")
                .finish(),
        }
    }
}

impl HostHandler for SshoqHostHandler {
    async fn connect(&mut self, endpoint: &str) -> Result<(), RegentError> {
        if self.is_connected().await {
            return Ok(());
        }

        // Parse endpoint as "hostname:port" (default port 443 for SSHOQ)
        let address_and_port: Vec<&str> = endpoint.split(':').collect();
        if address_and_port.is_empty() {
            return Err(RegentError::FailedInitialization(
                "empty address".to_string(),
            ));
        }

        let hostname = address_and_port[0];
        let port: u16 = match address_and_port.get(1) {
            Some(port_str) => match port_str.parse::<u16>() {
                Ok(p) => p,
                Err(e) => {
                    return Err(RegentError::FailedInitialization(format!(
                        "invalid port: {}",
                        e
                    )));
                }
            },
            None => DEFAULT_SSHOQ_PORT,
        };

        // Build the shhoq Config and auth methods from the resolved params
        if let SshoqHostHandler::NotConnected(params) = self {
            let (username, auth_methods) = build_auth_methods(&params.auth_method)?;

            let url_path = params
                .path
                .clone()
                .unwrap_or_else(|| DEFAULT_SSHOQ_URL_PATH.to_string());

            let config = Config::new(username, hostname, port, &url_path).map_err(|e| {
                RegentError::FailedInitialization(format!("Failed to build SSHOQ config: {:?}", e))
            })?;

            let client = match timeout(
                SSHOQ_CONNECT_TIMEOUT,
                Client::connect(&config, &auth_methods, &params.tls_config),
            )
            .await
            {
                Ok(Ok(client)) => client,
                Ok(Err(e)) => {
                    return Err(RegentError::FailureToEstablishConnection(format!(
                        "SSHOQ connection failed: {:?}",
                        e
                    )));
                }
                Err(_) => {
                    return Err(RegentError::FailureToEstablishConnection(format!(
                        "SSHOQ connection timeout elapsed ({} ms)",
                        SSHOQ_CONNECT_TIMEOUT.as_millis()
                    )));
                }
            };

            *self = SshoqHostHandler::Connected(params.clone(), Arc::new(client));
            Ok(())
        } else {
            Ok(())
        }
    }

    async fn is_connected(&mut self) -> bool {
        match self {
            SshoqHostHandler::NotConnected(_) => false,
            SshoqHostHandler::Connected(params, client) => {
                // Try a lightweight command to check if the connection is alive
                match client.run_command("true").await {
                    Ok(_) => true,
                    Err(_) => {
                        *self = SshoqHostHandler::NotConnected(params.clone());
                        false
                    }
                }
            }
        }
    }

    async fn disconnect(&mut self) -> Result<(), RegentError> {
        match self {
            SshoqHostHandler::NotConnected(_) => Ok(()),
            SshoqHostHandler::Connected(params, client) => {
                client.close();
                *self = SshoqHostHandler::NotConnected(params.clone());
                Ok(())
            }
        }
    }

    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        let check_cmd_content = format!("command -v {}", shell_quote(command));
        let check_cmd_result = self
            .run_command(check_cmd_content.as_str(), privilege)
            .await;

        match check_cmd_result {
            Ok(cmd_result) => Ok(cmd_result.return_code == 0),
            Err(e) => Err(RegentError::FailureToRunCommand(format!("{:?}", e))),
        }
    }

    async fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError> {
        match self {
            SshoqHostHandler::NotConnected(_) => Err(RegentError::NotConnectedToHost),
            SshoqHostHandler::Connected(params, client) => {
                // Apply privilege escalation wrapping (sudo, su, etc.)
                let effective_user = which_user_for_auth_method(&params.auth_method);
                let final_cmd = final_command(command, privilege, &effective_user);

                match client.run_command(&final_cmd).await {
                    Ok(output) => Ok(CommandResult {
                        return_code: output.exit_status as i64,
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    }),
                    Err(e) => Err(RegentError::FailureToRunCommand(format!(
                        "SSHOQ command execution failed: {:?}",
                        e
                    ))),
                }
            }
        }
    }

    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match self {
            SshoqHostHandler::NotConnected(_) => Err(RegentError::NotConnectedToHost),
            SshoqHostHandler::Connected(_params, client) => {
                let final_cmd = format!("cmd /C {}", command);
                match client.run_command(&final_cmd).await {
                    Ok(output) => Ok(CommandResult {
                        return_code: output.exit_status as i64,
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    }),
                    Err(e) => Err(RegentError::FailureToRunCommand(format!(
                        "SSHOQ Windows command execution failed: {:?}",
                        e
                    ))),
                }
            }
        }
    }

    async fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        match self {
            SshoqHostHandler::NotConnected(_) => Err(RegentError::NotConnectedToHost),
            SshoqHostHandler::Connected(_params, client) => {
                // SSHOQ client does not expose SFTP in its high-level API,
                // so we retrieve file content via `base64` encoding to handle
                // binary files safely.
                let cmd = format!("base64 {}", shell_quote(&path.display().to_string()));
                match client.run_command(&cmd).await {
                    Ok(output) => {
                        if output.exit_status != 0 {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Failed to read file {}: {}",
                                path.display(),
                                String::from_utf8_lossy(&output.stderr)
                            )));
                        }
                        // Decode base64 output (may contain newlines)
                        let encoded = String::from_utf8_lossy(&output.stdout);
                        let encoded_clean: String =
                            encoded.chars().filter(|c| !c.is_whitespace()).collect();
                        // Simple base64 decode
                        match base64_decode(&encoded_clean) {
                            Ok(bytes) => Ok(bytes),
                            Err(e) => Err(RegentError::FailedToGetFile(format!(
                                "Failed to decode base64 content of {}: {}",
                                path.display(),
                                e
                            ))),
                        }
                    }
                    Err(e) => Err(RegentError::FailedToGetFile(format!(
                        "SSHOQ file retrieval failed for {}: {:?}",
                        path.display(),
                        e
                    ))),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Auth types
// ---------------------------------------------------------------------------

/// Resolved authentication method for SSHOQ connections.
///
/// Holds the actual secret values (resolved from the secret provider),
/// ready to be used for connecting.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SshoqAuthMethod {
    /// Username + password authentication (HTTP Basic auth).
    UsernamePassword(Credentials),
    /// Private key authentication (JWT bearer token signed with the key).
    Key(LoginKey),
    /// Raw bearer token authentication (e.g. OIDC ID token).
    BearerToken(String),
}

impl std::fmt::Debug for SshoqAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SshoqAuthMethod::UsernamePassword(creds) => {
                write!(
                    f,
                    "UsernamePassword(Credentials {{ username: {:?}, password: \"*REDACTED*\" }})",
                    creds.username()
                )
            }
            SshoqAuthMethod::Key(login_key) => {
                write!(f, "Key(({:?}, *REDACTED*))", login_key.username())
            }
            SshoqAuthMethod::BearerToken(_) => {
                write!(f, "BearerToken(*REDACTED*)")
            }
        }
    }
}

/// Authentication reference for SSHOQ connections (before secret resolution).
///
/// Uses [`SecretReference`] to point to secrets in a secret provider,
/// mirroring [`crate::hosts::handlers::ssh2::Ssh2AuthReference`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SshoqAuthReference {
    /// Username + password, referenced as a [`Credentials`] secret.
    UsernamePassword(SecretReference),
    /// Private key, referenced by username + key secret reference.
    Key(LoginKeyRef),
    /// Raw bearer token, referenced as a string secret.
    BearerToken(SecretReference),
}

/// SSHOQ authentication and connection configuration.
///
/// This is the serializable form used in YAML/JSON inventories and the
/// Rust API. It holds secret *references* (not resolved secrets).
///
/// # Example
///
/// ```no_run
/// use regent_sdk::hosts::handlers::sshoq::{SshoqAuth, SshoqAuthReference, SshoqTlsConfig};
/// use regent_sdk::secrets::SecretReference;
///
/// // Password auth with defaults (system roots, /sshoq-server path)
/// let auth = SshoqAuth::username_password(SecretReference::from("my_creds", None));
///
/// // Password auth customized with path and TLS
/// let auth = SshoqAuth::username_password(SecretReference::from("my_creds", None))
///     .with_path("/my-sshoq-endpoint")
///     .with_tls_config(SshoqTlsConfig::insecure());
///
/// // Full constructor with all fields
/// let auth = SshoqAuth::from(
///     SshoqAuthReference::UsernamePassword(SecretReference::from("my_creds", None)),
///     Some("/my-sshoq-endpoint".to_string()),
///     Some(SshoqTlsConfig::insecure()),
/// );
///
/// // Bearer token auth
/// let auth = SshoqAuth::bearer_token(SecretReference::from("oidc_token", None));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct SshoqAuth {
    /// The authentication method reference.
    pub auth_method: SshoqAuthReference,
    /// Optional URL path of the SSHOQ server endpoint.
    /// Defaults to `/sshoq-server` when not set.
    pub path: Option<String>,
    /// Optional TLS configuration. Defaults to system root certificates.
    pub tls_config: Option<SshoqTlsConfig>,
}

impl SshoqAuth {
    /// Create an SSHOQ auth from all fields.
    ///
    /// This is the primary constructor. Use the convenience constructors
    /// ([`SshoqAuth::username_password`], [`SshoqAuth::key`],
    /// [`SshoqAuth::bearer_token`]) for the common cases, then customize
    /// with [`SshoqAuth::with_path`] and [`SshoqAuth::with_tls_config`].
    pub fn from(
        auth_method: SshoqAuthReference,
        path: Option<String>,
        tls_config: Option<SshoqTlsConfig>,
    ) -> Self {
        Self {
            auth_method,
            path,
            tls_config,
        }
    }

    /// Create SSHOQ auth with username + password credentials reference.
    pub fn username_password(credentials: SecretReference) -> Self {
        Self::from(
            SshoqAuthReference::UsernamePassword(credentials),
            None,
            None,
        )
    }

    /// Create SSHOQ auth with a private key reference.
    pub fn key(username: &str, key_secret_reference: SecretReference) -> Self {
        Self::from(
            SshoqAuthReference::Key(LoginKeyRef::from(
                username.to_string(),
                key_secret_reference,
            )),
            None,
            None,
        )
    }

    /// Create SSHOQ auth with a raw bearer token reference.
    pub fn bearer_token(token: SecretReference) -> Self {
        Self::from(SshoqAuthReference::BearerToken(token), None, None)
    }

    /// Set a custom URL path for the SSHOQ server endpoint.
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    /// Set the TLS configuration for the SSHOQ connection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::hosts::handlers::sshoq::{SshoqAuth, SshoqTlsConfig};
    /// use regent_sdk::secrets::SecretReference;
    ///
    /// let auth = SshoqAuth::username_password(SecretReference::from("creds", None))
    ///     .with_tls_config(SshoqTlsConfig::insecure());
    /// ```
    pub fn with_tls_config(mut self, tls_config: SshoqTlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the shhoq `AuthMethod` list and extract the username from a resolved
/// [`SshoqAuthMethod`].
fn build_auth_methods(
    auth_method: &SshoqAuthMethod,
) -> Result<(String, Vec<AuthMethod>), RegentError> {
    match auth_method {
        SshoqAuthMethod::UsernamePassword(credentials) => {
            let username = credentials.username().to_string();
            let auth = vec![AuthMethod::password(credentials.password())];
            Ok((username, auth))
        }
        SshoqAuthMethod::Key(login_key) => {
            let username = login_key.username().to_string();
            // Parse the private key from PEM content and create a PrivateKey auth method
            let private_key = shhoq::PrivateKey::from_pem(login_key.key().as_bytes(), None)
                .map_err(|e| {
                    RegentError::FailedInitialization(format!(
                        "Failed to parse SSHOQ private key: {:?}",
                        e
                    ))
                })?;
            let auth = vec![AuthMethod::private_key(private_key)];
            Ok((username, auth))
        }
        SshoqAuthMethod::BearerToken(token) => {
            // Bearer token auth: the username is embedded in the token,
            // but the shhoq Config requires a username. We use a placeholder.
            let auth = vec![AuthMethod::bearer_token(token)];
            Ok(("sshoq".to_string(), auth))
        }
    }
}

/// Determine the effective [`WhichUser`] for privilege escalation wrapping,
/// based on the resolved auth method.
///
/// - Password auth: use the password for sudo askpass.
/// - Key / BearerToken auth: no password available, rely on NOPASSWD sudo.
fn which_user_for_auth_method(auth_method: &SshoqAuthMethod) -> WhichUser {
    match auth_method {
        SshoqAuthMethod::UsernamePassword(credentials) => {
            WhichUser::CurrentUserWithSudoPassword(credentials.password().to_string())
        }
        SshoqAuthMethod::Key(_) | SshoqAuthMethod::BearerToken(_) => WhichUser::CurrentUser,
    }
}

/// Minimal base64 decoder (standard alphabet, with padding).
///
/// This avoids adding a base64 crate dependency for the simple case of
/// decoding file content retrieved via `base64` on the remote host.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    if bytes.len() % 4 == 1 {
        return Err("invalid base64 length".to_string());
    }

    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    let chunks: Vec<&[u8]> = bytes.chunks(4).collect();

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == chunks.len() - 1;
        let pad = if is_last {
            bytes.len() - (chunks.len() - 1) * 4
        } else {
            4
        };
        let _ = pad;

        let mut vals = [0u8; 4];
        for (j, &b) in chunk.iter().enumerate() {
            vals[j] = lookup[b as usize];
            if vals[j] == 255 {
                return Err(format!("invalid base64 character: '{}'", b as char));
            }
        }

        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);

        output.push((n >> 16) as u8);
        if chunk.len() > 2 {
            output.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            output.push(n as u8);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_username_password() {
        let yaml = r#"
            !UsernamePassword
              SecRef: /path/to/creds
              Provider: files
        "#;
        let result = yaml_serde::from_str::<SshoqAuthReference>(yaml);
        assert!(matches!(
            result,
            Ok(SshoqAuthReference::UsernamePassword(_))
        ));
    }

    #[test]
    fn test_deserialize_bearer_token() {
        let yaml = r#"
            !BearerToken
              SecRef: /path/to/token
              Provider: files
        "#;
        let result = yaml_serde::from_str::<SshoqAuthReference>(yaml);
        assert!(matches!(result, Ok(SshoqAuthReference::BearerToken(_))));
    }

    #[test]
    fn test_deserialize_key() {
        let yaml = r#"
            !Key
              Username: testuser
              Key:
                SecRef: /path/to/key
                Provider: files
        "#;
        let result = yaml_serde::from_str::<SshoqAuthReference>(yaml);
        assert!(matches!(result, Ok(SshoqAuthReference::Key(_))));
    }

    #[test]
    fn test_deserialize_sshoq_auth_with_path() {
        let yaml = r#"
            AuthMethod: !UsernamePassword
              SecRef: /path/to/creds
              Provider: files
            Path: /my-sshoq-endpoint
        "#;
        let result = yaml_serde::from_str::<SshoqAuth>(yaml);
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert_eq!(auth.path, Some("/my-sshoq-endpoint".to_string()));
        assert_eq!(auth.tls_config, None);
    }

    #[test]
    fn test_deserialize_sshoq_auth_without_path() {
        let yaml = r#"
            AuthMethod: !UsernamePassword
              SecRef: /path/to/creds
              Provider: files
        "#;
        let result = yaml_serde::from_str::<SshoqAuth>(yaml);
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert_eq!(auth.path, None);
        assert_eq!(auth.tls_config, None);
    }

    #[test]
    fn test_deserialize_tls_system_roots() {
        let yaml = r#"
            !SystemRoots
        "#;
        let result = yaml_serde::from_str::<SshoqTlsConfig>(yaml);
        assert!(matches!(result, Ok(SshoqTlsConfig::SystemRoots)));
    }

    #[test]
    fn test_deserialize_tls_insecure() {
        let yaml = r#"
            !Insecure
        "#;
        let result = yaml_serde::from_str::<SshoqTlsConfig>(yaml);
        assert!(matches!(result, Ok(SshoqTlsConfig::Insecure)));
    }

    #[test]
    fn test_deserialize_tls_known_hosts_file() {
        let yaml = r#"
            !KnownHostsFile /etc/regent/sshoq_known_hosts
        "#;
        let result = yaml_serde::from_str::<SshoqTlsConfig>(yaml);
        assert!(matches!(result, Ok(SshoqTlsConfig::KnownHostsFile(_))));
    }

    #[test]
    fn test_deserialize_tls_custom() {
        let yaml = r#"
            !Custom
              KnownHostsFile: /etc/regent/sshoq_known_hosts
              AdditionalRoots:
                - /etc/regent/ca1.der
                - /etc/regent/ca2.der
        "#;
        let result = yaml_serde::from_str::<SshoqTlsConfig>(yaml);
        if let Err(e) = &result {
            panic!("deserialization failed: {:?}", e);
        }
        assert!(result.is_ok());
        if let Ok(SshoqTlsConfig::Custom {
            known_hosts_file,
            additional_roots,
        }) = result
        {
            assert_eq!(
                known_hosts_file,
                Some("/etc/regent/sshoq_known_hosts".to_string())
            );
            assert_eq!(additional_roots.len(), 2);
        } else {
            panic!("expected Custom variant");
        }
    }

    #[test]
    fn test_deserialize_sshoq_auth_with_tls_config() {
        let yaml = r#"
            AuthMethod: !UsernamePassword
              SecRef: /path/to/creds
              Provider: files
            TlsConfig: !Insecure
        "#;
        let result = yaml_serde::from_str::<SshoqAuth>(yaml);
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert_eq!(auth.tls_config, Some(SshoqTlsConfig::Insecure));
    }

    #[test]
    fn test_tls_builder_system_roots() {
        assert_eq!(SshoqTlsConfig::system_roots(), SshoqTlsConfig::SystemRoots);
    }

    #[test]
    fn test_tls_builder_insecure() {
        assert_eq!(SshoqTlsConfig::insecure(), SshoqTlsConfig::Insecure);
    }

    #[test]
    fn test_tls_builder_known_hosts_file() {
        assert_eq!(
            SshoqTlsConfig::known_hosts_file("/etc/regent/known_hosts"),
            SshoqTlsConfig::KnownHostsFile("/etc/regent/known_hosts".to_string()),
        );
    }

    #[test]
    fn test_tls_builder_custom() {
        assert_eq!(
            SshoqTlsConfig::custom(Some("/etc/regent/known_hosts"), vec!["/etc/regent/ca.der"],),
            SshoqTlsConfig::Custom {
                known_hosts_file: Some("/etc/regent/known_hosts".to_string()),
                additional_roots: vec!["/etc/regent/ca.der".to_string()],
            },
        );
    }

    #[test]
    fn test_tls_builder_custom_no_known_hosts() {
        assert_eq!(
            SshoqTlsConfig::custom(Option::<&str>::None, vec!["/etc/regent/ca.der"]),
            SshoqTlsConfig::Custom {
                known_hosts_file: None,
                additional_roots: vec!["/etc/regent/ca.der".to_string()],
            },
        );
    }

    #[test]
    fn test_tls_config_to_client_system_roots() {
        let tls = SshoqTlsConfig::system_roots().to_client_tls_config();
        assert!(tls.is_ok());
        assert!(!tls.unwrap().is_insecure());
    }

    #[test]
    fn test_tls_config_to_client_insecure() {
        let tls = SshoqTlsConfig::insecure().to_client_tls_config();
        assert!(tls.is_ok());
        assert!(tls.unwrap().is_insecure());
    }

    #[test]
    fn test_base64_decode() {
        // "hello" in base64 is "aGVsbG8="
        let decoded = base64_decode("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        // "hello" without padding
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base64_decode_binary() {
        // [0, 1, 2, 3, 4, 5] in base64 is "AAECAwQF"
        let decoded = base64_decode("AAECAwQF").unwrap();
        assert_eq!(decoded, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_base64_decode_empty() {
        let decoded = base64_decode("").unwrap();
        assert_eq!(decoded, Vec::<u8>::new());
    }

    #[test]
    fn test_base64_decode_with_newlines() {
        // base64 output from the `base64` command wraps at 76 chars;
        // the caller is expected to strip whitespace before decoding
        let input: String = "aGVs\nbG8="
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let decoded = base64_decode(&input).unwrap();
        assert_eq!(decoded, b"hello");
    }
}
