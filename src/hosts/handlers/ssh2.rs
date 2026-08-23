use bytes::Bytes;
use russh::Disconnect;
use russh::Preferred;
use russh::client::AuthResult;
use russh::client::{Config, Handle, Handler};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{load_secret_key, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg};
use serde::Deserialize;
use serde::Serialize;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::handlers::localhost::WhichUser;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::LoginKey;
use crate::hosts::privilege::LoginKeyRef;
use crate::hosts::privilege::Privilege;
// use crate::secrets::SecretProvider;
use crate::secrets::SecretReference;

// #[derive(Clone)]
// pub struct Ssh2HostHandler {
//     auth: Ssh2AuthMethod,
//     session: Handle<Ssh2Client>,
// }

pub enum Ssh2HostHandler {
    NotConnected(Ssh2AuthMethod),
    Connected(Ssh2AuthMethod, Handle<Ssh2Client>),
}

struct Ssh2Client {}

impl Handler for Ssh2Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl Clone for Ssh2HostHandler {
    fn clone(&self) -> Self {
        match self {
            Ssh2HostHandler::NotConnected(auth) => Ssh2HostHandler::NotConnected(auth.clone()),
            Ssh2HostHandler::Connected(auth, _) => {
                // When cloning a connected handler, return a new NotConnected handler
                // The caller will need to reconnect
                Ssh2HostHandler::NotConnected(auth.clone())
            }
        }
    }
}

impl std::fmt::Debug for Ssh2HostHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ssh2HostHandler::NotConnected(auth) => {
                f.debug_tuple("NotConnected").field(auth).finish()
            }
            Ssh2HostHandler::Connected(auth, _) => f
                .debug_tuple("Connected")
                .field(auth)
                .field(&"*SESSION HANDLE*")
                .finish(),
        }
    }
}

impl HostHandler for Ssh2HostHandler {
    async fn connect(&mut self, endpoint: &str) -> Result<(), RegentError> {
        // Check whether a session is already enabled or not (init() might have already been called
        // on this host)
        if self.is_connected().await {
            return Ok(());
        }

        let address_and_port: Vec<&str> = endpoint.split(':').collect();
        if address_and_port.is_empty() {
            return Err(RegentError::FailedInitialization(
                "empty address".to_string(),
            ));
        }

        let address = address_and_port[0];
        let ssh_port: u16 = match address_and_port.get(1) {
            Some(port) => match port.parse::<u16>() {
                Ok(p) => p,
                Err(e) => {
                    return Err(RegentError::FailedInitialization(format!(
                        "invalid port: {}",
                        e
                    )));
                }
            },
            None => 22,
        };

        let addrs = format!("{}:{}", address, ssh_port);

        // Create russh configuration
        let config = Arc::new(Config {
            keepalive_interval: Some(Duration::from_secs(5)),
            keepalive_max: 3,
            nodelay: true,
            window_size: 2097152,       // 2 MB
            maximum_packet_size: 32768, // 32 KB
            channel_buffer_size: 128,
            inactivity_timeout: None,
            preferred: Preferred::default(),
            ..Default::default()
        });

        // Connect using russh
        let client_handler = Ssh2Client {};
        let connection_timeout = Duration::from_secs(10);
        let mut handle = match timeout(
            connection_timeout,
            russh::client::connect(config, addrs, client_handler),
        )
        .await
        {
            Ok(connection_result) => match connection_result {
                Ok(h) => h,
                Err(e) => {
                    return Err(RegentError::FailedTcpBinding(format!("{:?}", e)));
                }
            },
            Err(_details) => {
                return Err(RegentError::FailureToEstablishConnection(format!(
                    "Connection timeout elapsed ({} ms)",
                    connection_timeout.as_millis()
                )));
            }
        };

        // Authenticate based on the auth method
        if let Ssh2HostHandler::NotConnected(auth_method) = self {
            match auth_method {
                Ssh2AuthMethod::UsernamePassword(credentials) => {
                    match handle
                        .authenticate_password(credentials.username(), credentials.password())
                        .await
                    {
                        Ok(auth_result) => match auth_result {
                            AuthResult::Success => {
                                *self = Ssh2HostHandler::Connected(auth_method.clone(), handle);
                                return Ok(());
                            }
                            AuthResult::Failure {
                                remaining_methods,
                                partial_success,
                            } => {
                                return Err(RegentError::FailedInitialization(
                                    "Password authentication failed".to_string(),
                                ));
                            }
                        },
                        Err(e) => {
                            return Err(RegentError::FailedInitialization(format!(
                                "Password authentication error: {:?}",
                                e
                            )));
                        }
                    }
                }
                Ssh2AuthMethod::Key(login_key) => {
                    // Load the private key from the string
                    match load_secret_key(login_key.key(), None) {
                        Ok(key_pair) => {
                            let best_hash = match handle.best_supported_rsa_hash().await {
                                Ok(h) => h.flatten(),
                                Err(e) => {
                                    return Err(RegentError::FailedInitialization(format!(
                                        "Failed to get supported hash: {:?}",
                                        e
                                    )));
                                }
                            };
                            let key_with_alg =
                                PrivateKeyWithHashAlg::new(Arc::new(key_pair), best_hash);
                            match handle
                                .authenticate_publickey(login_key.username(), key_with_alg)
                                .await
                            {
                                Ok(auth_result) => match auth_result {
                                    AuthResult::Success => {
                                        *self =
                                            Ssh2HostHandler::Connected(auth_method.clone(), handle);
                                        return Ok(());
                                    }
                                    AuthResult::Failure {
                                        remaining_methods,
                                        partial_success,
                                    } => {
                                        return Err(RegentError::FailedInitialization(
                                            "Public key authentication failed".to_string(),
                                        ));
                                    }
                                },
                                Err(e) => {
                                    return Err(RegentError::FailedInitialization(format!(
                                        "Public key authentication error: {:?}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(error_details) => {
                            return Err(RegentError::FailedInitialization(format!(
                                "Failed to load key: {:?}",
                                error_details
                            )));
                        }
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    async fn is_connected(&mut self) -> bool {
        match self {
            Ssh2HostHandler::NotConnected(_) => false,
            Ssh2HostHandler::Connected(auth_method, session) => match session.send_ping().await {
                Ok(()) => true,
                Err(_error_details) => {
                    *self = Ssh2HostHandler::NotConnected(auth_method.clone());
                    false
                }
            },
        }
    }

    async fn disconnect(&mut self) -> Result<(), RegentError> {
        match self {
            Ssh2HostHandler::NotConnected(_) => Ok(()),
            Ssh2HostHandler::Connected(auth_method, session) => {
                match session
                    .disconnect(Disconnect::ByApplication, "regent", "English")
                    .await
                {
                    Ok(()) => {
                        *self = Ssh2HostHandler::NotConnected(auth_method.clone());
                        Ok(())
                    }
                    Err(error_details) => Err(RegentError::ProblemWithHostConnection(format!(
                        "{:?}",
                        error_details
                    ))),
                }
            }
        }
    }

    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        let check_cmd_content = format!("command -v {}", command);
        let check_cmd_result = self
            .run_command(check_cmd_content.as_str(), privilege)
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
        match self {
            Ssh2HostHandler::NotConnected(_auth_method) => {
                return Err(RegentError::NotConnectedToHost);
            }
            Ssh2HostHandler::Connected(_auth_method, session_handle) => {
                match session_handle.channel_open_session().await {
                    Ok(mut channel) => {
                        let final_command =
                            final_command(command, privilege, &WhichUser::CurrentUser);

                        if let Err(details) = channel.exec(true, final_command).await {
                            return Err(RegentError::FailureToRunCommand(format!("{:?}", details)));
                        }

                        let mut return_code = 1;
                        let mut command_output = String::new();

                        loop {
                            // There's an event available on the session channel
                            let Some(msg) = channel.wait().await else {
                                break;
                            };
                            match msg {
                                // Write data to the buffer
                                ChannelMsg::Data { ref data } => {
                                    command_output.push_str(&String::from_utf8_lossy(data));
                                }
                                ChannelMsg::ExitStatus { exit_status } => {
                                    return_code = exit_status;
                                    // cannot leave the loop immediately, there might still be more data to receive
                                }
                                _ => {}
                            }
                        }

                        Ok(CommandResult {
                            return_code: return_code.into(),
                            stdout: command_output,
                            stderr: String::new(),
                        })
                    }
                    Err(e) => Err(RegentError::FailureToEstablishConnection(e.to_string())),
                }
            }
        }
    }

    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match self {
            Ssh2HostHandler::NotConnected(_auth_method) => {
                return Err(RegentError::NotConnectedToHost);
            }
            Ssh2HostHandler::Connected(_auth_method, session_handle) => {
                match session_handle.channel_open_session().await {
                    Ok(mut channel) => {
                        let final_command = format!("cmd /C {}", command);

                        if let Err(details) = channel.exec(true, final_command).await {
                            return Err(RegentError::FailureToRunCommand(format!("{:?}", details)));
                        }

                        let mut return_code = 1;
                        let mut command_output = String::new();

                        loop {
                            // There's an event available on the session channel
                            let Some(msg) = channel.wait().await else {
                                break;
                            };
                            match msg {
                                // Write data to the buffer
                                ChannelMsg::Data { ref data } => {
                                    command_output.push_str(&String::from_utf8_lossy(data));
                                }
                                ChannelMsg::ExitStatus { exit_status } => {
                                    return_code = exit_status;
                                    // cannot leave the loop immediately, there might still be more data to receive
                                }
                                _ => {}
                            }
                        }

                        Ok(CommandResult {
                            return_code: return_code.into(),
                            stdout: command_output,
                            stderr: String::new(),
                        })
                    }

                    Err(e) => Err(RegentError::FailureToEstablishConnection(e.to_string())),
                }
            }
        }
    }

    async fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        match self {
            Ssh2HostHandler::NotConnected(_auth_method) => {
                return Err(RegentError::NotConnectedToHost);
            }
            Ssh2HostHandler::Connected(_auth_method, session_handle) => {
                match session_handle.channel_open_session().await {
                    Ok(mut channel) => {
                        // 1. SCP request in "source" mode (-f)
                        let cmd = format!("scp -f \"{}\"", path.display());
                        if let Err(e) = channel.exec(true, cmd).await {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Russh exec error: {:?}",
                                e
                            )));
                        }

                        // Stream buffer to isolate the text header from the binary content
                        let mut stream_buffer = Vec::new();

                        // 2. Initialization: Send a NULL byte to indicate that the client is ready
                        if let Err(e) = channel.data(Cursor::new(&[0x00][..])).await {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Russh data transfer error: {:?}",
                                e
                            )));
                        }

                        // 3. Read and parse the header (until \n)
                        let mut header_line = String::new();
                        loop {
                            if stream_buffer.is_empty() {
                                match fetch_next_chunk(&mut channel).await {
                                    Ok(chunk) => stream_buffer.extend_from_slice(chunk.as_ref()),
                                    Err(e) => return Err(e),
                                }
                            }

                            let chunk = stream_buffer.remove(0);
                            if chunk == b'\n' {
                                break;
                            }
                            header_line.push(chunk as char);
                        }

                        // 4. Validate the received header type (\x01 = Warning, \x02 = Fatal Error)
                        if header_line.starts_with('\x01') || header_line.starts_with('\x02') {
                            return Err(RegentError::FailedToGetFile(header_line[1..].to_string()));
                        }
                        if !header_line.starts_with('C') {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Invalid SCP file header: {}",
                                header_line
                            )));
                        }

                        // 5. Extract the size and name of the original file
                        let parts: Vec<&str> = header_line[1..].splitn(3, ' ').collect();
                        if parts.len() < 3 {
                            return Err(RegentError::FailedToGetFile(
                                "Malformed SCP header format".to_string(),
                            ));
                        }

                        let file_size: usize;
                        if let Ok(size) = parts[0].parse() {
                            file_size = size;
                        } else {
                            return Err(RegentError::FailedToGetFile(
                                "Invalid file size integer in header".to_string(),
                            ));
                        }
                        let filename = parts[1].to_string();

                        // 6. Send ACK to validate the header and start the binary stream
                        if let Err(e) = channel.data(Cursor::new(&[0x00][..])).await {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Russh data transfer error: {:?}",
                                e
                            )));
                        }

                        // 7. Allocate the final memory vector
                        let mut file_payload = Vec::with_capacity(file_size);

                        // If file bytes were already in the buffer during header parsing
                        if !stream_buffer.is_empty() {
                            let buffered_take = std::cmp::min(stream_buffer.len(), file_size);
                            file_payload.extend(stream_buffer.drain(..buffered_take));
                        }

                        // Main network loop: fill the Vec until reaching `file_size`
                        while file_payload.len() < file_size {
                            let remaining_needed = file_size - file_payload.len();

                            let mut chunk;
                            match fetch_next_chunk(&mut channel).await {
                                Ok(c) => chunk = c,
                                Err(e) => return Err(e),
                            }

                            if chunk.len() <= remaining_needed {
                                file_payload.extend_from_slice(&chunk);
                            } else {
                                // The network block exceeds the file size (it contains the final ACK token)
                                let excess = chunk.split_off(remaining_needed);
                                file_payload.extend_from_slice(&chunk);
                                stream_buffer.extend_from_slice(&excess); // Keep the excess for final verification
                            }
                        }

                        // 8. Verify the final status byte sent by the server (\x00 expected)
                        if stream_buffer.is_empty() {
                            match fetch_next_chunk(&mut channel).await {
                                Ok(chunk) => stream_buffer.extend_from_slice(chunk.as_ref()),
                                Err(e) => return Err(e),
                            }
                        }

                        let end_ack = stream_buffer.remove(0);
                        if end_ack != 0x00 {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Unexpected end transfer token status byte: {}",
                                end_ack
                            )));
                        }

                        // 9. Send the final ACK to close the protocol
                        if let Err(e) = channel.data(Cursor::new(&[0x00][..])).await {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Russh data transfer error: {:?}",
                                e
                            )));
                        }
                        if let Err(e) = channel.eof().await {
                            return Err(RegentError::FailedToGetFile(format!(
                                "Russh channel EOF error: {:?}",
                                e
                            )));
                        }

                        Ok(file_payload)
                    }
                    Err(e) => Err(RegentError::FailureToEstablishConnection(e.to_string())),
                }
            }
        }
    }
}

// impl Ssh2HostHandler {
//     pub fn from(auth: Ssh2AuthMethod) -> Result<Ssh2HostHandler, RegentError> {
//         match Session::new() {
//             Ok(session) => Ok(Ssh2HostHandler { auth, session }),
//             Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
//                 "Failed to create new SSH2 session : {:?}",
//                 details
//             ))),
//         }
//     }

//     pub fn username_password(
//         username: &str,
//         password: &str,
//     ) -> Result<Ssh2HostHandler, RegentError> {
//         match Ssh2HostHandler::from(Ssh2AuthMethod::UsernamePassword(Credentials::from(
//             username, password,
//         ))) {
//             Ok(ssh2_host_handler) => Ok(ssh2_host_handler),
//             Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
//                 "Failed to create new Ssh2HostHandler : {:?}",
//                 details
//             ))),
//         }
//     }

//     pub fn key(username: &str, key: String) -> Result<Ssh2HostHandler, RegentError> {
//         match Ssh2HostHandler::from(Ssh2AuthMethod::Key(LoginKey::from(
//             username.to_string(),
//             key,
//         ))) {
//             Ok(ssh2_host_handler) => Ok(ssh2_host_handler),
//             Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
//                 "Failed to create new Ssh2HostHandler : {:?}",
//                 details
//             ))),
//         }
//     }
// }

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Ssh2AuthMethod {
    UsernamePassword(Credentials),

    Key(LoginKey),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Ssh2AuthReference {
    UsernamePassword(SecretReference),
    Key(LoginKeyRef),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct Ssh2Auth {
    pub auth_method: Ssh2AuthReference,
}

impl Ssh2Auth {
    pub fn username_password(secret_reference: &str, secret_provider_name: Option<&str>) -> Self {
        match secret_provider_name {
            Some(name) => Self {
                auth_method: Ssh2AuthReference::UsernamePassword(SecretReference::from(
                    secret_reference,
                    Some(name.to_string()),
                )),
            },
            None => Self {
                auth_method: Ssh2AuthReference::UsernamePassword(SecretReference::from(
                    secret_reference,
                    None,
                )),
            },
        }
    }

    pub fn key(username: &str, key_secret_reference: SecretReference) -> Self {
        Self {
            auth_method: Ssh2AuthReference::Key(LoginKeyRef::from(
                username.to_string(),
                key_secret_reference,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_username_password() {
        let yaml = r#"
            !UsernamePassword
              Username: "testuser"
              Password: "testpass"
        "#;
        let auth_method = yaml_serde::from_str::<Ssh2AuthMethod>(yaml);
        matches!(auth_method, Ok(Ssh2AuthMethod::UsernamePassword(_)));
    }

    #[test]
    fn test_deserialize_key_file() {
        let yaml = r#"
            !Key
              Username: testuser
              Key: /path/to/private/key
        "#;
        let auth_method = yaml_serde::from_str::<Ssh2AuthMethod>(yaml);
        matches!(auth_method, Ok(Ssh2AuthMethod::Key(_)));
    }
}

impl std::fmt::Debug for Ssh2AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Ssh2AuthMethod::UsernamePassword(creds) => {
                write!(
                    f,
                    "UsernamePassword(Credentials {{ username: {:?}, password: \"*REDACTED*\" }})",
                    creds.username()
                )
            }
            Ssh2AuthMethod::Key(login_key_path) => {
                write!(f, "Key(({:?}, *REDACTED*))", login_key_path.username())
            }
        }
    }
}

async fn fetch_next_chunk(channel: &mut Channel<russh::client::Msg>) -> Result<Bytes, RegentError> {
    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::Data { data } = msg {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
    Err(RegentError::FailedToGetFile(
        "Unexpected end of SSH channel stream".to_string(),
    ))
}
