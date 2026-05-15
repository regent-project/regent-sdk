use serde::Deserialize;
use serde::Serialize;
use serde::de;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::command::CommandResult;
use crate::error::RegentError;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::handlers::localhost::WhichUser;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::LoginKey;
use crate::hosts::privilege::LoginKeyRef;
use crate::hosts::privilege::Privilege;
// use crate::secrets::SecretProvider;
use crate::secrets::SecretReference;

#[derive(Clone)]
pub struct Ssh2HostHandler {
    auth: Ssh2AuthMethod,
    session: Session,
}

impl<'de> Deserialize<'de> for Ssh2HostHandler {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Ssh2HostHandlerHelper {
            auth: Ssh2AuthMethod,
        }

        let helper = Ssh2HostHandlerHelper::deserialize(deserializer)?;
        match Ssh2HostHandler::from(helper.auth) {
            Ok(ssh2_host_handler) => Ok(ssh2_host_handler),
            Err(details) => Err(de::Error::custom(format!("{:?}", details))),
        }
    }
}

impl std::fmt::Debug for Ssh2HostHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh2HostHandler")
            .field("auth", &self.auth)
            .field("authenticated", &self.session.authenticated())
            .finish()
    }
}

impl HostHandler for Ssh2HostHandler {
    fn connect(
        &mut self,
        endpoint: &str,
        // _secret_provider: &Option<SecretProvider>,
    ) -> Result<(), RegentError> {
        // Check whether a session is already enabled or not (init() might have already been called
        // on this host)
        if self.is_connected() {
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

        match TcpStream::connect(format!("{}:{}", address, ssh_port)) {
            Ok(tcp) => {
                self.session.set_tcp_stream(tcp);

                if let Err(details) = self.session.handshake() {
                    return Err(RegentError::FailedInitialization(format!("{:?}", details)));
                }

                match &self.auth {
                    Ssh2AuthMethod::UsernamePassword(credentials) => {
                        match self
                            .session
                            .userauth_password(credentials.username(), credentials.password())
                        {
                            Ok(()) => Ok(()),
                            Err(detailss) => {
                                Err(RegentError::FailedInitialization(format!("{:?}", detailss)))
                            }
                        }
                    }
                    Ssh2AuthMethod::Key(login_key) => {
                        match self.session.userauth_pubkey_memory(
                            login_key.username(),
                            None,
                            login_key.key(),
                            None,
                        ) {
                            Ok(()) => Ok(()),
                            Err(detailss) => {
                                Err(RegentError::FailedInitialization(format!("{:?}", detailss)))
                            }
                        }
                    }
                    // Ssh2AuthMethod::Agent(_agent) => {
                    //     return Ok(());
                    // }
                    _ => {
                        return Err(RegentError::FailedInitialization(String::from(
                            "Other RegentError",
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(RegentError::FailedTcpBinding(format!("{:?}", e)));
            }
        }
    }

    fn is_connected(&mut self) -> bool {
        self.session.authenticated()
    }

    fn disconnect(&mut self) -> Result<(), RegentError> {
        if let Err(ssh2_details) = self.session.disconnect(
            Some(ssh2::DisconnectCode::ByApplication),
            "disconnection called",
            None,
        ) {
            return Err(RegentError::AnyOtherError(format!(
                "failed to close SSH2 session : {}",
                ssh2_details
            )));
        }
        Ok(())
    }

    fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        let check_cmd_content = format!("command -v {}", command);
        let check_cmd_result = self.run_command(check_cmd_content.as_str(), privilege);

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

    fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError> {
        match self.session.channel_session() {
            Ok(mut channel) => {
                let final_command = final_command(command, privilege, &WhichUser::CurrentUser);

                if let Err(details) = channel.exec(&final_command) {
                    return Err(RegentError::FailureToRunCommand(format!("{:?}", details)));
                }

                let mut stdout = String::new();
                let mut stderr = String::new();

                let mut ssh_stdout = channel.stream(0);
                let mut ssh_stderr = channel.stderr();

                if let Err(details) = ssh_stdout.read_to_string(&mut stdout) {
                    return Err(RegentError::FailureToRunCommand(format!(
                        "Unable to read from SSH STDOUT : {:?}",
                        details
                    )));
                }
                if let Err(details) = ssh_stderr.read_to_string(&mut stderr) {
                    return Err(RegentError::FailureToRunCommand(format!(
                        "Unable to read from SSH STDERR : {:?}",
                        details
                    )));
                }

                if let Err(details) = channel.close() {
                    return Err(RegentError::ProblemWithHostConnection(format!(
                        "Unable to close connection properly : {:?}",
                        details
                    )));
                }

                let return_code = match channel.exit_status() {
                    Ok(code) => code,
                    Err(e) => {
                        return Err(RegentError::ProblemWithHostConnection(format!(
                            "RegentError getting exit status: {}",
                            e
                        )));
                    }
                };

                Ok(CommandResult {
                    return_code,
                    stdout,
                    stderr,
                })
            }

            Err(e) => Err(RegentError::FailureToEstablishConnection(e.to_string())),
        }
    }

    fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        match self.session.channel_session() {
            Ok(mut channel) => {
                let final_command = format!("cmd /C {}", command);

                if let Err(details) = channel.exec(&final_command) {
                    return Err(RegentError::FailureToRunCommand(format!("{:?}", details)));
                }
                let mut stdout = String::new();
                let mut stderr = String::new();

                let mut ssh_stdout = channel.stream(0);
                let mut ssh_stderr = channel.stderr();

                if let Err(details) = ssh_stdout.read_to_string(&mut stdout) {
                    return Err(RegentError::FailureToRunCommand(format!(
                        "Unable to read from SSH STDOUT : {:?}",
                        details
                    )));
                }
                if let Err(details) = ssh_stderr.read_to_string(&mut stderr) {
                    return Err(RegentError::FailureToRunCommand(format!(
                        "Unable to read from SSH STDERR : {:?}",
                        details
                    )));
                }

                if let Err(details) = channel.wait_close() {
                    warn!("Failed ton wait on SSH channel closing : {:?}", details);
                }

                let return_code = match channel.exit_status() {
                    Ok(code) => code,
                    Err(e) => {
                        return Err(RegentError::ProblemWithHostConnection(format!(
                            "RegentError getting exit status: {}",
                            e
                        )));
                    }
                };

                return Ok(CommandResult {
                    return_code,
                    stdout,
                    stderr,
                });
            }
            Err(e) => {
                return Err(RegentError::FailureToEstablishConnection(format!("{e}")));
            }
        }
    }

    fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        if !self.is_connected() {
            return Err(RegentError::FailedInitialization(
                "Not connected to host".to_string(),
            ));
        }

        let (mut file_channel, stat) = match self.session.scp_recv(&path) {
            Ok((channel, filestats)) => (channel, filestats),
            Err(details) => {
                return Err(RegentError::ProblemWithHostConnection(format!(
                    "Failed to establish SSH2 channel to retrieve file : {:?}",
                    details
                )));
            }
        };

        let mut buffer: Vec<u8> = match stat.size().try_into() {
            Ok(size) => Vec::with_capacity(size),
            Err(_) => Vec::new(),
        };
        if let Err(details) = file_channel.read_to_end(&mut buffer) {
            error!("Failed to read SSH2 buffer : {:?}", details);
            return Err(RegentError::ProblemWithHostConnection(format!(
                "Failed to read SSH2 buffer : {:?}",
                details
            )));
        }

        // Close the channel and wait for the whole content to be tranferred
        if let Err(details) = file_channel.send_eof() {
            return Err(RegentError::ProblemWithHostConnection(format!(
                "{:?}",
                details
            )));
        }
        if let Err(details) = file_channel.wait_eof() {
            return Err(RegentError::ProblemWithHostConnection(format!(
                "{:?}",
                details
            )));
        }
        if let Err(details) = file_channel.close() {
            return Err(RegentError::ProblemWithHostConnection(format!(
                "{:?}",
                details
            )));
        }
        if let Err(details) = file_channel.wait_close() {
            return Err(RegentError::ProblemWithHostConnection(format!(
                "{:?}",
                details
            )));
        }

        Ok(buffer)
    }
}

impl Ssh2HostHandler {
    pub fn from(auth: Ssh2AuthMethod) -> Result<Ssh2HostHandler, RegentError> {
        match Session::new() {
            Ok(session) => Ok(Ssh2HostHandler { auth, session }),
            Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
                "Failed to create new SSH2 session : {:?}",
                details
            ))),
        }
    }

    pub fn username_password(
        username: &str,
        password: &str,
    ) -> Result<Ssh2HostHandler, RegentError> {
        match Ssh2HostHandler::from(Ssh2AuthMethod::UsernamePassword(Credentials::from(
            username, password,
        ))) {
            Ok(ssh2_host_handler) => Ok(ssh2_host_handler),
            Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
                "Failed to create new Ssh2HostHandler : {:?}",
                details
            ))),
        }
    }

    pub fn key(username: &str, key: String) -> Result<Ssh2HostHandler, RegentError> {
        match Ssh2HostHandler::from(Ssh2AuthMethod::Key(LoginKey::from(
            username.to_string(),
            key,
        ))) {
            Ok(ssh2_host_handler) => Ok(ssh2_host_handler),
            Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
                "Failed to create new Ssh2HostHandler : {:?}",
                details
            ))),
        }
    }

    pub fn agent(agent_name: &str) -> Result<Ssh2HostHandler, RegentError> {
        match Ssh2HostHandler::from(Ssh2AuthMethod::Agent(agent_name.to_string())) {
            Ok(ssh2_host_handler) => Ok(ssh2_host_handler),
            Err(details) => Err(RegentError::ProblemWithHostConnection(format!(
                "Failed to create new Ssh2HostHandler : {:?}",
                details
            ))),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Ssh2AuthMethod {
    UsernamePassword(Credentials),

    Key(LoginKey),
    Agent(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Ssh2AuthReference {
    UsernamePassword(SecretReference),
    Key(LoginKeyRef),
    Agent(String),
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

    pub fn agent(agent_name: &str) -> Self {
        Self {
            auth_method: Ssh2AuthReference::Agent(agent_name.to_string()),
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

    #[test]
    fn test_deserialize_agent() {
        let yaml = r#"
            !Agent
                "default"
        "#;
        let auth_method = yaml_serde::from_str::<Ssh2AuthMethod>(yaml);
        matches!(auth_method, Ok(Ssh2AuthMethod::Agent(_)));
    }
}

impl std::fmt::Debug for Ssh2AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Ssh2AuthMethod::UsernamePassword(creds) => {
                write!(
                    f,
                    "UsernamePassword(Credentials {{ username: {:?}, password: \"********\" }})",
                    creds.username()
                )
            }
            Ssh2AuthMethod::Key(login_key_path) => {
                write!(f, "Key(({:?}, ********))", login_key_path.username())
            }
            Ssh2AuthMethod::Agent(agent_name) => {
                write!(f, "Agent({:?})", agent_name)
            }
        }
    }
}
