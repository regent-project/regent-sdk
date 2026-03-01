use crate::command::CommandResult;
use crate::error::Error;
use crate::hosts::handlers::HostHandler;
use crate::hosts::handlers::final_command;
use crate::hosts::handlers::localhost::WhichUser;
use crate::hosts::privilege::Credentials;
use crate::hosts::privilege::Privilege;
use pem::Pem;
use serde::Deserialize;
use serde::Serialize;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;

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
        Ok(Ssh2HostHandler::from(helper.auth))
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
    fn connect(&mut self, endpoint: &str) -> Result<(), Error> {
        // Check whether a session is already enabled or not (init() might have already been called
        // on this host)
        if self.is_connected() {
            return Ok(());
        }

        // finding out if address is "address" or "address:port" kind, to decide which port to use
        let address: &str;
        let ssh_port: u16;

        let mut iterator = endpoint.split(':');

        match iterator.next() {
            Some(host_address) => {
                address = host_address;
                match iterator.next() {
                    Some(port) => match port.parse::<u16>() {
                        Ok(port) => {
                            ssh_port = port;
                        }
                        Err(error_detail) => {
                            return Err(Error::FailedInitialization(format!(
                                "failure to parse given port : {}",
                                error_detail
                            )));
                        }
                    },
                    None => {
                        // No port specified, using default ssh port then
                        ssh_port = 22;
                    }
                }
            }
            None => {
                return Err(Error::FailedInitialization("empty address".to_string()));
            }
        }

        match TcpStream::connect(format!("{}:{}", address, ssh_port)) {
            Ok(tcp) => {
                self.session.set_tcp_stream(tcp);

                if let Err(error_detail) = self.session.handshake() {
                    return Err(Error::FailedInitialization(format!("{:?}", error_detail)));
                }

                match &self.auth {
                    Ssh2AuthMethod::UsernamePassword(credentials) => {
                        self.session
                            .userauth_password(credentials.username(), credentials.password())
                            .unwrap();
                        if self.session.authenticated() {
                            return Ok(());
                        } else {
                            return Err(Error::FailedInitialization(String::from(
                                "Authentication failed",
                            )));
                        }
                    }
                    Ssh2AuthMethod::KeyFile((username, privatekeypath)) => {
                        self.session
                            .userauth_pubkey_file(username.as_str(), None, &privatekeypath, None)
                            .unwrap(); // TODO : add pubkey and passphrase support
                        if self.session.authenticated() {
                            return Ok(());
                        } else {
                            return Err(Error::FailedInitialization(String::from(
                                "Authentication failed",
                            )));
                        }
                    }
                    Ssh2AuthMethod::KeyMemory((username, pem)) => {
                        self.session
                            .userauth_pubkey_memory(
                                username.as_str(),
                                None,
                                pem.to_string().as_str(), // Pem struct doesn't implement directly '.as_str()' but accepts '.to_string()'
                                None,
                            )
                            .unwrap(); // TODO : add pubkey and passphrase support
                        if self.session.authenticated() {
                            return Ok(());
                        } else {
                            return Err(Error::FailedInitialization(String::from(
                                "Authentication failed",
                            )));
                        }
                    }
                    // Ssh2AuthMethod::Agent(_agent) => {
                    //     return Ok(());
                    // }
                    _ => return Err(Error::FailedInitialization(String::from("Other error"))),
                }
            }
            Err(e) => {
                return Err(Error::FailedTcpBinding(format!("{:?}", e)));
            }
        }
    }

    fn is_connected(&mut self) -> bool {
        self.session.authenticated()
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        if let Err(ssh2_error_detail) = self.session.disconnect(
            Some(ssh2::DisconnectCode::ByApplication),
            "disconnection called",
            None,
        ) {
            return Err(Error::AnyOtherError(format!(
                "failed to close SSH2 session : {}",
                ssh2_error_detail
            )));
        }
        Ok(())
    }

    fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, Error> {
        let check_cmd_content = format!("command -v {}", command);
        let check_cmd_result = self.run_command(check_cmd_content.as_str(), privilege);

        match check_cmd_result {
            Ok(cmd_result) => {
                if cmd_result.return_code == 0 {
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
        match self.session.channel_session() {
            Ok(mut channel) => {
                let final_command = final_command(command, privilege, &WhichUser::CurrentUser);

                if let Err(error_detail) = channel.exec(&final_command) {
                    return Err(Error::FailureToRunCommand(format!("{:?}", error_detail)));
                }
                let mut stdout = String::new();
                let mut stderr = String::new();

                let mut ssh_stdout = channel.stream(0);
                let mut ssh_stderr = channel.stderr();

                ssh_stdout.read_to_string(&mut stdout).unwrap();
                ssh_stderr.read_to_string(&mut stderr).unwrap();

                // channel.read_to_string(&mut s).unwrap();
                channel.wait_close().unwrap();

                return Ok(CommandResult {
                    return_code: channel.exit_status().unwrap(),
                    stdout,
                    stderr,
                });
            }
            Err(e) => {
                return Err(Error::FailureToEstablishConnection(format!("{e}")));
            }
        }
    }

    fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, Error> {
        match self.session.channel_session() {
            Ok(mut channel) => {
                let final_command = format!("cmd /C {}", command);

                if let Err(error_detail) = channel.exec(&final_command) {
                    return Err(Error::FailureToRunCommand(format!("{:?}", error_detail)));
                }
                let mut stdout = String::new();
                let mut stderr = String::new();

                let mut ssh_stdout = channel.stream(0);
                let mut ssh_stderr = channel.stderr();

                ssh_stdout.read_to_string(&mut stdout).unwrap();
                ssh_stderr.read_to_string(&mut stderr).unwrap();

                // channel.read_to_string(&mut s).unwrap();
                channel.wait_close().unwrap();

                return Ok(CommandResult {
                    return_code: channel.exit_status().unwrap(),
                    stdout,
                    stderr,
                });
            }
            Err(e) => {
                return Err(Error::FailureToEstablishConnection(format!("{e}")));
            }
        }
    }

    fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, Error> {
        if !self.is_connected() {
            return Err(Error::FailedInitialization(
                "Not connected to host".to_string(),
            ));
        }

        let (mut file_channel, stat) = self.session.scp_recv(&path).unwrap();

        let mut buffer: Vec<u8> = match stat.size().try_into() {
            Ok(size) => Vec::with_capacity(size),
            Err(_) => Vec::new(),
        };
        file_channel.read_to_end(&mut buffer).unwrap();

        // Close the channel and wait for the whole content to be tranferred
        if let Err(error_detail) = file_channel.send_eof() {
            return Err(Error::ConnectionLevel(format!("{:?}", error_detail)));
        }
        if let Err(error_detail) = file_channel.wait_eof() {
            return Err(Error::ConnectionLevel(format!("{:?}", error_detail)));
        }
        if let Err(error_detail) = file_channel.close() {
            return Err(Error::ConnectionLevel(format!("{:?}", error_detail)));
        }
        if let Err(error_detail) = file_channel.wait_close() {
            return Err(Error::ConnectionLevel(format!("{:?}", error_detail)));
        }

        Ok(buffer)
    }
}

impl Ssh2HostHandler {
    pub fn from(auth: Ssh2AuthMethod) -> Ssh2HostHandler {
        Ssh2HostHandler {
            auth,
            session: Session::new().unwrap(),
        }
    }

    pub fn username_password(username: &str, password: &str) -> Ssh2HostHandler {
        Ssh2HostHandler::from(Ssh2AuthMethod::UsernamePassword(Credentials::from(
            username, password,
        )))
    }

    pub fn key_file(username: &str, key_file_path: &str) -> Ssh2HostHandler {
        Ssh2HostHandler::from(Ssh2AuthMethod::KeyFile((
            username.to_string(),
            PathBuf::from(key_file_path),
        )))
    }

    pub fn key_in_memory(username: &str, key_content: Pem) -> Ssh2HostHandler {
        Ssh2HostHandler::from(Ssh2AuthMethod::KeyMemory((
            username.to_string(),
            key_content,
        )))
    }

    pub fn agent(agent_name: &str) -> Ssh2HostHandler {
        Ssh2HostHandler::from(Ssh2AuthMethod::Agent(agent_name.to_string()))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Ssh2AuthMethod {
    UsernamePassword(Credentials),
    KeyFile((String, PathBuf)), // (username, private key's path)
    KeyMemory((String, Pem)),   // (username, PEM encoded key from memory)
    Agent(String),              // Name of SSH agent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_username_password() {
        let yaml = r#"
            !UsernamePassword
              username: "testuser"
              password: "testpass"
        "#;
        let auth_method: Ssh2AuthMethod = yaml_serde::from_str(yaml).unwrap();
        matches!(auth_method, Ssh2AuthMethod::UsernamePassword(_));
    }

    #[test]
    fn test_deserialize_key_file() {
        let yaml = r#"
            !KeyFile
              - "testuser"
              - "/path/to/private/key"
        "#;
        let auth_method: Ssh2AuthMethod = yaml_serde::from_str(yaml).unwrap();
        matches!(auth_method, Ssh2AuthMethod::KeyFile(_));
    }

    #[test]
    fn test_deserialize_key_memory() {
        let yaml = r#"
            !KeyMemory
              - "testuser"
              - "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAwn3SGLS+W9Kh8B7eSysF7rYuAyUNuFuhGUbT2wf0O8QAAAJhAq7a2QKu2
tgAAAAtzc2gtZWQyNTUxOQAAACAwn3SGLS+W9Kh8B7eSysF7rYuAyUNuFuhGUbT2wf0O8Q
AAAEB1D2VaOhrGOqiNkiQpeCPzT1WgI53LjxQWSZIqiiclKTCfdIYtL5b0qHwHt5LKwXut
i4DJQ24W6EZRtPbB/Q7xAAAAE3JvbXpvckBsYXB0b3BsZW5vdm8BAg==
-----END OPENSSH PRIVATE KEY-----"
        "#;
        let auth_method: Ssh2AuthMethod = yaml_serde::from_str(yaml).unwrap();
        matches!(auth_method, Ssh2AuthMethod::KeyMemory(_));
    }

    #[test]
    fn test_deserialize_agent() {
        let yaml = r#"
            !Agent
                "default"
        "#;
        let auth_method: Ssh2AuthMethod = yaml_serde::from_str(yaml).unwrap();
        matches!(auth_method, Ssh2AuthMethod::Agent(_));
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
            Ssh2AuthMethod::KeyFile((username, key_path)) => {
                write!(f, "KeyFile(({:?}, {:?}))", username, key_path)
            }
            Ssh2AuthMethod::KeyMemory((username, _key_content)) => {
                write!(f, "KeyMemory(({:?}, \"********\"))", username)
            }
            Ssh2AuthMethod::Agent(agent_name) => {
                write!(f, "Agent({:?})", agent_name)
            }
        }
    }
}
