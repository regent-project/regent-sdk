//! Most frequent case : reach host through SSHv2

use crate::connection::specification::Credentials;
use crate::error::Error;
use crate::result::cmd::CmdResult;
use pem::Pem;
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ssh2ConnectionDetails {
    pub hostaddress: String,
    pub authmode: Ssh2AuthMode,
}

impl Ssh2ConnectionDetails {
    pub fn from(hostaddress: String, authmode: Ssh2AuthMode) -> Ssh2ConnectionDetails {
        Ssh2ConnectionDetails {
            hostaddress,
            authmode,
        }
    }
}

#[derive(Clone)]
pub struct Ssh2HostHandler {
    pub hostaddress: String,
    pub sshsession: Session,
    pub authmode: Ssh2AuthMode,
}

impl Ssh2HostHandler {
    pub fn new() -> Ssh2HostHandler {
        Ssh2HostHandler {
            hostaddress: String::new(),
            sshsession: Session::new().unwrap(),
            authmode: Ssh2AuthMode::Unset,
        }
    }

    pub fn none() -> Ssh2HostHandler {
        Ssh2HostHandler {
            hostaddress: String::from(""),
            sshsession: Session::new().unwrap(), // TODO: remove this unnecessary construction
            authmode: Ssh2AuthMode::Unset,
        }
    }

    pub fn from(hostaddress: String, authmode: Ssh2AuthMode) -> Ssh2HostHandler {
        Ssh2HostHandler {
            hostaddress,
            sshsession: Session::new().unwrap(),
            authmode,
        }
    }

    pub fn set_to(&mut self, hostaddress: String, authmode: Ssh2AuthMode) {
        self.hostaddress = hostaddress;
        self.authmode = authmode;
    }

    pub fn init(&mut self) -> Result<(), Error> {
        if self.authmode == Ssh2AuthMode::Unset {
            return Err(Error::MissingInitialization(
                "SSH2 authentication mode is unset".to_string(),
            ));
        } else {
            // Check whether a session is already enabled or not (init() might have already been called
            // on this host)
            if self.sshsession.authenticated() {
                return Ok(());
            }

            // finding out if address is "address" or "address:port" kind, to decide which port to use
            let address: &str;
            let ssh_port: u16;

            let mut iterator = self.hostaddress.split(':');

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
                    self.sshsession.set_tcp_stream(tcp);

                    if let Err(error_detail) = self.sshsession.handshake() {
                        return Err(Error::FailedInitialization(format!("{:?}", error_detail)));
                    }

                    match &self.authmode {
                        Ssh2AuthMode::UsernamePassword(credentials) => {
                            self.sshsession
                                .userauth_password(&credentials.username, &credentials.password)
                                .unwrap();
                            if self.sshsession.authenticated() {
                                return Ok(());
                            } else {
                                return Err(Error::FailedInitialization(String::from(
                                    "Authentication failed",
                                )));
                            }
                        }
                        Ssh2AuthMode::KeyFile((username, privatekeypath)) => {
                            self.sshsession
                                .userauth_pubkey_file(
                                    username.as_str(),
                                    None,
                                    &privatekeypath,
                                    None,
                                )
                                .unwrap(); // TODO : add pubkey and passphrase support
                            if self.sshsession.authenticated() {
                                return Ok(());
                            } else {
                                return Err(Error::FailedInitialization(String::from(
                                    "Authentication failed",
                                )));
                            }
                        }
                        Ssh2AuthMode::KeyMemory((username, pem)) => {
                            self.sshsession
                                .userauth_pubkey_memory(
                                    username.as_str(),
                                    None,
                                    pem.to_string().as_str(), // Pem struct doesn't implement directly '.as_str()' but accepts '.to_string()'
                                    None,
                                )
                                .unwrap(); // TODO : add pubkey and passphrase support
                            if self.sshsession.authenticated() {
                                return Ok(());
                            } else {
                                return Err(Error::FailedInitialization(String::from(
                                    "Authentication failed",
                                )));
                            }
                        }
                        // Ssh2AuthMode::Agent(_agent) => {
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
    }

    pub fn is_this_cmd_available(&self, cmd: &str) -> Result<bool, Error> {
        let check_cmd_content = format!("command -v {}", cmd);
        let check_cmd_result = self.run_cmd(check_cmd_content.as_str());

        match check_cmd_result {
            Ok(cmd_result) => {
                if cmd_result.rc == 0 {
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

    pub fn run_cmd(&self, cmd: &str) -> Result<CmdResult, Error> {
        if let Ssh2AuthMode::Unset = self.authmode {
            return Err(Error::MissingInitialization(
                "Can't run command on remote host : authentication unset".to_string(),
            ));
        }

        match self.sshsession.channel_session() {
            Ok(mut channel) => {
                if let Err(error_detail) = channel.exec(cmd) {
                    return Err(Error::FailureToRunCommand(format!("{:?}", error_detail)));
                }
                let mut s = String::new();
                channel.read_to_string(&mut s).unwrap();
                channel.wait_close().unwrap();

                return Ok(CmdResult {
                    rc: channel.exit_status().unwrap(),
                    stdout: s,
                });
            }
            Err(e) => {
                return Err(Error::FailureToEstablishConnection(format!("{e}")));
            }
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum Ssh2AuthMode {
    Unset,
    UsernamePassword(Credentials),
    KeyFile((String, PathBuf)), // (username, private key's path)
    KeyMemory((String, Pem)),   // (username, PEM encoded key from memory)
                                // Agent(String),              // Name of SSH agent
}

impl std::fmt::Debug for Ssh2AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Ssh2AuthMode::Unset => {
                write!(f, "Unset")
            }
            Ssh2AuthMode::UsernamePassword(creds) => {
                write!(
                    f,
                    "UsernamePassword(Credentials {{ username: {:?}, password: \"********\" }})",
                    creds.username
                )
            }
            Ssh2AuthMode::KeyFile((username, key_path)) => {
                write!(f, "KeyFile(({:?}, {:?}))", username, key_path)
            }
            Ssh2AuthMode::KeyMemory((username, _key_content)) => {
                write!(f, "KeyMemory(({:?}, \"********\"))", username)
            } // Ssh2AuthMode::Agent(agent_name) => {
              //     write!(f, "Agent({:?})", agent_name)
              // }
        }
    }
}

impl Ssh2AuthMode {
    pub fn username_password(username: &str, password: &str) -> Ssh2AuthMode {
        Ssh2AuthMode::UsernamePassword(Credentials::from(username, password))
    }

    pub fn key_file(username: &str, key_file_path: &str) -> Ssh2AuthMode {
        Ssh2AuthMode::KeyFile((username.to_string(), PathBuf::from(key_file_path)))
    }

    pub fn key_in_memory(username: &str, key_content: Pem) -> Ssh2AuthMode {
        Ssh2AuthMode::KeyMemory((username.to_string(), key_content))
    }
}

// #############################################
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSsh2ConnectionDetails {
    pub host_endpoint: String,
    pub authentication_mode: Ssh2AuthMode,
}

impl NewSsh2ConnectionDetails {
    /// Commands will be run on a remote host through SSH2, with username/password authentication
    pub fn from(
        host_endpoint: &str,
        authentication_mode: Ssh2AuthMode,
    ) -> NewSsh2ConnectionDetails {
        NewSsh2ConnectionDetails {
            host_endpoint: host_endpoint.to_string(),
            authentication_mode,
        }
    }
}
