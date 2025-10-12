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
            // TODO : add SSH custom port handling
            match TcpStream::connect(format!("{}:22", self.hostaddress)) {
                Ok(tcp) => {
                    self.sshsession.set_tcp_stream(tcp);
                    self.sshsession.handshake().unwrap();

                    match &self.authmode {
                        Ssh2AuthMode::UsernamePassword(credentials) => {
                            self.sshsession
                                .userauth_password(&credentials.username, &credentials.password)
                                .unwrap();
                            if self.sshsession.authenticated() {
                                return Ok(());
                            } else {
                                return Err(Error::FailedInitialization(String::from(
                                    "PLACEHOLDER",
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
                                    "PLACEHOLDER",
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
                                    "PLACEHOLDER",
                                )));
                            }
                        }
                        Ssh2AuthMode::Agent(_agent) => {
                            return Ok(());
                        } // TODO
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
                channel.exec(cmd).unwrap();
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
    Agent(String),              // Name of SSH agent
}

impl std::fmt::Debug for Ssh2AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Ssh2AuthMode::Unset => {
                write!(f, "Unset")
            }
            Ssh2AuthMode::UsernamePassword(creds) => {
                write!(f, "UsernamePassword(Credentials {{ username: {:?}, password: \"HIDDEN PASSWORD\" }})", creds.username)
            }
            Ssh2AuthMode::KeyFile((username, key_path)) => {
                write!(f, "KeyFile(({:?}, {:?}))", username, key_path)
            }
            Ssh2AuthMode::KeyMemory((username, _key_content)) => {
                write!(f, "KeyMemory(({:?}, \"HIDDEN KEY CONTENT\"))", username)
            }
            Ssh2AuthMode::Agent(agent_name) => {
                write!(f, "Agent({:?})", agent_name)
            }
        }
    }
}
