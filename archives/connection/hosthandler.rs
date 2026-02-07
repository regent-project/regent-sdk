use crate::connection::connectionmode::localhost::{
    LocalHostConnectionDetails, LocalHostHandler, WhichUser,
};
use crate::connection::connectionmode::ssh2mode::{
    NewSsh2ConnectionDetails, Ssh2ConnectionDetails, Ssh2HostHandler,
};
use crate::connection::specification::{ConnectionMode, Privilege};
use crate::error::Error;
use crate::result::cmd::CmdResult;
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::process::Command;

use super::host_connection::HostConnectionInfo;
use crate::connection::connectionmode::ssh2mode::Ssh2AuthMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHandlingInfo {
    pub connectionmode: ConnectionMode,
    pub hostaddress: String,
    pub connectiondetails: ConnectionDetails,
}

impl HostHandlingInfo {
    pub fn new() -> HostHandlingInfo {
        HostHandlingInfo {
            connectionmode: ConnectionMode::Unset,
            hostaddress: String::new(),
            connectiondetails: ConnectionDetails::Unset,
        }
    }

    pub fn from(
        connectionmode: ConnectionMode,
        hostaddress: String,
        connectiondetails: ConnectionDetails,
    ) -> HostHandlingInfo {
        HostHandlingInfo {
            connectionmode,
            hostaddress: hostaddress.clone(),
            connectiondetails,
        }
    }
}

#[derive(Clone)]
pub struct HostHandler {
    pub connectionmode: ConnectionMode,
    pub localhost: Option<LocalHostHandler>,
    pub ssh2: Option<Ssh2HostHandler>,
}

impl HostHandler {
    pub fn new() -> HostHandler {
        HostHandler {
            connectionmode: ConnectionMode::Unset,
            localhost: None,
            ssh2: None,
        }
    }

    pub fn from(
        address: String,
        host_connection_info: HostConnectionInfo,
    ) -> Result<HostHandler, Error> {
        match host_connection_info {
            HostConnectionInfo::Unset => Err(Error::MissingInitialization(
                "Host connection info is still unset. Unable to build a HostHandler.".into(),
            )),
            HostConnectionInfo::LocalHost(which_user) => Ok(HostHandler {
                connectionmode: ConnectionMode::LocalHost,
                localhost: Some(LocalHostHandler::from(which_user)),
                ssh2: None,
            }),
            HostConnectionInfo::Ssh2(ssh2_auth_mode) => Ok(HostHandler {
                connectionmode: ConnectionMode::Ssh2,
                localhost: None,
                ssh2: Some(Ssh2HostHandler::from(address, ssh2_auth_mode)),
            }),
        }
    }

    pub fn init(&mut self) -> Result<(), Error> {
        match self.connectionmode {
            ConnectionMode::Unset => {
                return Err(Error::MissingInitialization(
                    "ConnectionMode is unset".to_string(),
                ));
            }
            // Nothing to initialize when working on localhost
            ConnectionMode::LocalHost => {
                return Ok(());
            }
            ConnectionMode::Ssh2 => self.ssh2.as_mut().unwrap().init(),
        }
    }

    // Use this to check if a command is available on target host
    pub fn is_this_cmd_available(&mut self, cmd: &str) -> Result<bool, Error> {
        match self.connectionmode {
            ConnectionMode::Unset => Err(Error::MissingInitialization(
                "ConnectionMode is unset".to_string(),
            )),
            ConnectionMode::LocalHost => {
                self.localhost.as_mut().unwrap().is_this_cmd_available(cmd)
            }
            ConnectionMode::Ssh2 => self.ssh2.as_mut().unwrap().is_this_cmd_available(cmd),
        }
    }

    pub fn run_cmd(&mut self, cmd: &str, privilege: &Privilege) -> Result<CmdResult, Error> {
        let final_cmd = final_cmd(cmd.to_string(), privilege);
        match self.connectionmode {
            ConnectionMode::Unset => Err(Error::MissingInitialization(
                "ConnectionMode is unset".to_string(),
            )),
            ConnectionMode::LocalHost => {
                self.localhost.as_mut().unwrap().run_cmd(final_cmd.as_str())
            }
            ConnectionMode::Ssh2 => self.ssh2.as_mut().unwrap().run_cmd(final_cmd.as_str()),
        }
    }
}

// TODO : add some syntax checks
fn final_cmd(cmd: String, privilege: &Privilege) -> String {
    match privilege {
        Privilege::Usual => {
            let final_cmd = format!("{} 2>&1", cmd);
            return final_cmd;
        }
        Privilege::WithSudo => {
            let final_cmd = format!("sudo {} 2>&1", cmd);
            return final_cmd;
        }
        Privilege::WithSudoAsUser(username) => {
            let final_cmd = format!("sudo -u {} {} 2>&1", username, cmd);
            return final_cmd;
        }
        Privilege::WithSudoRs => {
            let final_cmd = format!("sudo-rs {} 2>&1", cmd);
            return final_cmd;
        }
        Privilege::WithSudoRsAsUser(username) => {
            let final_cmd = format!("sudo-rs -u {} {} 2>&1", username, cmd);
            return final_cmd;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionDetails {
    Unset,
    LocalHost(LocalHostConnectionDetails),
    Ssh2(Ssh2ConnectionDetails),
}

// ###############################################
//      Parallel approach
// ###############################################

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NewConnectionDetails {
    LocalHost(WhichUser),
    Ssh2(NewSsh2ConnectionDetails),
}

#[derive(Clone)]
pub enum ConnectionHandler {
    LocalHost(WhichUser),
    Ssh2(Session),
}

impl ConnectionHandler {
    pub fn from(connection_details: &NewConnectionDetails) -> Result<ConnectionHandler, Error> {
        match &connection_details {
            NewConnectionDetails::LocalHost(user_info) => {
                Ok(ConnectionHandler::LocalHost(user_info.clone()))
            }

            NewConnectionDetails::Ssh2(ssh2_details) => {
                // finding out if address is "address" or "address:port" kind, to decide which port to use
                let address: &str;
                let ssh_port: u16;

                let mut iterator = ssh2_details.host_endpoint.split(':');

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

                let mut ssh2_session = Session::new().unwrap();
                match TcpStream::connect(format!("{}:{}", address, ssh_port)) {
                    Ok(tcp_stream) => {
                        ssh2_session.set_tcp_stream(tcp_stream);

                        if let Err(error_detail) = ssh2_session.handshake() {
                            return Err(Error::FailedInitialization(format!("{:?}", error_detail)));
                        }

                        match &ssh2_details.authentication_mode {
                            Ssh2AuthMode::UsernamePassword(credentials) => {
                                ssh2_session
                                    .userauth_password(&credentials.username, &credentials.password)
                                    .unwrap();
                                if ssh2_session.authenticated() {
                                    return Ok(ConnectionHandler::Ssh2(ssh2_session));
                                } else {
                                    return Err(Error::FailedInitialization(String::from(
                                        "Authentication failed",
                                    )));
                                }
                            }
                            Ssh2AuthMode::KeyFile((username, privatekeypath)) => {
                                ssh2_session
                                    .userauth_pubkey_file(
                                        username.as_str(),
                                        None,
                                        &privatekeypath,
                                        None,
                                    )
                                    .unwrap(); // TODO : add pubkey and passphrase support
                                if ssh2_session.authenticated() {
                                    return Ok(ConnectionHandler::Ssh2(ssh2_session));
                                } else {
                                    return Err(Error::FailedInitialization(String::from(
                                        "Authentication failed",
                                    )));
                                }
                            }
                            Ssh2AuthMode::KeyMemory((username, pem)) => {
                                ssh2_session
                                    .userauth_pubkey_memory(
                                        username.as_str(),
                                        None,
                                        pem.to_string().as_str(), // Pem struct doesn't implement directly '.as_str()' but accepts '.to_string()'
                                        None,
                                    )
                                    .unwrap(); // TODO : add pubkey and passphrase support
                                if ssh2_session.authenticated() {
                                    return Ok(ConnectionHandler::Ssh2(ssh2_session));
                                } else {
                                    return Err(Error::FailedInitialization(String::from(
                                        "Authentication failed",
                                    )));
                                }
                            }
                            // Ssh2AuthMode::Agent(_agent) => {
                            //     return Ok(());
                            // }
                            _ => {
                                return Err(Error::FailedInitialization(String::from(
                                    "Other error",
                                )));
                            }
                        }
                    }
                    Err(e) => {
                        return Err(Error::FailedTcpBinding(format!("{:?}", e)));
                    }
                }
            }
        }
    }

    pub fn run_cmd(&self, cmd: &str, privilege: &Privilege) -> Result<CmdResult, Error> {
        let cmd = final_cmd(cmd.to_string(), &privilege);
        match &self {
            ConnectionHandler::LocalHost(user_info) => {
                let result = match user_info {
                    WhichUser::CurrentUser => Command::new("sh").arg("-c").arg(cmd).output(),
                    WhichUser::PasswordLessUser(username) => Command::new("su")
                        .arg("-")
                        .arg(username)
                        .arg("-c")
                        .arg("sh")
                        .arg("-c")
                        .arg(cmd)
                        .output(),
                    WhichUser::UsernamePassword(credentials) => {
                        let command_content = format!(
                            "echo \"{}\" | su - {} -c \"{}\"",
                            credentials.password, credentials.username, cmd
                        );

                        Command::new("sh").arg("-c").arg(command_content).output()
                    }
                };

                match result {
                    Ok(output) => Ok(CmdResult {
                        rc: output.status.code().unwrap(),
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    }),
                    Err(e) => Err(Error::FailureToRunCommand(format!("{}", e))),
                }
            }
            ConnectionHandler::Ssh2(session) => match session.channel_session() {
                Ok(mut channel) => {
                    if let Err(error_detail) = channel.exec(&cmd) {
                        return Err(Error::FailureToRunCommand(format!("{:?}", error_detail)));
                    }
                    let mut s = String::new();

                    if let Err(e) = channel.read_to_string(&mut s) {
                        return Err(Error::FailureToRunCommand(format!(
                            "Failed to read output: {:?}",
                            e
                        )));
                    }
                    if let Err(e) = channel.wait_close() {
                        return Err(Error::FailureToRunCommand(format!(
                            "Channel wait close error: {:?}",
                            e
                        )));
                    }
                    Ok(CmdResult {
                        rc: channel.exit_status().unwrap_or(-1),
                        stdout: s,
                    })
                }
                Err(e) => {
                    return Err(Error::FailureToEstablishConnection(format!("{:?}", e)));
                }
            },
        }
    }

    pub fn is_this_cmd_available(
        &mut self,
        cmd: &str,
        privilege: &Privilege,
    ) -> Result<bool, Error> {
        let check_cmd_content = format!("which {}", cmd);
        match self.run_cmd(&check_cmd_content, privilege) {
            Ok(check_cmd_result) => {
                if check_cmd_result.rc == 0 {
                    return Ok(true);
                } else {
                    return Ok(false);
                }
            }
            Err(error_detail) => Err(error_detail),
        }
    }
}
