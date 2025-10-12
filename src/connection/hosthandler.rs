use crate::connection::connectionmode::localhost::{LocalHostConnectionDetails, LocalHostHandler};
use crate::connection::connectionmode::ssh2mode::{Ssh2ConnectionDetails, Ssh2HostHandler};
use crate::connection::specification::{ConnectionMode, Privilege};
use crate::error::Error;
use crate::result::cmd::CmdResult;
use serde::{Deserialize, Serialize};

use super::host_connection::HostConnectionInfo;

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

    pub fn run_cmd(&mut self, cmd: &str, privilege: Privilege) -> Result<CmdResult, Error> {
        let final_cmd = final_cmd(cmd.to_string(), privilege.clone());
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
fn final_cmd(cmd: String, privilege: Privilege) -> String {
    match privilege {
        Privilege::Usual => {
            return format!("{} 2>&1", cmd);
        }
        Privilege::WithSudo => {
            let final_cmd = format!("sudo -u root {} 2>&1", cmd);
            return final_cmd;
        }
        Privilege::AsUser(username) => {
            let final_cmd = format!("sudo -u {} {} 2>&1", username, cmd);
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
