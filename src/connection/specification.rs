use serde::{Deserialize, Serialize};

/// ConnectionMode is not directly withholding different host handlers like Ssh2(Ssh2HostHandler)
/// because Serialize trait is not implemented for one of the Ssh2 structs. Instead, we pass the
/// calling functions all parameters required to build one HostHandler to let the final worker binary build
/// do it by itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionMode {
    Unset,
    LocalHost,
    Ssh2,
    // Ssh3
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Privilege {
    /// Run cmd as the current authenticated user
    Usual,
    /// Run cmd with sudo
    WithSudo,
    /// Run cmd as another user
    AsUser(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub fn from(username: String, password: String) -> Credentials {
        Credentials { username, password }
    }
}

// Message broker (RabbitMQ) part
// TODO: create a dedicated module for this ?

pub const REFRESH_INTERVAL_MILLI_SECONDS: u64 = 300;
