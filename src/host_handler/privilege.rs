use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Privilege {
    /// Run cmd as the current authenticated user
    None,
    // /// Run cmd as another user using su
    // WithSuAsUser(Credentials),
    /// Run cmd with sudo
    WithSudo,
    // /// Run cmd as another user using sudo
    // WithSudoAsUser(Credentials),
    /// Run cmd with sudo-rs
    WithSudoRs,
    // /// Run cmd as another user using sudo-rs
    // WithSudoRsAsUser(Credentials),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn from(username: &str, password: &str) -> Credentials {
        Credentials {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}