use serde::{Deserialize, Serialize};

use crate::secrets::SecretReference;

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
#[serde(rename_all = "PascalCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoginKey {
    username: String,
    key: String,
}

impl LoginKey {
    pub fn from(username: String, key: String) -> Self {
        Self { username, key }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct LoginKeyRef {
    username: String,
    key: SecretReference,
}

impl LoginKeyRef {
    pub fn from(username: String, key: SecretReference) -> Self {
        Self { username, key }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn key_ref(&self) -> &SecretReference {
        &self.key
    }
}
