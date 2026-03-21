use std::str::FromStr;
use serde::{Serialize, Deserialize};

use crate::error::Error;
use crate::secrets::SecretProvider;
use crate::secrets::Secret;

// In here, every secret, encrypted or not, is reachable by the application through an environment variable

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarSecretProvider {}

impl EnvVarSecretProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl SecretProvider for EnvVarSecretProvider {
    fn connect() -> Result<(), Error> {
        Ok(())
    }
    
    fn get_secret<T: FromStr>(secret_reference: String) -> Result<Secret<T>, Error> {
        match std::env::var(secret_reference) {
            Ok(raw_content) => {
                match raw_content.parse::<T>() {
                    Ok(content) => {
                        Ok(Secret::from(content))
                    }
                    Err(_parse_error_detail) => {
                        Err(Error::FailureToParseContent(format!("Content received from secret provider but failure to parse as {}", std::any::type_name::<T>())))
                    }
                }
            }
            Err(error_detail) => {
                Err(Error::FailedToGetSecret(format!("{}", error_detail)))
            }
        }
    }
}