use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::secrets::Secret;
use crate::secrets::SecretProvider;

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

    fn get_secret<T: DeserializeOwned>(&self, secret_reference: &str) -> Result<Secret<T>, Error> {
        match std::env::var(secret_reference) {
            Ok(raw_content) => match serde_json::from_str::<T>(&raw_content) {
                Ok(content) => Ok(Secret::from(content)),
                Err(_parse_error_detail) => Err(Error::FailureToParseContent(format!(
                    "Content received from secret provider but failure to parse as {}",
                    std::any::type_name::<T>()
                ))),
            },
            Err(error_detail) => Err(Error::FailedToGetSecret(format!(
                "{} : {}",
                secret_reference, error_detail
            ))),
        }
    }
}
