use serde::de::DeserializeOwned;

use crate::error::Error;
use crate::secrets::Secret;
use crate::secrets::SecretProvidingSolution;

// In here, every secret, encrypted or not, is reachable by the application through an environment variable

#[derive(Clone)]
pub struct EnvVarSecretProvider {}

impl EnvVarSecretProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl SecretProvidingSolution for EnvVarSecretProvider {
    fn connect() -> Result<(), Error> {
        Ok(())
    }

    fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, Error> {
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

    fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, Error> {
        match std::env::var(secret_reference) {
            Ok(raw_content) => Ok(Secret::from(raw_content)),
            Err(error_detail) => Err(Error::FailedToGetSecret(format!(
                "{} : {}",
                secret_reference, error_detail
            ))),
        }
    }
}
