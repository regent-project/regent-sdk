use serde::de::DeserializeOwned;

use crate::error::RegentError;
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
    fn connect() -> Result<(), RegentError> {
        Ok(())
    }

    fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError> {
        match std::env::var(secret_reference) {
            Ok(raw_content) => match serde_json::from_str::<T>(&raw_content) {
                Ok(content) => Ok(Secret::from(secret_reference, content)),
                Err(_parse_details) => Err(RegentError::FailureToParseContent(format!(
                    "Content received from secret provider but failure to parse as {}",
                    std::any::type_name::<T>()
                ))),
            },
            Err(details) => Err(RegentError::FailedToGetSecret(format!(
                "{} : {}",
                secret_reference, details
            ))),
        }
    }

    fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError> {
        match std::env::var(secret_reference) {
            Ok(raw_content) => Ok(Secret::from(secret_reference, raw_content)),
            Err(details) => Err(RegentError::FailedToGetSecret(format!(
                "{} : {}",
                secret_reference, details
            ))),
        }
    }
}
