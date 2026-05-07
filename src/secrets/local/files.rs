use serde::de::DeserializeOwned;

use crate::error::RegentError;
use crate::secrets::Secret;
use crate::secrets::SecretProvidingSolution;

// In here, every secret, encrypted or not, is stored in a reachable/readable file

#[derive(Clone)]
pub struct FilesSecretProvider {}

impl FilesSecretProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl SecretProvidingSolution for FilesSecretProvider {
    async fn connect(&mut self) -> Result<(), RegentError> {
        Ok(())
    }

    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError> {
        // Read the file content as a string
        let raw_content = std::fs::read_to_string(secret_reference).map_err(|details| {
            RegentError::FailedToGetSecret(format!("{} : {}", secret_reference, details))
        })?;

        // Deserialize the content as the requested type T
        match serde_json::from_str::<T>(&raw_content) {
            Ok(content) => Ok(Secret::from(secret_reference, content)),
            Err(parse_details) => Err(RegentError::FailureToParseContent(format!(
                "Content received from secret provider [{}] but failure to parse as {} : {:?}",
                raw_content,
                std::any::type_name::<T>(),
                parse_details
            ))),
        }
    }

    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError> {
        // Read the file content as a string
        match std::fs::read_to_string(secret_reference) {
            Ok(raw_content) => Ok(Secret::from(secret_reference, raw_content)),
            Err(details) => Err(RegentError::FailedToGetSecret(format!(
                "{} : {}",
                secret_reference, details
            ))),
        }
    }
}
