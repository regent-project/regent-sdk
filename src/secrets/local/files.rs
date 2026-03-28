use serde::de::DeserializeOwned;

use crate::error::Error;
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
    fn connect() -> Result<(), Error> {
        Ok(())
    }

    fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, Error> {
        // Read the file content as a string
        let raw_content = std::fs::read_to_string(secret_reference).map_err(|error_detail| {
            Error::FailedToGetSecret(format!("{} : {}", secret_reference, error_detail))
        })?;

        // Deserialize the content as the requested type T
        match serde_json::from_str::<T>(&raw_content) {
            Ok(content) => Ok(Secret::from(content)),
            Err(parse_error_detail) => Err(Error::FailureToParseContent(format!(
                "Content received from secret provider but failure to parse as {} : {:?}",
                std::any::type_name::<T>(),
                parse_error_detail
            ))),
        }
    }

    fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, Error> {
        // Read the file content as a string
        match std::fs::read_to_string(secret_reference) {
            Ok(raw_content) => Ok(Secret::from(raw_content)),
            Err(error_detail) => Err(Error::FailedToGetSecret(format!(
                "{} : {}",
                secret_reference, error_detail
            ))),
        }
    }
}
