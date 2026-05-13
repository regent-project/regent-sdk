use serde::de::DeserializeOwned;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::error::RegentError;
use crate::secrets::Secret;
use crate::secrets::SecretProvidingSolution;

// https://crates.io/crates/google-cloud-secretmanager-v1

use google_cloud_secretmanager_v1::client::SecretManagerService;

#[derive(Clone)]
pub struct GcpSecretProvider {
    gcp_client: SecretManagerService,
}

impl GcpSecretProvider {
    pub async fn new() -> Result<Self, RegentError> {
        match SecretManagerService::builder().with_tracing().build().await {
            Ok(gcp_client) => Ok(GcpSecretProvider { gcp_client }),
            Err(details) => {
                error!(
                    "Failed to create a GCP Secret Manager client : {:?}",
                    details
                );
                Err(RegentError::FailedToGetSecret(format!(
                    "Failed to create a GCP Secret Manager client : {:?}",
                    details
                )))
            }
        }
    }
}

impl SecretProvidingSolution for GcpSecretProvider {
    async fn connect(&mut self) -> Result<(), RegentError> {
        match self.gcp_client.test_iam_permissions().send().await {
            Ok(_test_iam_permissions) => Ok(()),
            Err(details) => Err(RegentError::ProblemWithSecretsProvider(format!(
                "{}",
                details
            ))),
        }
    }

    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str, // projects/1021394879318/secrets/MY_VERY_LONG_TOKEN
    ) -> Result<Secret<T>, RegentError> {
        match self
            .gcp_client
            .access_secret_version()
            .set_name(secret_reference)
            .send()
            .await
        {
            Ok(access_secret_version_response) => match access_secret_version_response.payload {
                Some(secret_payload) => match std::str::from_utf8(&secret_payload.data) {
                    Ok(secret_data_as_str) => match serde_json::from_str::<T>(secret_data_as_str) {
                        Ok(content) => Ok(Secret::from(secret_reference, content)),
                        Err(_parse_details) => Err(RegentError::FailureToParseContent(format!(
                            "Content received from secret provider but failure to parse as {}",
                            std::any::type_name::<T>()
                        ))),
                    },
                    Err(details) => Err(RegentError::FailedToGetSecret(format!(
                        "Secret {} contains invalid UTF-8 sequence: {}",
                        secret_reference, details
                    ))),
                },
                None => Err(RegentError::FailedToGetSecret(format!(
                    "Empty secret {}: GCP API returned an AccessSecretVersionResponse with field payload = None",
                    secret_reference
                ))),
            },
            Err(details) => Err(RegentError::FailedToGetSecret(format!(
                "Failed to retrieve secret {}: {:?}",
                secret_reference, details
            ))),
        }
    }

    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError> {
        match self
            .gcp_client
            .access_secret_version()
            .set_name(secret_reference)
            .send()
            .await
        {
            Ok(access_secret_version_response) => match access_secret_version_response.payload {
                Some(secret_payload) => match std::str::from_utf8(&secret_payload.data) {
                    Ok(secret_data_as_str) => Ok(Secret::from(
                        secret_reference,
                        secret_data_as_str.to_string(),
                    )),
                    Err(details) => Err(RegentError::FailedToGetSecret(format!(
                        "Secret {} contains invalid UTF-8 sequence: {}",
                        secret_reference, details
                    ))),
                },
                None => Err(RegentError::FailedToGetSecret(format!(
                    "Empty secret {}: GCP API returned an AccessSecretVersionResponse with field payload = None",
                    secret_reference
                ))),
            },
            Err(details) => Err(RegentError::FailedToGetSecret(format!(
                "Failed to retrieve secret {}: {:?}",
                secret_reference, details
            ))),
        }
    }
}
