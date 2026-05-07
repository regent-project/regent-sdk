use serde::de::DeserializeOwned;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::error::RegentError;
use crate::secrets::Secret;
use crate::secrets::SecretProvidingSolution;

use aws_config::SdkConfig as AwsConfig;
use aws_sdk_secretsmanager::Client;

// https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets-rust.html

#[derive(Clone)]
pub struct AwsSecretsManagerProvider {
    aws_client: Client,
}

impl AwsSecretsManagerProvider {
    pub fn from(aws_config: AwsConfig) -> AwsSecretsManagerProvider {
        Self {
            aws_client: Client::new(&aws_config),
        }
    }
}

impl SecretProvidingSolution for AwsSecretsManagerProvider {
    async fn connect(&mut self) -> Result<(), RegentError> {
        match self.aws_client.get_random_password().send().await {
            Ok(_aws_response) => Ok(()),
            Err(details) => {
                error!("Failed to query AWS Secretsmanager : {:?}", details);
                Err(RegentError::FailedToGetSecret(format!(
                    "Failed to query AWS Secretsmanager : {:?}",
                    details
                )))
            }
        }
    }

    async fn get_secret_typed<T: DeserializeOwned>(
        &self,
        secret_reference: &str,
    ) -> Result<Secret<T>, RegentError> {
        match self
            .aws_client
            .get_secret_value()
            .secret_id(secret_reference)
            .send()
            .await
        {
            Ok(aws_response) => match aws_response.secret_string() {
                Some(clear_secret_content) => {
                    match serde_json::from_str::<T>(&clear_secret_content) {
                        Ok(content) => Ok(Secret::from(secret_reference, content)),
                        Err(_parse_details) => Err(RegentError::FailureToParseContent(format!(
                            "Content received from secret provider but failure to parse as {}",
                            std::any::type_name::<T>()
                        ))),
                    }
                }
                None => {
                    error!("Empty response from AWS Secretsmanager");
                    Err(RegentError::FailedToGetSecret(format!(
                        "Empty response from AWS Secretsmanager"
                    )))
                }
            },
            Err(details) => {
                error!("Failed to query AWS Secretsmanager : {:?}", details);
                Err(RegentError::FailedToGetSecret(format!(
                    "Failed to query AWS Secretsmanager : {:?}",
                    details
                )))
            }
        }
    }

    async fn get_secret_raw(&self, secret_reference: &str) -> Result<Secret<String>, RegentError> {
        match self
            .aws_client
            .get_secret_value()
            .secret_id(secret_reference)
            .send()
            .await
        {
            Ok(aws_response) => match aws_response.secret_string() {
                Some(clear_secret_content) => Ok(Secret::from(
                    secret_reference,
                    clear_secret_content.to_string(),
                )),
                None => {
                    error!("Empty response from AWS Secretsmanager");
                    Err(RegentError::FailedToGetSecret(format!(
                        "Empty response from AWS Secretsmanager"
                    )))
                }
            },
            Err(details) => {
                error!("Failed to query AWS Secretsmanager : {:?}", details);
                Err(RegentError::FailedToGetSecret(format!(
                    "Failed to query AWS Secretsmanager : {:?}",
                    details
                )))
            }
        }
    }
}
