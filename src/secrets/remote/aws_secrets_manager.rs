use crate::{RegentError, secrets::SecretProvider};

// https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets-rust.html

pub struct AwsSecretManagerConnector {}

impl AwsSecretManagerConnector {
    pub fn from(
        region: &str,
        access_key_id: &str,
        secret_access_key: &str
    ) -> Result<AwsSecretManagerConnector, RegentError> {
        todo!()
    }
}

impl SecretProvider for AwsSecretManagerConnector {}