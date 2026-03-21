pub mod environment_variables;
pub mod files;
pub mod aws_secrets_manager;
pub mod gcp_secret_manager;
pub mod delinea_secret_server;
pub mod hashicorp_vault;
mod infisical;

pub enum SecretsManagementSolution {
    Files,
    EnvironmentVariable,
    AwsSecretsManager,
    GcpSecretManager,
    DelineaSecretServer,
    HashicorpVault
}

// Each SecretsManagementSolution variant's nested type must implement this trait
pub trait SecretProvider {
    // fn get_secret(secret_reference: String) -> Secret;
}


// Wrapper type which holds secrets content and helps to avoid leaking secrets (usual or debug logging in general...)
pub struct Secret {}