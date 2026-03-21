use crate::secrets::SecretProvider;

// In here, every secret, encrypted or not, is reachable by the application through an environment variable

pub struct EnvVarSecretProvider {}

impl SecretProvider for EnvVarSecretProvider {}