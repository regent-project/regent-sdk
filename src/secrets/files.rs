use crate::secrets::SecretProvider;

// In here, every secret, encrypted or not, is stored in a reachable/readable file

pub struct FilesSecretProvider {}

impl SecretProvider for FilesSecretProvider {}