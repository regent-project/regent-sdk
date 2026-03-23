use crate::secrets::SecretProvider;

// https://crates.io/crates/google-cloud-secretmanager-v1

pub struct GcpSecretProvider {}

impl SecretProvider for GcpSecretProvider {}