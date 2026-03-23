use crate::secrets::SecretProvider;

// https://developer.hashicorp.com/vault/api-docs

pub struct HashiCorpSecretProvider {}

impl SecretProvider for HashiCorpSecretProvider {}