use regent_sdk::ExpectedState;
use regent_sdk::hosts::inventory::Inventory;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let yaml_inventory_builder = r#"---
DefaultConnectionMethod: !Localhost
    UserKind: !CurrentUser

Hosts:
  - Id: my_managed_host
    Endpoint: localhost
"#;

    let mut inventory = Inventory::from_raw_yaml(yaml_inventory_builder).unwrap();

    // Describe the expected state
    let expected_state_description = r#"---
Attributes:
  - Name: first line from an environment variable
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line:
        Provider: env_var
        SecRef: TOKEN_CONTENT
      State: !Present
      Position: !Top

  - Name: last line from a file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line:
        SecRef: /home/romzor/last_line
      State: !Present
      Position: !Bottom
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .add_default_provider("files", SecretProvider::files())
        .add_provider("env_var", SecretProvider::env_var())
        .build()
        .unwrap();

    let mut living_inventory = inventory.init(Some(secrets_providers_pool)).await.unwrap();

    // Try reach compliance if not already there
    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
