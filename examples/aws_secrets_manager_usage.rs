use regent_sdk::ExpectedState;
use regent_sdk::hosts::inventory::Inventory;
use regent_sdk::secrets::SecretProvider;
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
  - Name: token value set in conf file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line:
        SecRef: arn:aws:secretsmanager:eu-central-1:658712556498:secret:MY_TOKEN_CONTENT-xyz
      State: !Present
      Position: !Top
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    // We need to provide an AWS SdkConfig object for the Regent SecretProvider to be able to connect to AWS Secretsmanager.
    // This part is not handled by the Regent crate. Refer to official aws_config crate documentation for this.
    let config_aws = aws_config::load_from_env().await;

    // Once the SdkConfig object is built, pass it to this helper method...
    let secret_provider = SecretProvider::aws_secretsmanager(config_aws);

    // ... and just use this newly built secret_provider like any other Regent secret provider.
    let mut living_inventory = inventory.init(Some(secret_provider)).await.unwrap();

    // Try reach compliance if not already there
    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
