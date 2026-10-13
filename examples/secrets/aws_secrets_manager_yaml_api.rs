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

    let expected_state_description = r#"---
Attributes:
  - Name: token value set in conf file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      State: !Present
        Position: !InsertBefore BOF
      Line: !Raw
        SecRef: arn:aws:secretsmanager:eu-central-1:658712556498:secret:MY_TOKEN_CONTENT-xyz
        Provider: aws_prod_account

  - Name: last line from a file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      State: !Present
        Position: !InsertAfter EOF
      Line: !Raw
        SecRef: LAST_LINE_CONTENT
        Provider: env_vars
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    // We need to provide an AWS SdkConfig object for the Regent SecretProvider to be able to connect to AWS Secretsmanager.
    // This part is not handled by the Regent crate. Refer to official aws_config crate documentation for this.
    let config_aws = aws_config::load_from_env().await;

    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&SecretProvider::env_var("env_vars"))
        .add_provider(&SecretProvider::aws_secretsmanager(
            "aws_prod_account",
            config_aws,
        ))
        .build()
        .unwrap();

    let mut living_inventory = inventory.init(Some(secrets_providers_pool)).await.unwrap();

    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
