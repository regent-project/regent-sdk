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
  - Name: first line from AWS...
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/.my_app_conf_file
      State: !Present
        Position: !InsertBefore BOF
      Line: !Raw
        SecRef: arn:aws:secretsmanager:eu-central-1:123456789:secret:MY_TOKEN_CONTENT-xyz
        Provider: aws_prod_account

  - Name: ...second line from GCP...
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/.my_app_conf_file
      State: !Present
        Position: !InsertAfter EOF
      Line: !Raw
        SecRef: projects/123456789123/secrets/MY_VERY_LONG_TOKEN/versions/latest
        Provider: gcp_regent_project

  - Name: ...and the 3rd line taken out of an environment variable (default provider)
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/.my_app_conf_file
      State: !Present
        Position: !InsertAfter EOF
      Line: !Raw
        SecRef: THIRD_LINE_CONTENT
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    // By default, secrets will be taken from environment variables...
    let default_secrets_provider = SecretProvider::env_var("env_var");

    // ...but we will also have secrets on AWS SecretsManager...
    let config_aws = aws_config::load_from_env().await;
    let aws_secretsmanager_prod_account =
        SecretProvider::aws_secretsmanager("aws_prod_account", config_aws);

    // ...and also on Google Cloud SecretManager, because why not ?
    let gcp_secretmanager_regent_project = SecretProvider::gcp_secretmanager("gcp_regent_project")
        .await
        .unwrap();

    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&default_secrets_provider)
        .add_provider(&aws_secretsmanager_prod_account)
        .add_provider(&gcp_secretmanager_regent_project)
        .build()
        .unwrap();

    let mut living_inventory = inventory.init(Some(secrets_providers_pool)).await.unwrap();

    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
