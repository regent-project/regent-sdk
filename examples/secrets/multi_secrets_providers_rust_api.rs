use regent_sdk::attribute::utilities::lineinfile::LineInFileExpectedState;
use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
use regent_sdk::hosts::inventory::Inventory;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder, SecretReference};
use regent_sdk::{Attribute, ExpectedState, Privilege};
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let managed_host = ManagedHostBuilder::new(
        "my_managed_host",
        "localhost",
        Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    );

    let mut inventory = Inventory::from(
        "my_inventory".to_string(),
        HashMap::from([(managed_host.id().to_string(), managed_host)]),
    );

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

    // Each line of the file comes from a different provider
    let conf_file = "~/.my_app_conf_file";

    let first_line_from_aws = LineInFileExpectedState::present_at_top(
        conf_file,
        LineInFileExpectedState::raw_line_from_secret(SecretReference::from_provider(
            "arn:aws:secretsmanager:eu-central-1:123456789:secret:MY_TOKEN_CONTENT-xyz",
            &aws_secretsmanager_prod_account,
        )),
        None,
    );

    let second_line_from_gcp = LineInFileExpectedState::present_at_bottom(
        conf_file,
        LineInFileExpectedState::raw_line_from_secret(SecretReference::from_provider(
            "projects/123456789123/secrets/MY_VERY_LONG_TOKEN/versions/latest",
            &gcp_secretmanager_regent_project,
        )),
        None,
    );

    let third_line_from_env_var = LineInFileExpectedState::present_at_bottom(
        conf_file,
        LineInFileExpectedState::raw_line_from_secret(SecretReference::from_provider(
            "THIRD_LINE_CONTENT",
            &default_secrets_provider,
        )),
        None,
    );

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::lineinfile(
            first_line_from_aws,
            Privilege::None,
            Some("first line from AWS...".to_string()),
        ))
        .with_attribute(Attribute::lineinfile(
            second_line_from_gcp,
            Privilege::None,
            Some("...second line from GCP...".to_string()),
        ))
        .with_attribute(Attribute::lineinfile(
            third_line_from_env_var,
            Privilege::None,
            Some("...and the 3rd line taken out of an environment variable".to_string()),
        ))
        .build();

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
