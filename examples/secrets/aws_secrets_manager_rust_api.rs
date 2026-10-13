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

    // We need to provide an AWS SdkConfig object for the Regent SecretProvider to be able to connect to AWS Secretsmanager.
    // This part is not handled by the Regent crate. Refer to official aws_config crate documentation for this.
    let config_aws = aws_config::load_from_env().await;

    // Declare the secret providers first: the expected state refers to them directly
    let env_vars = SecretProvider::env_var("env_vars");
    let aws_prod_account = SecretProvider::aws_secretsmanager("aws_prod_account", config_aws);

    let token_from_aws = LineInFileExpectedState::present_at_top(
        "~/my_token",
        LineInFileExpectedState::raw_line_from_secret(SecretReference::from_provider(
            "arn:aws:secretsmanager:eu-central-1:658712556498:secret:MY_TOKEN_CONTENT-xyz",
            &aws_prod_account,
        )),
        None,
    );

    let last_line_from_env_var = LineInFileExpectedState::present_at_bottom(
        "~/my_token",
        LineInFileExpectedState::raw_line_from_secret(SecretReference::from_provider(
            "LAST_LINE_CONTENT",
            &env_vars,
        )),
        None,
    );

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::lineinfile(
            token_from_aws,
            Privilege::None,
            Some("token value set in conf file".to_string()),
        ))
        .with_attribute(Attribute::lineinfile(
            last_line_from_env_var,
            Privilege::None,
            Some("last line from a file".to_string()),
        ))
        .build();

    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&env_vars)
        .add_provider(&aws_prod_account)
        .build()
        .unwrap();

    let mut living_inventory = inventory.init(Some(secrets_providers_pool)).await.unwrap();

    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
