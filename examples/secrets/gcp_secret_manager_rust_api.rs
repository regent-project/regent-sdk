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

    // Declare the secret providers first: the expected state refers to them directly.
    // Authentication is handled outside of this crate. For GCP, we run '$ gcloud auth application-default login' prior to running this example.
    let env_vars = SecretProvider::env_var("env_vars");
    let gcp_secret_manager = SecretProvider::gcp_secretmanager("gpc_secret_manager")
        .await
        .unwrap();

    let token_from_gcp = LineInFileExpectedState::present_at_top(
        "~/my_token",
        LineInFileExpectedState::raw_line_from_secret(SecretReference::from_provider(
            "projects/1020394869318/secrets/MY_VERY_LONG_TOKEN/versions/latest",
            &gcp_secret_manager,
        )),
        None,
    );

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::lineinfile(
            token_from_gcp,
            Privilege::None,
            Some("token value set in conf file".to_string()),
        ))
        .build();

    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&env_vars)
        .add_provider(&gcp_secret_manager)
        .build()
        .unwrap();

    let mut living_inventory = inventory.init(Some(secrets_providers_pool)).await.unwrap();

    living_inventory
        .reach_compliance(&expected_state)
        .await
        .unwrap();
}
