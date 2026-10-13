use regent_sdk::attribute::system::service::ServiceExpectedState;
use regent_sdk::attribute::utilities::lineinfile::LineInFileExpectedState;
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::ssh2::Ssh2Auth;
use regent_sdk::hosts::inventory::Inventory;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool, SecretReference};
use regent_sdk::{Attribute, ExpectedState, Privilege};
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let files = SecretProvider::files("files");
    let secret_providers = SecretProvidersPool::with_default_provider(&files);

    // Describe the hosts, with the variables available in their expected state
    let mut managed_host = ManagedHostBuilder::new(
        "my_managed_host",
        "localhost",
        Some(ConnectionMethod::Ssh2(Ssh2Auth::username_password(
            SecretReference::from_provider("./dev/credentials.secret", &files),
        ))),
    );
    managed_host.set_host_vars(Some(HashMap::from([
        ("package_name".to_string(), "httpd".to_string()),
        ("service_name".to_string(), "bluetooth".to_string()),
    ])));

    let mut inventory = Inventory::from(
        "my_inventory".to_string(),
        HashMap::from([(managed_host.id().to_string(), managed_host)]),
    );

    let token_is_set = LineInFileExpectedState::present_at_top(
        "~/my_token",
        LineInFileExpectedState::raw_line_from_str("A_VERY_LONG_TOKEN"),
        None,
    );

    // "{{ service_name }}" is rendered with the variables of each host
    let service_is_available = ServiceExpectedState::started_and_enabled("{{ service_name }}");

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::lineinfile(
            token_is_set,
            Privilege::None,
            Some("token value set in conf file".to_string()),
        ))
        .with_attribute(Attribute::service(
            service_is_available,
            Privilege::None,
            Some("bluetooth available".to_string()),
        ))
        .build();

    // Open connections within this Inventory
    let mut living_inventory = inventory.init(Some(secret_providers)).await.unwrap();

    match living_inventory.reach_compliance(&expected_state).await {
        Ok(inventory_compliance) => {
            for (_host_id, compliance_status) in inventory_compliance {
                if compliance_status.is_already_compliant() {
                    // Do something with that information
                } else {
                    // This host was not compliant. Actions have been taken to remedy this situation.
                    // You have access to what was done :
                    // - in realtime through tracing events created on the fly
                    // - after the fact with this :
                    for (remediation, remediation_outcome) in compliance_status.actions_taken() {
                        println!("*** {:?} -> {:?}", remediation, remediation_outcome);
                    }
                }
            }
        }
        Err(error_detail) => {
            // Something went seriously wrong and forbade from even trying to assess/reach compliance.
            println!("Unable to reach compliance : {:?}", error_detail);
        }
    }
}
