use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::TargetUser;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};

#[tokio::main]
async fn main() {
    let secret_providers =
        SecretProvidersPool::with_default_provider(&SecretProvider::env_var("env_vars"));

    let mut managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<address:port>",
        Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    )
    .build(Some(secret_providers))
    .await
    .unwrap();

    assert!(managed_host.connect().await.is_ok());

    // What kind of OS are we dealing with ?
    match managed_host.collect_properties().await {
        Ok(()) => {
            println!("Host properties : {:?}", managed_host.get_host_properties());
        }
        Err(error_detail) => {
            println!("Unable to collect host properties : {:?}", error_detail);
        }
    }
}
