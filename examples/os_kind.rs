use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::TargetUser;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::SecretProvider;
use regent_sdk::secrets::local::environment_variables::EnvVarSecretProvider;

fn main() {
    // Build a SecretProvider
    let secret_provider = SecretProvider::EnvironmentVariable(EnvVarSecretProvider::new());

    // Describe the ManagedHost
    let mut managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<address:port>",
        Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    )
    .build(Some(secret_provider))
    .unwrap();

    // Open connection with this ManagedHost
    assert!(managed_host.connect().is_ok());

    // What kind of OS are we dealing with ?
    match managed_host.collect_properties() {
        Ok(()) => {
            println!("Host properties : {:?}", managed_host.get_host_properties());
        }
        Err(error_detail) => {
            println!("Unable to collect host properties : {:?}", error_detail);
        }
    }
}
