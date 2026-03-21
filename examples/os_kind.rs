use regent_sdk::{LocalHostHandler, ManagedHost};
use regent_sdk::secrets::environment_variables::EnvVarSecretProvider;
use regent_sdk::secrets::SecretsManagementSolution;

fn main() {
    // Build a SecretProvider
    let env_var_secret_provider = SecretsManagementSolution::EnvironmentVariable(EnvVarSecretProvider::new());// EnvVarSecretProvider::new();

    // Describe the ManagedHost
    let mut managed_host = ManagedHost::new(
        "localhost",
        env_var_secret_provider,
        LocalHostHandler::new(regent_sdk::WhichUser::CurrentUser),
    );

    // Open connection with this ManageHost
    managed_host.connect().unwrap();

    // What kind of Os are we dealing with ?
    match managed_host.collect_properties() {
        Ok(()) => {
            println!("Host properties : {:?}", managed_host.get_host_properties());
        }
        Err(error_detail) => {
            println!("Unable to collect host properties : {:?}", error_detail);
        }
    }
}
