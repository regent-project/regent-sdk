use regent_sdk::ExpectedState;
use regent_sdk::hosts::inventory::Inventory;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let yaml_inventory_builder = r#"---
DefaultConnectionMethod: !Ssh2
    AuthMethod: !Key
        Username: regenter
        Key:
            SecRef: ./ssh/private.key

GlobalVars:
    package_name: httpd
    service_name: bluetooth

Hosts:
  - Id: my_managed_host
    Endpoint: localhost
    HostConnectionMethod: !Ssh2
      AuthMethod: !UsernamePassword
        SecRef: ./dev/credentials.secret
"#;

    let mut inventory = Inventory::from_raw_yaml(yaml_inventory_builder).unwrap();

    // Describe the expected state
    let expected_state_description = r#"---
Attributes:
  - Name: token value set in conf file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line: "A_VERY_LONG_TOKEN"
      State: !Present
      Position: !Top

  - Name: bluetooth available
    Privilege: !None
    Detail: !Service
      Name: "{{ service_name }}"
      CurrentStatus: !Active
      AutoStart: !Enabled
"#;

    let expected_state = match ExpectedState::from_raw_yaml(expected_state_description) {
        Ok(state) => state,
        Err(error_detail) => {
            println!("Wrong yaml content : {:?}", error_detail);
            std::process::exit(1);
        }
    };

    // Build a SecretProvidersPool
    let secret_providers = SecretProvidersPool::from("env_vars", SecretProvider::files());

    // Open connections within this Inventory
    let mut living_inventory = inventory.init(Some(secret_providers)).await.unwrap();

    // Try reach compliance if not already there
    match living_inventory.reach_compliance(&expected_state).await {
        Ok(inventory_compliance) => {
            for (host_id, compliance_status) in inventory_compliance {
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
        }
    }
}
