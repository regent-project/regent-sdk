use regent_sdk::ExpectedState;
use regent_sdk::hosts::inventory::InventoryBuilder;
use regent_sdk::secrets::SecretProvider;
use tracing_subscriber;

fn main() {
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

    let mut inventory = InventoryBuilder::from_raw_yaml(yaml_inventory_builder)
        .unwrap()
        .build()
        .unwrap();

    // Describe the expected state
    let expected_state_description = r#"---
Attributes:
  - Name: token value set in conf file
    Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      #Line: "{{ hello }}"
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

    let secret_provider = SecretProvider::files();

    // Open connections within this Inventory
    let mut living_inventory = inventory.init(Some(secret_provider)).unwrap();

    // Try reach compliance if not already there
    match living_inventory.reach_compliance(&expected_state) {
        Ok(inventory_compliance) => {
            // for (host_id, compliance_status) in inventory_compliance {
            //     if compliance_status.is_already_compliant() {
            //         println!("Congratulations, {} is already compliant !", host_id);
            //     } else {
            //         println!(
            //             "Oups ! {} is not compliant. Here is the list of required remediations :",
            //             host_id
            //         );

            //         for (remediation, remediation_outcome) in compliance_status.actions_taken() {
            //             println!("*** {:?} -> {:?}", remediation, remediation_outcome);
            //         }
            //     }
            // }
        }
        Err(_error_detail) => {
            // println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
