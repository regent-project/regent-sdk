use regent_sdk::ExpectedState;
use regent_sdk::hosts::inventory::InventoryBuilder;
use regent_sdk::secrets::SecretProvider;

fn main() {
    let yaml_inventory_builder = r#"---
DefaultConnectionMethod: !Ssh2
    AuthMethod: !Key
        Username: regenter
        Key:
            SecRef: ssh/private.key

GlobalVars:
    package_name: httpd
    version: 1.2.3

Hosts:
  - Id: my_first_host
    Endpoint: localhost
    HostVars:
        version: 2.3.4

  - Id: my_second_host
    Endpoint: localhost
    HostConnectionMethod: !Ssh2
      AuthMethod: !UsernamePassword
        SecRef: credentials.secret
"#;

    let mut inventory = InventoryBuilder::from_raw_yaml(yaml_inventory_builder)
        .unwrap()
        .build()
        .unwrap();
    println!("{:#?}", inventory);

    // Describe the expected state
    let expected_state_description = r#"---
Attributes:
  - Privilege: !None
    Detail: !Service
      Name: httpd
      CurrentStatus: !Active
      AutoStart: !Enabled

  - Privilege: !None
    Detail: !Command
      Cmd: sleep 2
"#;

    let expected_state = match ExpectedState::from_raw_yaml(expected_state_description) {
        Ok(state) => state,
        Err(error_detail) => {
            println!("Wrong yaml content : {:?}", error_detail);
            std::process::exit(1);
        }
    };

    // Open connections within this Inventory
    let mut living_inventory = inventory.init(&Some(SecretProvider::files())).unwrap();

    // Assess whether the host is compliant or not
    match living_inventory.reach_compliance(&expected_state) {
        Ok(inventory_comliance) => {
            for (host_id, compliance_status) in inventory_comliance {
                if compliance_status.is_already_compliant() {
                    println!("Congratulations, {} is already compliant !", host_id);
                } else {
                    println!(
                        "Oups ! {} is not compliant. Here is the list of required remediations :",
                        host_id
                    );

                    for remediation in compliance_status.all_remediations() {
                        println!("*** {:?}", remediation);
                    }
                }
            }
        }
        Err(error_detail) => {
            println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
