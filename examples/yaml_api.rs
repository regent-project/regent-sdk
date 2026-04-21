use regent_sdk::ExpectedState;
use regent_sdk::hosts::inventory::InventoryBuilder;
use regent_sdk::secrets::SecretProvider;

fn main() {
    let yaml_inventory_builder = r#"---
DefaultConnectionMethod: !Ssh2
    AuthMethod: !Key
        Username: regenter
        Key:
            SecRef: ./ssh/private.key

GlobalVars:
    package_name: httpd

Hosts:
  - Id: my_host
    Endpoint: localhost
    HostConnectionMethod: !Ssh2
      AuthMethod: !UsernamePassword
        SecRef: ./dev/credentials.secret
    HostVars:
        line_content: "ABCD1234"
"#;

    let mut inventory = InventoryBuilder::from_raw_yaml(yaml_inventory_builder)
        .unwrap()
        .build()
        .unwrap();

    // Describe the expected state
    let expected_state_description = r#"---
Attributes:
  - Privilege: !None
    Detail: !LineInFile
      FilePath: ~/my_token
      Line: "{{ line_content }}"
      State: !Present
      Position: !Top

  - Privilege: !WithSudoRs
    Detail: !Service
      Name: "{{ package_name }}"
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

    let secret_provider = Some(SecretProvider::files());

    // Open connections within this Inventory
    let mut living_inventory = inventory.init(&secret_provider).unwrap();

    // Try reach compliance if not already there
    match living_inventory.reach_compliance(&expected_state, &secret_provider) {
        Ok(inventory_compliance) => {
            for (host_id, compliance_status) in inventory_compliance {
                if compliance_status.is_already_compliant() {
                    println!("Congratulations, {} is already compliant !", host_id);
                } else {
                    println!(
                        "Oups ! {} is not compliant. Here is the list of required remediations :",
                        host_id
                    );

                    for (remediation, remediation_outcome) in compliance_status.actions_taken() {
                        println!("*** {:?} -> {:?}", remediation, remediation_outcome);
                    }
                }
            }
        }
        Err(error_detail) => {
            println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
