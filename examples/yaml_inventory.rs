use regent_sdk::Privilege;
use regent_sdk::attribute::shell::command::CommandBlockExpectedState;
use regent_sdk::attribute::system::service::{
    ServiceBlockExpectedState, ServiceExpectedAutoStart, ServiceExpectedStatus,
};
use regent_sdk::hosts::inventory::InventoryBuilder;
use regent_sdk::secrets::SecretProvider;
use regent_sdk::{Attribute, ExpectedState};

fn main() {
    let yaml_inventory_builder = r#"---
ConnectionMethod: !Ssh2
    AuthMethod: !Key
        Username: regenter
        Key:
            SecRef: /path/to/ssh/private.key

Hosts:

  - Id: my_first_host
    Endpoint: <address:port>

  - Id: my_second_host
    Endpoint: <address:port>
    ConnectionMethod: !Ssh2
      AuthMethod: !UsernamePassword
        SecRef: /path/to/credentials/secret
"#;

    let inventory_builder = InventoryBuilder::from_raw_yaml(yaml_inventory_builder).unwrap();

    let mut inventory = inventory_builder
        .build(&Some(SecretProvider::files()))
        .unwrap();

    // Describe the expected state
    let httpd_service_active_and_enabled = ServiceBlockExpectedState::builder("httpd")
        .with_service_state(ServiceExpectedStatus::Active)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    let very_long_operation = Attribute::command(
        CommandBlockExpectedState::builder("sleep 2"),
        Privilege::None,
    );

    let localhost_expected_state = ExpectedState::new()
        .with_attribute(very_long_operation)
        .with_attribute(Attribute::service(
            httpd_service_active_and_enabled,
            Privilege::None,
        ))
        .build();

    // Open connections within this Inventory
    if let Err(details) = inventory.connect() {
        println!("Failed to connect to hosts : {:?}", details);
        std::process::exit(1);
    }

    // Assess whether the host is compliant or not
    match inventory.reach_compliance(&localhost_expected_state) {
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
