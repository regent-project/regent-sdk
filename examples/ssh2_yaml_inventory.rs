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
Hosts:

  - Id: localhost_1
    Endpoint: localhost
    ConnectionMethod: !Ssh2
      AuthMethod: !UsernamePassword
        SecRef: credentials.secret

  - Id: localhost_2
    Endpoint: localhost
    ConnectionMethod: !Ssh2
      AuthMethod: !UsernamePassword
        SecRef: credentials.secret
"#;

    let inventory_builder = InventoryBuilder::from_raw_yaml(yaml_inventory_builder).unwrap();

    let mut inventory = inventory_builder
        .build(&Some(SecretProvider::files()))
        .unwrap();

    // Open connection with this ManageHost
    assert!(inventory.connect().is_ok());

    // Describe the expected state
    let httpd_service_active_and_enabled = ServiceBlockExpectedState::builder("httpd")
        .with_service_state(ServiceExpectedStatus::Active)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    let very_long_operation = Attribute::command(
        CommandBlockExpectedState::builder("sleep 5"),
        Privilege::None,
    );

    let localhost_expected_state = ExpectedState::new()
        .with_attribute(Attribute::service(
            httpd_service_active_and_enabled,
            Privilege::None,
        ))
        .with_attribute(very_long_operation)
        .build();

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
