use regent_sdk::Privilege;
use regent_sdk::attribute::system::service::{
    ServiceBlockExpectedState, ServiceExpectedAutoStart, ServiceExpectedStatus,
};
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::ssh2::Ssh2Auth;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::SecretProvider;
use regent_sdk::{Attribute, ExpectedState};

fn main() {
    let secret_provider = SecretProvider::files();

    // Describe the ManagedHost
    let mut managed_host = ManagedHostBuilder::new("<host-id>", "localhost")
        .connection_method(ConnectionMethod::Ssh2(Ssh2Auth::username_password(
            "credentials.secret",
        )))
        .build(&Some(secret_provider))
        .unwrap();

    // Open connection with this ManageHost
    assert!(managed_host.connect().is_ok());

    // Describe the expected state
    let httpd_service_active_and_enabled = ServiceBlockExpectedState::builder("httpd")
        .with_service_state(ServiceExpectedStatus::Active)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    let localhost_expected_state = ExpectedState::new()
        .with_attribute(Attribute::service(
            httpd_service_active_and_enabled,
            Privilege::None,
        ))
        .build();

    // Assess whether the host is compliant or not
    match managed_host.assess_compliance(&localhost_expected_state) {
        Ok(compliance_status) => {
            if compliance_status.is_already_compliant() {
                println!("Congratulations, host is already compliant !");
            } else {
                println!(
                    "Oups ! Host is not compliant. Here is the list of required remediations :"
                );

                for remediation in compliance_status.all_remediations() {
                    println!("*** {:?}", remediation);
                }
            }
        }
        Err(error_detail) => {
            println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
