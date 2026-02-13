use regent_sdk::attribute::package::apt::{AptBlockExpectedState, PackageExpectedState};
use regent_sdk::{Attribute, ExpectedState};
use regent_sdk::{ManagedHost, Privilege, Ssh2HostHandler};

fn main() {
    // Describe the ManagedHost
    let mut managed_host = ManagedHost::new(
        "<host-endpoint>:<port>",
        Ssh2HostHandler::key_file("regent-user", "<path/to/private/key>"),
    );

    // Open connection with this ManageHost
    managed_host.connect().unwrap();

    // Describe the expected state
    let apache_expected_state = AptBlockExpectedState::builder()
        .with_package_state("apache2", PackageExpectedState::Present)
        .build()
        .unwrap();

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::apt(apache_expected_state, Privilege::WithSudo))
        .build();

    // Assess whether the host is compliant or not
    match managed_host.assess_compliance(&expected_state) {
        Ok(compliance_status) => {
            if compliance_status.is_already_compliant() {
                println!("Congratulations, host is already compliant !");
            } else {
                println!(
                    "Oups ! Host is not compliant. Here is the list of required remediations : {:#?}",
                    compliance_status.all_remediations()
                );

                // If not, try once to reach compliance
                match managed_host.reach_compliance(&expected_state) {
                    Ok(outcome) => {
                        println!(
                            "Try reach compliance outcome : {:#?}",
                            outcome.actions_taken()
                        );
                    }
                    Err(error_detail) => {
                        println!("Unable to try to reach compliance : {:#?}", error_detail);
                    }
                }
            }
        }
        Err(error_detail) => {
            println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
