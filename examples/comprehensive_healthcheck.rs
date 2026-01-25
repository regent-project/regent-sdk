use regent_sdk::expected_state::global_state::{CompliancyStatus, DryRunMode, ExpectedState};
use regent_sdk::{Apt, Attribute, Service};
use regent_sdk::{
    ManagedHost, NewConnectionDetails, NewSsh2ConnectionDetails, Privilege, Ssh2AuthMode,
};
use std::thread::sleep;
use std::time::Duration;

// Performs a comprehensive health check on a managed host by continuously assessing
// compliance with expected system state and attempting remediation when necessary.
//
// This function runs an infinite loop that:
// 1. Checks if the host is compliant with the expected state
// 2. If not compliant, attempts to automatically fix issues
// 3. Sleeps for 5 seconds before repeating the process

fn comprehensive_health_check(mut managed_host: ManagedHost, expected_state: ExpectedState) {
    // Assess whether the host is compliant or not
    loop {
        match managed_host.assess_compliance_with(&expected_state, DryRunMode::Sequential) {
            Ok(compliancy_status) => match compliancy_status {
                CompliancyStatus::Compliant => {
                    println!("[INFO] so far so good !");
                }
                CompliancyStatus::NotCompliant(changes) => {
                    println!(
                        "[WARN] Not compliant ! Here is what needs to be done : {:?}",
                        changes
                    );

                    match managed_host.try_reach_compliance_with(&expected_state) {
                        Ok(()) => {
                            println!("[INFO] Fixed !");
                        }

                        Err(failure_details) => {
                            println!(
                                "[ERROR] remediation failed, we need to bother some sysadmin somewhere ! {:?}",
                                failure_details
                            );
                        }
                    }
                }
            },
            Err(health_check_failure_details) => {
                println!(
                    "[ERROR] unable to assess compliancy : {:?}",
                    health_check_failure_details
                );
            }
        }

        sleep(Duration::from_secs(5));
    }
}

fn main() {
    // This creates a package block to check that boinc is installed (distributed computing - https://boinc.berkeley.edu/)
    let boinc_package_installed = Apt::AptBlockExpectedState::builder()
        .with_package_state("boinc", Apt::PackageExpectedState::Present)
        .build()
        .unwrap();

    // This creates a service block to ensure boinc is active and enabled
    let boinc_service_active_and_enabled =
        Service::ServiceBlockExpectedState::builder("boinc-client")
            .with_service_state(Service::ServiceExpectedStatus::Active)
            .with_autostart_state(Service::ServiceExpectedAutoStart::Enabled)
            .build()
            .unwrap();

    // Combines both service expectations into a complete expected state configuration
    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::Apt(boinc_package_installed))
        .with_attribute(Attribute::Service(boinc_service_active_and_enabled))
        .build();

    // Creates a managed host instance with SSH connection details and sudo privileges
    let my_managed_host = ManagedHost::from(
        NewConnectionDetails::Ssh2(NewSsh2ConnectionDetails::from(
            "<target-host-endpoint>:<port>",
            Ssh2AuthMode::key_file("regent-user", "/path/to/private/key"),
        )),
        Privilege::WithSudo,
    )
    .unwrap();

    comprehensive_health_check(my_managed_host, expected_state);
}
