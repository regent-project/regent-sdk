use regent_sdk::connection::specification::Privilege;
use regent_sdk::expected_state::global_state::{CompliancyStatus, DryRunMode, ExpectedState};
use regent_sdk::modules::prelude::ServiceBlockExpectedState;
use regent_sdk::modules::system::service::{ServiceExpectedAutoStart, ServiceExpectedStatus};
use regent_sdk::{Attribute, HostConnectionInfo, ManagedHost};
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
                CompliancyStatus::NotCompliant => {
                    println!("[WARN] Not compliant");
                    println!("[INFO] let's try to fix things on our own at least once");

                    if let Err(failure_details) =
                        managed_host.try_reach_compliance_with(&expected_state)
                    {
                        println!(
                            "[ERROR] self-remediation failed, we need to bother some sysadmin somewhere ! {:?}",
                            failure_details
                        );
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
    // This creates a service block for docker.socket that should be active and enabled
    let docker_socket_service_inactive_and_disabled =
        ServiceBlockExpectedState::builder("docker.socket")
            .with_service_state(ServiceExpectedStatus::Active)
            .with_autostart_state(ServiceExpectedAutoStart::Enabled)
            .build()
            .unwrap();

    // This creates a service block for docker that should be active and enabled
    let docker_service_inactive_and_disabled = ServiceBlockExpectedState::builder("docker")
        .with_service_state(ServiceExpectedStatus::Active)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    // Combines both service expectations into a complete expected state configuration
    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::Service(
            docker_socket_service_inactive_and_disabled,
        ))
        .with_attribute(Attribute::Service(docker_service_inactive_and_disabled))
        .build();

    // Creates a managed host instance with SSH connection details and sudo privileges
    let my_managed_host = ManagedHost::from(
        "<target-host-endpoint>:<port>",
        HostConnectionInfo::ssh2_with_key_file("regent-user", "/path/to/private/key"),
        Privilege::WithSudo,
    );

    comprehensive_health_check(my_managed_host, expected_state);
}

