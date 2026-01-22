use regent_sdk::connection::specification::Privilege;
use regent_sdk::expected_state::global_state::{CompliancyStatus, DryRunMode, ExpectedState};
use regent_sdk::modules::prelude::ServiceBlockExpectedState;
use regent_sdk::modules::system::service::{ServiceExpectedAutoStart, ServiceExpectedStatus};
use regent_sdk::{Attribute, HostConnectionInfo, ManagedHost};
use std::thread::sleep;
use std::time::Duration;

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
    // Build different properties of the expected state : check if Docker daemon is available on the host but not running/enabled
    let docker_socket_service_inactive_and_disabled =
        ServiceBlockExpectedState::builder("docker.socket")
            .with_service_state(ServiceExpectedStatus::Active)
            .with_autostart_state(ServiceExpectedAutoStart::Enabled)
            .build()
            .unwrap();

    let docker_service_inactive_and_disabled = ServiceBlockExpectedState::builder("docker")
        .with_service_state(ServiceExpectedStatus::Active)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    // Assemble all the properties into a single reusable object
    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::Service(
            docker_socket_service_inactive_and_disabled,
        ))
        .with_attribute(Attribute::Service(docker_service_inactive_and_disabled))
        .build();

    // Describe how to connect to the target host
    let my_managed_host = ManagedHost::from(
        // "srv1.www.company.com:22",
        // ConnectionInfo::ssh2_with_username_password("admin", "strong-password"),
        "<target-host-endpoint>:<port>",
        HostConnectionInfo::ssh2_with_key_file("regent-user", "/path/to/private/key"),
        Privilege::WithSudo,
    );

    comprehensive_health_check(my_managed_host, expected_state);
}
