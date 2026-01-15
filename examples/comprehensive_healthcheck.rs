use regent_sdk::connection::connectionmode::localhost::WhichUser;
use regent_sdk::connection::specification::Privilege;
use regent_sdk::expected_state::global_state::{CompliancyStatus, DryRunMode, ExpectedState};
use regent_sdk::host::host::ManagedHost;
use regent_sdk::modules::prelude::ServiceBlockExpectedState;
use regent_sdk::modules::system::service::{ServiceExpectedAutoStart, ServiceExpectedStatus};
use regent_sdk::prelude::Attribute;
use regent_sdk::prelude::HostConnectionInfo;
use std::thread::sleep;
use std::time::Duration;

fn comprehensive_health_check(mut managed_host: ManagedHost, expected_state: ExpectedState) {
    // Assess whether the host is compliant or not
    loop {
        match managed_host.assess_compliance_with(&expected_state, DryRunMode::Parallel) {
            Ok(compliancy_status) => match compliancy_status {
                CompliancyStatus::Compliant => {
                    println!("[INFO] so far so good !");
                }
                CompliancyStatus::NotCompliant => {
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
    let docker_socket_service_started_and_enabled =
        ServiceBlockExpectedState::builder("docker.socket")
            .with_service_state(ServiceExpectedStatus::Inactive)
            .with_autostart_state(ServiceExpectedAutoStart::Disabled)
            .build()
            .unwrap();

    let docker_service_started_and_enabled = ServiceBlockExpectedState::builder("docker")
        .with_service_state(ServiceExpectedStatus::Inactive)
        .with_autostart_state(ServiceExpectedAutoStart::Disabled)
        .build()
        .unwrap();

    // Assemble all the properties into a single reusable object
    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::Service(
            docker_socket_service_started_and_enabled,
        ))
        .with_attribute(Attribute::Service(docker_service_started_and_enabled))
        .build();

    // Describe how to connect to the target host
    let my_managed_host = ManagedHost::from(
        // "srv1.www.company.com:22",
        // ConnectionInfo::ssh2_with_username_password("admin", "strong-password"),
        "localhost",
        HostConnectionInfo::LocalHost(WhichUser::CurrentUser),
        Privilege::WithSudoRs,
    );

    comprehensive_health_check(my_managed_host, expected_state);
}
