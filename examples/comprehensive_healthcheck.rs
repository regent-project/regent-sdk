use regent_sdk::expected_state::global_state::{DryRunMode, ExpectedState};
use regent_sdk::host::host::ManagedHost;
use regent_sdk::modules::packages::yumdnf::PackageExpectedState;
use regent_sdk::modules::prelude::{ServiceBlockExpectedState, YumDnfBlockExpectedState};
use regent_sdk::modules::system::service::{ServiceExpectedAutoStart, ServiceExpectedState};
use regent_sdk::prelude::Attribute;
use regent_sdk::prelude::ConnectionInfo;
use std::thread::sleep;
use std::time::Duration;

fn comprehensive_health_check(managed_host: ManagedHost, expected_state: ExpectedState) {
    // Assess whether the host is compliant or not
    loop {
        sleep(Duration::from_secs(20));

        match managed_host.assess_compliance_with(&expected_state, DryRunMode::Parallel) {
            Ok(()) => {
                println!("[INFO] so far so good !");
            }
            Err(health_check_failure_details) => {
                println!("[WARNING] {:?}", health_check_failure_details);

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
        }
    }
}

fn main() {
    // Build different properties of the expected state
    let httpd_package_installed = YumDnfBlockExpectedState::builder()
        .with_package_state("httpd", PackageExpectedState::Present)
        .with_system_upgrade()
        .build()
        .unwrap();

    let httpd_service_started_and_enabled = ServiceBlockExpectedState::builder("httpd")
        .with_service_state(ServiceExpectedState::Started)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    // Assemble all the properties into a single reusable object
    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::Dnf(httpd_package_installed))
        .with_attribute(Attribute::Service(httpd_service_started_and_enabled))
        .build();

    // Describe how to connect to the target host
    let my_managed_host = ManagedHost::from(
        "srv1.www.company.com:22",
        ConnectionInfo::ssh2_with_username_password("admin", "strong-password"),
    );

    comprehensive_health_check(my_managed_host, expected_state);
}
