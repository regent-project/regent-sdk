use regent_sdk::expected_state::global_state::{ComplianceStatus, DryRunMode, ExpectedState};
use regent_sdk::{Attribute, Service::*};
use regent_sdk::{
    ManagedHost, NewConnectionDetails, NewSsh2ConnectionDetails, Privilege, Ssh2AuthMode,
};

// Here we just check if a Host has a given (large) list of services running or not.
fn main() {
    let services_which_must_be_active_and_enabled = ["accounts-daemon","alsa-restore","anacron","apache2","apparmor","avahi-daemon","boinc-client","colord","console-setup","cron","cups-browsed","cups","dbus","fwupd","gdm","ifupdown-pre","keyboard-setup","kmod-static-nodes","low-memory-monitor","ModemManager","networking","NetworkManager-wait-online","NetworkManager","packagekit","plymouth-quit-wait","plymouth-read-write","plymouth-start","polkit","power-profiles-daemon","rtkit-daemon","ssh","switcheroo-control","systemd-binfmt","systemd-journal-flush","systemd-journald","systemd-logind","systemd-modules-load","systemd-random-seed","systemd-remount-fs","systemd-sysctl","systemd-sysusers","systemd-timesyncd","systemd-tmpfiles-setup-dev","systemd-tmpfiles-setup","systemd-udev-trigger","systemd-udevd","systemd-update-utmp","systemd-user-sessions","udisks2","upower","wpa_supplicant"];

    let mut expected_state = ExpectedState::new();

    for service_name in services_which_must_be_active_and_enabled {
        let service_block = ServiceBlockExpectedState::builder(service_name)
            .with_service_state(ServiceExpectedStatus::Active)
            .build()
            .expect("Failed to build service block");

        let attribute = Attribute::Service(service_block);
        expected_state = expected_state.with_attribute(attribute);
    }

    let expected_state = expected_state.build();

    let mut my_managed_host = ManagedHost::from(
        NewConnectionDetails::Ssh2(NewSsh2ConnectionDetails::from(
            "<target-host-endpoint>:<port>",
            Ssh2AuthMode::key_file("regent-user", "/path/to/private/key"),
        )),
        Privilege::WithSudo,
    )
    .unwrap();

    // Assessing compliance with a large number of services and attributes
    // DryRunMode::Parallel enables concurrent assessment for performance
    match my_managed_host.assess_compliance_with(&expected_state, DryRunMode::Parallel) {
        Ok(compliance_status) => match compliance_status {
            ComplianceStatus::Compliant => {
                println!("[INFO] so far so good !");
            }
            ComplianceStatus::NotCompliant(changes) => {
                println!(
                    "[WARN] Not compliant ! Here is what needs to be done : {:?}",
                    changes
                );
            }
        },
        Err(health_check_failure_details) => {
            println!(
                "[ERROR] unable to assess compliance : {:?}",
                health_check_failure_details
            );
        }
    }

    match my_managed_host.assess_compliance_with(&expected_state, DryRunMode::Parallel) {
        Ok(compliance_status) => match compliance_status {
            ComplianceStatus::Compliant => {
                println!("[INFO] Everything is running !");
            }
            ComplianceStatus::NotCompliant(changes) => {
                println!(
                    "[WARN] Not compliant ! Here is what needs to be done : {:?}",
                    changes
                );
            }
        },
        Err(health_check_failure_details) => {
            println!(
                "[ERROR] unable to assess compliance : {:?}",
                health_check_failure_details
            );
        }
    }
}
