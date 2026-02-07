use regent_sdk::{
    host_handler::{
        localhost::{LocalHostHandler, WhichUser},
        privilege::Privilege, ssh2::Ssh2HostHandler,
    },
    managed_host::ManagedHost,
    state::{
        ExpectedState,
        attribute::{
            Attribute,
            package::apt::{AptBlockExpectedState, PackageExpectedState},
        },
        compliance::ComplianceAssesment,
    },
};
use std::collections::HashMap;

fn main() {
    // Describe the ManagedHost
    let mut managed_host = ManagedHost::from(
        "127.0.0.1:31002",
        Ssh2HostHandler::key_file("regent-user", "../ssh_key/key.priv"),
        HashMap::new(),
    );

    managed_host.connect().unwrap();

    let apache_expected_state = AptBlockExpectedState::builder()
        .with_package_state("apache2", PackageExpectedState::Absent)
        .build()
        .unwrap();

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::apt(
            apache_expected_state,
            Privilege::WithSudo,
        ))
        .build();

    match managed_host.assess_compliance(&expected_state) {
        Ok(compliance_status) => match compliance_status {
            ComplianceAssesment::AlreadyCompliant => {
                println!("Congratulations, host is already compliant !");
            }
            ComplianceAssesment::NonCompliant(remediations) => {
                println!(
                    "Oups ! Host is not compliant. Here is the list of required remediations : {:?}",
                    remediations
                );

                match managed_host.reach_compliance(&expected_state) {
                    Ok(outcome) => {
                        println!("Try reach compliance outcome : {:?}", outcome);
                    }
                    Err(error_detail) => {
                        println!("Unable to try to reach compliance : {:#?}", error_detail);
                    }
                }
            }
        },
        Err(error_detail) => {
            println!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
