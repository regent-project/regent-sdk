use regent_sdk::ExpectedState;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};

#[tokio::main]
async fn main() {
    let secret_providers =
        SecretProvidersPool::with_default_provider(&SecretProvider::env_var("env_vars"));

    let host_description = r#"---
Id: <host-id>
Endpoint: <host-endpoint>:<port>
HostConnectionMethod: !Localhost
  UserKind: CurrentUser
"#;

    let mut managed_host = ManagedHostBuilder::from_raw_yaml(host_description)
        .unwrap()
        .build(Some(secret_providers))
        .await
        .unwrap();

    assert!(managed_host.connect().await.is_ok());

    let expected_state_description = r#"---
Attributes:
  - Name: apache2 package is installed
    Privilege: !WithSudo
    Detail: !Apt
      Package: apache2
      State: Present
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    match managed_host.assess_compliance(&expected_state, true).await {
        Ok(compliance_status) => {
            if compliance_status.is_already_compliant() {
                println!("Congratulations, host is already compliant !");
            } else {
                println!(
                    "Oups ! Host is not compliant. Here is the list of required remediations : {:#?}",
                    compliance_status.all_remediations()
                );

                // If not, try once to reach compliance
                match managed_host.reach_compliance(&expected_state).await {
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
