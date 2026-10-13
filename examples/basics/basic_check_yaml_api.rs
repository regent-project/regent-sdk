use regent_sdk::ExpectedState;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};

#[tokio::main]
async fn main() {
    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&SecretProvider::files("files"))
        .build()
        .unwrap();

    let host_description = r#"---
Id: <host-id>
Endpoint: <address:port>
HostConnectionMethod: !Ssh2
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
"#;

    let mut managed_host = ManagedHostBuilder::from_raw_yaml(host_description)
        .unwrap()
        .build(Some(secrets_providers_pool))
        .await
        .unwrap();

    assert!(managed_host.connect().await.is_ok());

    let expected_state_description = r#"---
Attributes:
  - Name: httpd service is active and enabled
    Privilege: !None
    Detail: !Service
      Name: httpd
      State: Started
      Enabled: true
"#;

    let localhost_expected_state =
        ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    match managed_host
        .assess_compliance(&localhost_expected_state, true)
        .await
    {
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
