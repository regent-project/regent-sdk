//! SSHOQ connection with private key authentication — YAML API
//!
//! This example demonstrates connecting to an SSHOQ server using SSH private
//! key authentication, defined entirely in YAML.
//!
//! The private key is retrieved from a secret provider (e.g. a file on disk)
//! and used to sign a JWT bearer token for authentication.

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
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !Key
    Username: alice
    Key:
      SecRef: /path/to/private/key
      Provider: files
  # Path: /my-sshoq-endpoint          # optional, defaults to /sshoq-server
  # TlsConfig: !Insecure              # optional, defaults to !SystemRoots
  # TlsConfig: !KnownHostsFile /etc/regent/sshoq_known_hosts
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

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    match managed_host.assess_compliance(&expected_state, true).await {
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
