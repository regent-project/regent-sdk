//! Basic compliance check using SSHOQ (SSH over QUIC) connection — YAML API
//!
//! This example connects to a host running an SSHOQ server using a YAML-defined
//! inventory, then assesses whether the `httpd` service is active and enabled.
//!
//! SSHOQ uses QUIC (HTTP/3) on port 443 by default.
//!
//! TLS configuration options (TlsConfig field):
//!   TlsConfig: !SystemRoots                              # default
//!   TlsConfig: !Insecure                                 # skip cert verification (testing)
//!   TlsConfig: !KnownHostsFile /path/to/known_hosts      # trust pinned certs
//!   TlsConfig: !Custom                                   # known_hosts + additional roots
//!     KnownHostsFile: /path/to/known_hosts
//!     AdditionalRoots:
//!       - /path/to/ca.der
//!
//! Prerequisites:
//! - An SSHOQ server running on the target host
//! - A credentials file (YAML with `Username` and `Password` keys) accessible
//!   via the `files` secret provider

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
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
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
