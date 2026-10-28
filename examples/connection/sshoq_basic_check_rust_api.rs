//! Basic compliance check using SSHOQ (SSH over QUIC) connection — Rust API
//!
//! This example connects to a host running an SSHOQ server, then assesses
//! whether the `httpd` service is active and enabled.
//!
//! SSHOQ uses QUIC (HTTP/3) on port 443 by default. The endpoint should be
//! given as `hostname` or `hostname:port`.
//!
//! # SshoqAuth construction styles
//!
//! ```no_run
//! use regent_sdk::hosts::handlers::sshoq::{SshoqAuth, SshoqAuthReference, SshoqTlsConfig};
//! use regent_sdk::secrets::SecretReference;
//!
//! let creds = SecretReference::from("my_creds", None);
//!
//! // 1. Convenience constructor (defaults: SystemRoots, /sshoq-server)
//! let auth = SshoqAuth::username_password(creds.clone());
//!
//! // 2. Convenience + chainable customizers
//! let auth = SshoqAuth::username_password(creds.clone())
//!     .with_path("/my-sshoq-endpoint")
//!     .with_tls_config(SshoqTlsConfig::insecure());
//!
//! // 3. Full constructor with all fields
//! let auth = SshoqAuth::from(
//!     SshoqAuthReference::UsernamePassword(creds),
//!     Some("/my-sshoq-endpoint".to_string()),
//!     Some(SshoqTlsConfig::insecure()),
//! );
//! ```
//!
//! # TLS configuration options
//!
//! - `SshoqTlsConfig::system_roots()` (default): trust system root certificates
//! - `SshoqTlsConfig::insecure()`: skip certificate verification (testing only)
//! - `SshoqTlsConfig::known_hosts_file(path)`: trust pinned certificates
//! - `SshoqTlsConfig::custom(known_hosts_file, additional_roots)`: known_hosts + DER root certs
//!
//! Prerequisites:
//! - An SSHOQ server running on the target host
//! - A credentials file (YAML with `Username` and `Password` keys) accessible
//!   via the `files` secret provider

use regent_sdk::Privilege;
use regent_sdk::attribute::system::service::ServiceExpectedState;
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::sshoq::SshoqAuth;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder, SecretReference};
use regent_sdk::{Attribute, ExpectedState};

#[tokio::main]
async fn main() {
    let files = SecretProvider::files("files");
    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&files)
        .build()
        .unwrap();

    // SSHOQ connection: endpoint is "hostname" or "hostname:port" (default port 443)
    let mut managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<sshoq-server-address>", // e.g. "example.com" or "example.com:4433"
        Some(ConnectionMethod::Sshoq(
            SshoqAuth::username_password(SecretReference::from_provider(
                "/path/to/credentials/secret",
                &files,
            )), // Chainable customizers:
                // .with_path("/my-sshoq-endpoint")
                // .with_tls_config(SshoqTlsConfig::insecure())
                // .with_tls_config(SshoqTlsConfig::known_hosts_file(
                //     "/etc/regent/sshoq_known_hosts",
                // ))
        )),
    )
    .build(Some(secrets_providers_pool))
    .await
    .unwrap();

    assert!(managed_host.connect().await.is_ok());

    let httpd_service_active_and_enabled = ServiceExpectedState::started_and_enabled("httpd");

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::service(
            httpd_service_active_and_enabled,
            Privilege::None,
            None,
        ))
        .build();

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
