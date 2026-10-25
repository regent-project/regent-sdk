//! SSHOQ connection with bearer token authentication — Rust API
//!
//! This example demonstrates connecting to an SSHOQ server using a raw bearer
//! token (e.g. an OIDC ID token) instead of username/password credentials.
//!
//! SSHOQ supports three authentication methods:
//! - `UsernamePassword`: HTTP Basic auth (username + password)
//! - `Key`: JWT bearer token signed with an SSH private key
//! - `BearerToken`: raw bearer token (e.g. OIDC ID token)

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

    // SSHOQ with bearer token auth (e.g. an OIDC token stored in a file)
    let mut managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<sshoq-server-address>", // e.g. "example.com" or "example.com:4433"
        Some(ConnectionMethod::Sshoq(
            SshoqAuth::bearer_token(SecretReference::from_provider(
                "/path/to/oidc/token",
                &files,
            ))
            // Uncomment to use a custom SSHOQ server endpoint path:
            // .with_path("/my-sshoq-endpoint")
            //
            // TLS configuration (defaults to SystemRoots):
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

    match managed_host
        .assess_compliance(&expected_state, true)
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
