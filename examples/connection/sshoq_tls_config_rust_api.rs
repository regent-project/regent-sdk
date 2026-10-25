//! SSHOQ connection configuration — Rust API
//!
//! This example demonstrates the different ways to configure an SSHOQ connection
//! via [`SshoqAuth`]:
//!
//! 1. Convenience constructors (`username_password`, `key`, `bearer_token`)
//! 2. Chainable customizers (`.with_path()`, `.with_tls_config()`)
//! 3. Full constructor (`SshoqAuth::from()`)
//!
//! TLS configuration via [`SshoqTlsConfig`] builder methods:
//! - `SshoqTlsConfig::system_roots()` (default): trust system root certificates
//! - `SshoqTlsConfig::insecure()`: skip certificate verification (testing only)
//! - `SshoqTlsConfig::known_hosts_file(path)`: trust pinned certificates
//! - `SshoqTlsConfig::custom(known_hosts_file, additional_roots)`: known_hosts + DER root certs

use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::sshoq::{SshoqAuth, SshoqAuthReference, SshoqTlsConfig};
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder, SecretReference};

#[tokio::main]
async fn main() {
    let files = SecretProvider::files("files");
    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&files)
        .build()
        .unwrap();

    let creds_ref = SecretReference::from_provider("/path/to/credentials/secret", &files);
    let key_ref = SecretReference::from_provider("/path/to/private/key", &files);
    let token_ref = SecretReference::from_provider("/path/to/oidc/token", &files);

    // ── Convenience constructors (defaults: SystemRoots TLS, /sshoq-server path) ──

    let _auth_password = SshoqAuth::username_password(creds_ref.clone());
    let _auth_key = SshoqAuth::key("alice", key_ref.clone());
    let _auth_token = SshoqAuth::bearer_token(token_ref.clone());

    // ── Chainable customizers ──

    // Custom endpoint path only
    let _auth_path = SshoqAuth::username_password(creds_ref.clone())
        .with_path("/my-sshoq-endpoint");

    // Insecure TLS (testing only)
    let _auth_insecure = SshoqAuth::username_password(creds_ref.clone())
        .with_tls_config(SshoqTlsConfig::insecure());

    // Known hosts file: trust system roots + pinned certificates
    let _auth_known_hosts = SshoqAuth::username_password(creds_ref.clone())
        .with_tls_config(SshoqTlsConfig::known_hosts_file(
            "/etc/regent/sshoq_known_hosts",
        ));

    // Custom: known_hosts file + additional DER-encoded root certificates
    let _auth_custom = SshoqAuth::username_password(creds_ref.clone())
        .with_tls_config(SshoqTlsConfig::custom(
            Some("/etc/regent/sshoq_known_hosts"),
            vec![
                "/etc/regent/my-internal-ca.der",
                "/etc/regent/another-ca.der",
            ],
        ));

    // Combining path and TLS config
    let _auth_full = SshoqAuth::username_password(creds_ref.clone())
        .with_path("/custom-sshoq-endpoint")
        .with_tls_config(SshoqTlsConfig::insecure());

    // ── Full constructor (all fields at once) ──

    let _auth_from = SshoqAuth::from(
        SshoqAuthReference::UsernamePassword(creds_ref.clone()),
        Some("/my-sshoq-endpoint".to_string()),
        Some(SshoqTlsConfig::insecure()),
    );

    // ── Build a managed host ──

    let _managed_host = ManagedHostBuilder::new(
        "<host-id>",
        "<sshoq-server-address>", // e.g. "example.com" or "example.com:4433"
        Some(ConnectionMethod::Sshoq(_auth_insecure)),
    )
    .build(Some(secrets_providers_pool))
    .await
    .unwrap();

    println!("SSHOQ auth configuration examples constructed successfully.");
}
