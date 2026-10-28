//! SSHOQ low-level handler API — Rust API
//!
//! This example demonstrates using the SSHOQ handler directly, without going
//! through `ManagedHostBuilder` / `ConnectionMethod`. This is useful when you
//! need full control over the connection — for example, using a custom
//! `shhoq::ClientTlsConfig` that is not expressible via [`SshoqTlsConfig`],
//! or when building a handler programmatically.
//!
//! The normal path is `ManagedHostBuilder` + `ConnectionMethod::Sshoq(SshoqAuth)`.
//! This example shows the lower-level alternative.

use regent_sdk::hosts::handlers::sshoq::SshoqConnectionParams;
use regent_sdk::hosts::handlers::{Handler, HostHandler};
use regent_sdk::hosts::privilege::Credentials;
use regent_sdk::{Privilege, RegentError};

#[tokio::main]
async fn main() -> Result<(), RegentError> {
    // ── Construct connection params via convenience constructors ──

    // Password auth with system roots TLS
    let params = SshoqConnectionParams::username_password(
        Credentials::from("alice", "secret"),
        shhoq::ClientTlsConfig::with_system_roots(),
    );

    // Same, but with a custom endpoint path
    let _params_with_path = SshoqConnectionParams::username_password(
        Credentials::from("alice", "secret"),
        shhoq::ClientTlsConfig::with_system_roots(),
    )
    .with_path("/my-sshoq-endpoint");

    // ── Custom ClientTlsConfig (not expressible via SshoqTlsConfig) ──

    // Example: system roots + known_hosts file + additional root certificate
    let tls = shhoq::ClientTlsConfig::with_system_roots()
        .with_known_hosts_file("/etc/regent/sshoq_known_hosts");

    let _params_custom_tls =
        SshoqConnectionParams::username_password(Credentials::from("alice", "secret"), tls);

    // ── Full constructor ──

    use regent_sdk::hosts::handlers::sshoq::SshoqAuthMethod;
    use regent_sdk::hosts::privilege::LoginKey;

    let _params_full = SshoqConnectionParams::from(
        SshoqAuthMethod::Key(LoginKey::from(
            "alice".to_string(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n...".to_string(),
        )),
        Some("/custom-path".to_string()),
        shhoq::ClientTlsConfig::insecure(),
    );

    // ── Wrap in a Handler and connect ──

    let mut handler = Handler::sshoq(regent_sdk::SshoqHostHandler::NotConnected(params));

    // Connect to the SSHOQ server (endpoint: "hostname" or "hostname:port", default 443)
    handler.connect("example.com").await?;

    // Run a command
    let result = handler.run_command("echo hello", &Privilege::None).await?;
    println!("Output: {}", result.stdout);

    // Check if a command is available
    let has_docker = handler
        .is_this_command_available("docker", &Privilege::None)
        .await?;
    println!("docker available: {}", has_docker);

    // Disconnect
    handler.disconnect().await?;

    println!("Done.");
    Ok(())
}
