//! SSHOQ connection configuration — YAML API
//!
//! This example demonstrates the different ways to configure an SSHOQ connection
//! via YAML inventory snippets, parsed with [`ManagedHostBuilder::from_raw_yaml`].
//!
//! # Auth methods
//!
//! ```yaml
//! # Username + password (secret reference to a Credentials YAML file)
//! HostConnectionMethod: !Sshoq
//!   AuthMethod: !UsernamePassword
//!     SecRef: /path/to/credentials/secret
//!     Provider: files
//!
//! # SSH private key (username + secret reference to a key file)
//! HostConnectionMethod: !Sshoq
//!   AuthMethod: !Key
//!     Username: alice
//!     Key:
//!       SecRef: /path/to/private/key
//!       Provider: files
//!
//! # Raw bearer token (e.g. OIDC ID token)
//! HostConnectionMethod: !Sshoq
//!   AuthMethod: !BearerToken
//!     SecRef: /path/to/oidc/token
//!     Provider: files
//! ```
//!
//! # Optional fields
//!
//! ```yaml
//! HostConnectionMethod: !Sshoq
//!   AuthMethod: !UsernamePassword
//!     SecRef: /path/to/credentials/secret
//!     Provider: files
//!   Path: /my-sshoq-endpoint          # default: /sshoq-server
//!   TlsConfig: !Insecure              # default: !SystemRoots
//! ```
//!
//! # TLS configuration (TlsConfig field)
//!
//! ```yaml
//! TlsConfig: !SystemRoots                              # default: trust system roots
//! TlsConfig: !Insecure                                 # skip cert verification (testing only)
//! TlsConfig: !KnownHostsFile /etc/regent/known_hosts   # trust pinned certificates
//! TlsConfig: !Custom                                   # known_hosts + additional DER root certs
//!   KnownHostsFile: /etc/regent/known_hosts
//!   AdditionalRoots:
//!     - /etc/regent/my-internal-ca.der
//!     - /etc/regent/another-ca.der
//! ```

use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};

#[tokio::main]
async fn main() {
    let secrets_providers_pool = SecretProvidersPoolBuilder::new()
        .with_default_provider(&SecretProvider::files("files"))
        .build()
        .unwrap();

    // ── Auth method variants (defaults: SystemRoots TLS, /sshoq-server path) ──

    // Username + password
    let yaml_password = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
"#;

    // SSH private key
    let yaml_key = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !Key
    Username: alice
    Key:
      SecRef: /path/to/private/key
      Provider: files
"#;

    // Bearer token
    let yaml_token = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !BearerToken
    SecRef: /path/to/oidc/token
    Provider: files
"#;

    // ── Custom path only ──

    let yaml_path = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
  Path: /my-sshoq-endpoint
"#;

    // ── TLS configuration variants ──

    // Insecure TLS (testing only)
    let yaml_insecure = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
  TlsConfig: !Insecure
"#;

    // Known hosts file: trust system roots + pinned certificates
    let yaml_known_hosts = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
  TlsConfig: !KnownHostsFile /etc/regent/sshoq_known_hosts
"#;

    // Custom: known_hosts file + additional DER-encoded root certificates
    let yaml_custom = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
  TlsConfig: !Custom
    KnownHostsFile: /etc/regent/sshoq_known_hosts
    AdditionalRoots:
      - /etc/regent/my-internal-ca.der
      - /etc/regent/another-ca.der
"#;

    // ── Combining path and TLS config ──

    let yaml_full = r#"---
Id: <host-id>
Endpoint: <sshoq-server-address>
HostConnectionMethod: !Sshoq
  AuthMethod: !UsernamePassword
    SecRef: /path/to/credentials/secret
    Provider: files
  Path: /custom-sshoq-endpoint
  TlsConfig: !Insecure
"#;

    // ── Parse and build all configurations ──

    let yamls = [
        ("password (defaults)", yaml_password),
        ("key auth (defaults)", yaml_key),
        ("bearer token (defaults)", yaml_token),
        ("custom path", yaml_path),
        ("insecure TLS", yaml_insecure),
        ("known hosts file", yaml_known_hosts),
        ("custom TLS (known_hosts + additional roots)", yaml_custom),
        ("path + TLS combined", yaml_full),
    ];

    for (label, yaml) in &yamls {
        let _managed_host = ManagedHostBuilder::from_raw_yaml(yaml)
            .unwrap()
            .build(Some(secrets_providers_pool.clone()))
            .await
            .unwrap();
        println!("Parsed and built: {}", label);
    }

    println!("All SSHOQ YAML configurations parsed and built successfully.");
}
