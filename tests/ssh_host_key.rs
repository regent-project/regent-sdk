//! SSH host key verification (`Ssh2Auth::host_key`): against an in-process
//! russh server, a matching fingerprint / known_hosts entry connects, anything
//! else is refused before authentication.

use std::sync::Arc;

use regent_sdk::hosts::handlers::HostHandler;
use regent_sdk::hosts::handlers::ssh2::{Ssh2AuthMethod, Ssh2HostHandler, Ssh2HostKey};
use regent_sdk::hosts::privilege::Credentials;
use russh::keys::{HashAlg, PrivateKey};
use russh::server::{Auth, Server as _};

#[derive(Clone)]
struct AcceptAll;

impl russh::server::Server for AcceptAll {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl russh::server::Handler for AcceptAll {
    type Error = russh::Error;
    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
}

/// A deterministic Ed25519 test key.
fn test_key(seed: u8) -> PrivateKey {
    PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
        &[seed; 32],
    ))
}

/// Start a server; returns its port and host key.
async fn server() -> (u16, PrivateKey) {
    let key = test_key(1);
    let mut config = russh::server::Config::default();
    config.keys.push(key.clone());
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = AcceptAll.run_on_socket(config, &listener).await;
    });
    (port, key)
}

async fn connect(port: u16, host_key: Option<Ssh2HostKey>) -> bool {
    let mut handler = Ssh2HostHandler::NotConnected(
        Ssh2AuthMethod::UsernamePassword(Credentials::from("user", "password")),
        host_key,
    );
    handler.connect(&format!("127.0.0.1:{port}")).await.is_ok()
}

#[tokio::test]
async fn fingerprints() {
    let (port, key) = server().await;
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    assert!(fingerprint.starts_with("SHA256:"));
    assert!(connect(port, Some(Ssh2HostKey::Fingerprints(vec![fingerprint]))).await);
    let other = test_key(2);
    let wrong = other.public_key().fingerprint(HashAlg::Sha256).to_string();
    assert!(!connect(port, Some(Ssh2HostKey::Fingerprints(vec![wrong]))).await);
    // no policy: any key is accepted (unchanged behaviour)
    assert!(connect(port, None).await);
}

#[tokio::test]
async fn known_hosts_file() {
    let (port, key) = server().await;
    let dir = std::env::temp_dir().join(format!("regent-known-hosts-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let listed = dir.join("known_hosts");
    std::fs::write(
        &listed,
        format!(
            "[127.0.0.1]:{port} {}\n",
            key.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let empty = dir.join("empty_known_hosts");
    std::fs::write(&empty, "").unwrap();
    assert!(
        connect(
            port,
            Some(Ssh2HostKey::KnownHostsFile(listed.display().to_string()))
        )
        .await
    );
    assert!(
        !connect(
            port,
            Some(Ssh2HostKey::KnownHostsFile(empty.display().to_string()))
        )
        .await
    );
}

#[test]
fn yaml_form() {
    let auth: regent_sdk::hosts::handlers::ssh2::Ssh2Auth = yaml_serde::from_str(
        "AuthMethod: !Key\n  Username: ops\n  Key:\n    SecRef: id_ed25519\n    Provider: files\nHostKey: !Fingerprints\n  - SHA256:abc\n",
    )
    .unwrap();
    assert_eq!(
        auth.host_key,
        Some(Ssh2HostKey::Fingerprints(vec!["SHA256:abc".to_string()]))
    );
    // absent field: serialized form unchanged for older readers
    let plain = regent_sdk::hosts::handlers::ssh2::Ssh2Auth::key(
        "ops",
        regent_sdk::secrets::SecretReference::from("k", None),
    );
    assert!(!serde_json::to_string(&plain).unwrap().contains("HostKey"));
}
