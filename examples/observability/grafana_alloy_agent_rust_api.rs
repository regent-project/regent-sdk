use regent_sdk::Privilege;
use regent_sdk::attribute::observability::alloy::AlloyExpectedState;
use regent_sdk::attribute::system::service::ServiceExpectedState;
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::ssh2::Ssh2Auth;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::SecretReference;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use regent_sdk::{Attribute, ExpectedState};
use std::time::Duration;
use tracing::{error, info, warn};

// MIMIR_TOKEN is read by Alloy (sys.env) from the environment of its service: the token is never written to the configuration
const ALLOY_CONFIG: &str = r#"prometheus.exporter.unix "host" { }

prometheus.scrape "host" {
  targets    = prometheus.exporter.unix.host.targets
  forward_to = [prometheus.remote_write.mimir.receiver]
}

prometheus.remote_write "mimir" {
  endpoint {
    url = "https://mimir.example.com/api/v1/push"
    bearer_token = sys.env("MIMIR_TOKEN")
  }
}

loki.source.journal "journal" {
  forward_to = [loki.write.loki.receiver]
  labels     = { job = "journal", host = "srv-web" }
}

loki.write "loki" {
  endpoint {
    url = "https://loki.example.com/loki/api/v1/push"
  }
}
"#;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Let's plug a host into a Grafana stack from Rust code");

    let file = SecretProvider::files("file");
    let secret_providers = SecretProvidersPool::with_default_provider(&file);

    let mut managed_host = ManagedHostBuilder::new(
        "srv-web",
        "<host-address>",
        Some(ConnectionMethod::Ssh2(Ssh2Auth::key(
            "admin",
            SecretReference::from_provider("<ssh-private-key-path>", &file),
        ))),
    )
    .build(Some(secret_providers))
    .await
    .unwrap();

    assert!(managed_host.connect().await.is_ok());

    // A single agent for the host metrics (Mimir) and the journal (Loki)
    let alloy = AlloyExpectedState::present()
        .with_version("1.10.2".parse().unwrap())
        .with_custom_args(&[
            "--server.http.listen-addr=127.0.0.1:12345",
            "--disable-reporting",
        ])
        .with_config(ALLOY_CONFIG);

    let expected_state = ExpectedState::new()
        .with_attribute(
            Attribute::alloy(
                alloy,
                Privilege::WithSudo,
                Some("Alloy sends the host metrics and logs to Grafana".to_string()),
            )
            .with_timeout(Duration::from_secs(900)),
        )
        .with_attribute(Attribute::service(
            ServiceExpectedState::started_and_enabled("alloy"),
            Privilege::WithSudo,
            Some("Alloy runs".to_string()),
        ))
        .build();

    match managed_host.assess_compliance(&expected_state, true).await {
        Ok(compliance_status) => {
            if compliance_status.is_already_compliant() {
                info!("Congratulations, host is already compliant !");
            } else {
                warn!(
                    "Oups ! Host is not compliant. Here is the list of required remediations : {:#?}",
                    compliance_status.all_remediations()
                );

                // If not, try once to reach compliance
                match managed_host.reach_compliance(&expected_state).await {
                    Ok(outcome) => {
                        info!(
                            "Try reach compliance outcome : {:#?}",
                            outcome.actions_taken()
                        );
                    }
                    Err(error_detail) => {
                        error!("Unable to try to reach compliance : {:#?}", error_detail);
                    }
                }
            }
        }
        Err(error_detail) => {
            error!("Failed to assess compliance : {:?}", error_detail);
        }
    }
}
