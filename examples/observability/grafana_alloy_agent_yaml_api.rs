use regent_sdk::ExpectedState;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Let's plug a host into a Grafana stack from YAML descriptions");

    let secret_providers =
        SecretProvidersPool::with_default_provider(&SecretProvider::files("file"));

    let host_description = r#"---
Id: srv-web
Endpoint: <host-address>
HostConnectionMethod: !Ssh2
  AuthMethod: !Key
    Username: admin
    Key:
      SecRef: <ssh-private-key-path>
      Provider: file
"#;

    let mut managed_host = ManagedHostBuilder::from_raw_yaml(host_description)
        .unwrap()
        .build(Some(secret_providers))
        .await
        .unwrap();

    assert!(managed_host.connect().await.is_ok());

    // A single agent for the host metrics (Mimir) and the journal (Loki).
    // MIMIR_TOKEN is read by Alloy (sys.env) from the environment of its service: the token is never written to the configuration.
    let expected_state_description = r#"---
Attributes:
  - Name: Alloy sends the host metrics and logs to Grafana
    Privilege: !WithSudo
    Timeout: 15m
    Detail: !Alloy
      State: Present
      Version: '1.10.2'
      CustomArgs:
        - --server.http.listen-addr=127.0.0.1:12345
        - --disable-reporting
      Config: |
        prometheus.exporter.unix "host" { }

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
  - Name: Alloy runs
    Privilege: !WithSudo
    Detail: !Service
      Name: alloy
      State: Started
      Enabled: true
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

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
