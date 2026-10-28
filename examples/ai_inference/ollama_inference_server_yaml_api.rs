use regent_sdk::ExpectedState;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Let's handle an inference server from YAML descriptions");

    let secret_providers =
        SecretProvidersPool::with_default_provider(&SecretProvider::files("file"));

    let host_description = r#"---
Id: srv-inference
Endpoint: <host-address>
HostConnectionMethod: !Ssh2
  AuthMethod: !Key
    Username: inference
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

    let expected_state_description = r#"---
Attributes:
  - Name: NVIDIA driver is installed
    Privilege: !WithSudo
    Detail: !NvidiaDriver
      State: !Present
        KernelModules: !Proprietary 580
    Timeout: 1h
  - Name: Ollama is installed with the Qwen2.5 1.5B model
    Privilege: !WithSudo
    Detail: !Ollama
      State: Present
      ApiConfig:
        Host: 0.0.0.0:11434
      Models:
        - Name: qwen2.5:1.5b
          State: Present
    Timeout: 30m
  - Name: Ollama service is running and enabled at boot
    Privilege: !WithSudo
    Detail: !Service
      Name: ollama
      State: Started
      Enabled: true
    Timeout: 5m
  - Name: Port is open
    Privilege: !WithSudo
    Detail: !Iptables
      State: Present
      Action:
        Insert:
          Position: 1
      Table: Filter
      Details:
        Chain: Input
        Criteria:
          Protocol:
            Tcp:
              DestPort: 11434
        Target: Accept
    Timeout: 5m
  - Name: Docker storage has at least 5% free on /var/lib/docker
    Privilege: !WithSudo
    Detail: !Storage
      Target: !MountPoint /var/lib/docker
      Threshold: !PercentUsed 95
      Cleanup:
        - docker system prune -af
        - journalctl --vacuum-time=3d
    Timeout: 5m
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
