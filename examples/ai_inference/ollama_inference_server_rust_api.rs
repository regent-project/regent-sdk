use regent_sdk::Privilege;
use regent_sdk::attribute::ai::ollama::{OllamaApiConfig, OllamaExpectedState, OllamaModel};
use regent_sdk::attribute::gpu::nvidia_driver::{NvidiaDriverConfig, NvidiaDriverExpectedState};
use regent_sdk::attribute::network::iptables::IptablesExpectedState;
use regent_sdk::attribute::system::service::ServiceExpectedState;
use regent_sdk::attribute::utilities::storage::{StorageExpectedState, Threshold};
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::ssh2::Ssh2Auth;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::SecretReference;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use regent_sdk::{Attribute, ExpectedState};
use std::time::Duration;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Let's handle an inference server from Rust code");

    let file = SecretProvider::files("file");
    let secret_providers = SecretProvidersPool::with_default_provider(&file);

    let mut managed_host = ManagedHostBuilder::new(
        "srv-inference",
        "<host-address>",
        Some(ConnectionMethod::Ssh2(Ssh2Auth::key(
            "inference",
            SecretReference::from_provider("<ssh-private-key-path>", &file),
        ))),
    )
    .build(Some(secret_providers))
    .await
    .unwrap();

    assert!(managed_host.connect().await.is_ok());

    let nvidia_driver_is_installed = NvidiaDriverExpectedState::present(
        NvidiaDriverConfig::new()
            .with_proprietary_kernel_modules(580)
            .unwrap(),
    );

    let ollama_is_installed = OllamaExpectedState::present_with_config_and_models(
        OllamaApiConfig::new().with_listening_endpoint("0.0.0.0:11434"),
        vec![OllamaModel::present("qwen2.5:1.5b")],
    );

    let ollama_service_is_running = ServiceExpectedState::started_and_enabled("ollama");

    let port_is_open = IptablesExpectedState::allow_tcp_port(11434, Some(1));

    let mut docker_storage_watch =
        StorageExpectedState::watch_mountpoint("/var/lib/docker", Threshold::Percent(95));
    docker_storage_watch.with_cleanup(vec![
        "docker system prune -af".to_string(),
        "journalctl --vacuum-time=3d".to_string(),
    ]);

    let expected_state = ExpectedState::new()
        .with_attribute(
            Attribute::nvidia_driver(
                nvidia_driver_is_installed,
                Privilege::WithSudo,
                Some("NVIDIA driver is installed".to_string()),
            )
            .with_timeout(Duration::from_secs(3600)),
        )
        .with_attribute(
            Attribute::ollama(
                ollama_is_installed,
                Privilege::WithSudo,
                Some("Ollama is installed with the Qwen2.5 1.5B model".to_string()),
            )
            .with_timeout(Duration::from_secs(1800)),
        )
        .with_attribute(
            Attribute::service(
                ollama_service_is_running,
                Privilege::WithSudo,
                Some("Ollama service is running and enabled at boot".to_string()),
            )
            .with_timeout(Duration::from_secs(300)),
        )
        .with_attribute(
            Attribute::iptables(
                port_is_open,
                Privilege::WithSudo,
                Some("Port is open".to_string()),
            )
            .with_timeout(Duration::from_secs(300)),
        )
        .with_attribute(
            Attribute::storage(
                docker_storage_watch,
                Privilege::WithSudo,
                Some("Docker storage has at least 5% free on /var/lib/docker".to_string()),
            )
            .with_timeout(Duration::from_secs(300)),
        )
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
