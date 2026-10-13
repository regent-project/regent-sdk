use regent_sdk::Privilege;
use regent_sdk::attribute::ai::ollama::{
    OllamaApiConfig, OllamaExpectedState, OllamaModel, OllamaModelState,
};
use regent_sdk::attribute::gpu::nvidia_driver::KernelModules;
use regent_sdk::attribute::gpu::nvidia_driver::NvidiaDriverConfig;
use regent_sdk::attribute::gpu::nvidia_driver::NvidiaDriverExpectedState;
use regent_sdk::attribute::gpu::nvidia_driver::ProprietaryBranch;
use regent_sdk::attribute::network::iptables::IptablesExpectedState;
use regent_sdk::attribute::system::service::ServiceExpectedState;
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

    // Build a SecretProvidersPool
    let file = SecretProvider::files("file");
    let secret_providers = SecretProvidersPool::with_default_provider(&file);

    // Describe the ManagedHost
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

    // Open connection with this ManageHost
    assert!(managed_host.connect().await.is_ok());

    // ************************************************************************
    // ********* DEFINE EACH ATTRIBUTE OF YOUR EXPECTED STATE *****************

    // --> Nvidia driver is installed
    let nvidia_driver_is_installed = NvidiaDriverExpectedState::present(
        NvidiaDriverConfig::new()
            .with_kernel_modules(KernelModules::Proprietary(ProprietaryBranch::new(580))),
    );

    // --> Ollama is installed
    let ollama_is_installed = OllamaExpectedState::present_with_default_config()
        .with_api_config(OllamaApiConfig {
            host: Some("0.0.0.0:11434".to_string()),
            ..Default::default()
        })
        .with_models(vec![OllamaModel {
            name: "qwen2.5:1.5b".to_string(),
            state: OllamaModelState::Present,
        }]);

    // --> Ollama is running and enabled
    let ollama_service_is_running = ServiceExpectedState::started_and_enabled("ollama");

    // --> The listening port is allowed
    let port_is_open = IptablesExpectedState::allow_tcp_port(11434, Some(1));

    // ************************************************************************
    // ****** COMBINE EVERY ATTRIBUTE INTO A SINGLE DESCRIPTION ***************
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
        .build();

    // Assess whether the host is compliant or not
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
