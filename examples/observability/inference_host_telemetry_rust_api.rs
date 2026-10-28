use regent_sdk::Privilege;
use regent_sdk::attribute::network::iptables::IptablesExpectedState;
use regent_sdk::attribute::observability::fluentbit::{FluentBitConfig, FluentBitExpectedState};
use regent_sdk::attribute::observability::node_exporter::NodeExporterExpectedState;
use regent_sdk::attribute::observability::otel_collector::{
    OtelCollectorDistribution, OtelCollectorExpectedState,
};
use regent_sdk::attribute::system::service::ServiceExpectedState;
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::ssh2::Ssh2Auth;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::SecretReference;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use regent_sdk::{Attribute, ExpectedState};
use std::time::Duration;
use tracing::{error, info, warn};

const FLUENTBIT_CONFIG: &str = r#"service:
  flush: 1
  log_level: info
pipeline:
  inputs:
    - name: systemd
      tag: journal.*
      read_from_tail: on
  outputs:
    - name: loki
      match: 'journal.*'
      host: loki.example.com
      port: 3100
      labels: job=fluentbit, host=srv-inference
"#;

const OTEL_COLLECTOR_CONFIG: &str = r#"receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
      http:
        endpoint: 127.0.0.1:4318
processors:
  batch:
exporters:
  otlphttp:
    endpoint: https://otel-gateway.example.com
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
"#;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Let's ship the telemetry of an inference server from Rust code");

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

    // Metrics: Node Exporter, with a textfile directory where the inference jobs drop *.prom files
    let node_exporter = NodeExporterExpectedState::present("1.12.1".parse().unwrap())
        .with_enabled_collectors(&["systemd", "processes"])
        .with_disabled_collectors(&["wifi"])
        .with_textfile_directory("/var/lib/node_exporter/textfile");

    // Logs: Fluent Bit forwards the journal to Loki
    let fluentbit = FluentBitExpectedState::present()
        .with_version("4.0.3".parse().unwrap())
        .with_config(FluentBitConfig::yaml(FLUENTBIT_CONFIG));

    // Traces: the OpenTelemetry Collector receives the OTLP spans of the inference server
    let otel_collector = OtelCollectorExpectedState::present(
        OtelCollectorDistribution::Contrib,
        "0.164.0".parse().unwrap(),
    )
    .with_config(OTEL_COLLECTOR_CONFIG);

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::node_exporter(
            node_exporter,
            Privilege::WithSudo,
            Some("Node Exporter exposes the host metrics".to_string()),
        ))
        .with_attribute(Attribute::service(
            ServiceExpectedState::started_and_enabled("node_exporter"),
            Privilege::WithSudo,
            Some("Node Exporter runs".to_string()),
        ))
        .with_attribute(Attribute::iptables(
            IptablesExpectedState::allow_tcp_port(9100, Some(1)),
            Privilege::WithSudo,
            Some("Prometheus can scrape the Node Exporter".to_string()),
        ))
        .with_attribute(
            Attribute::fluentbit(
                fluentbit,
                Privilege::WithSudo,
                Some("Fluent Bit ships the journal to Loki".to_string()),
            )
            .with_timeout(Duration::from_secs(900)),
        )
        .with_attribute(Attribute::service(
            ServiceExpectedState::started_and_enabled("fluent-bit"),
            Privilege::WithSudo,
            Some("Fluent Bit runs".to_string()),
        ))
        .with_attribute(
            Attribute::otel_collector(
                otel_collector,
                Privilege::WithSudo,
                Some("The OpenTelemetry Collector forwards the inference traces".to_string()),
            )
            .with_timeout(Duration::from_secs(900)),
        )
        .with_attribute(Attribute::service(
            ServiceExpectedState::started_and_enabled("otelcol-contrib"),
            Privilege::WithSudo,
            Some("The OpenTelemetry Collector runs".to_string()),
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
