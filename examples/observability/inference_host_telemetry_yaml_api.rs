use regent_sdk::ExpectedState;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Let's ship the telemetry of an inference server from YAML descriptions");

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

    // Metrics: Node Exporter, with a textfile directory where the inference jobs drop *.prom files
    // Logs: Fluent Bit forwards the journal to Loki
    // Traces: the OpenTelemetry Collector receives the OTLP spans of the inference server
    let expected_state_description = r#"---
Attributes:
  - Name: Node Exporter exposes the host metrics
    Privilege: !WithSudo
    Detail: !NodeExporter
      State: Present
      Version: '1.12.1'
      EnabledCollectors: [systemd, processes]
      DisabledCollectors: [wifi]
      TextfileDirectory: /var/lib/node_exporter/textfile
  - Name: Node Exporter runs
    Privilege: !WithSudo
    Detail: !Service
      Name: node_exporter
      State: Started
      Enabled: true
  - Name: Prometheus can scrape the Node Exporter
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
              DestPort: 9100
        Target: Accept
  - Name: Fluent Bit ships the journal to Loki
    Privilege: !WithSudo
    Timeout: 15m
    Detail: !FluentBit
      State: Present
      Version: '4.0.3'
      Config:
        Format: Yaml
        Content: |
          service:
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
  - Name: Fluent Bit runs
    Privilege: !WithSudo
    Detail: !Service
      Name: fluent-bit
      State: Started
      Enabled: true
  - Name: The OpenTelemetry Collector forwards the inference traces
    Privilege: !WithSudo
    Timeout: 15m
    Detail: !OtelCollector
      State: Present
      Distribution: Contrib
      Version: '0.164.0'
      Config: |
        receivers:
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
  - Name: The OpenTelemetry Collector runs
    Privilege: !WithSudo
    Detail: !Service
      Name: otelcol-contrib
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
