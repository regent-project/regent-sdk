use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Router, extract::State, routing::get};
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use serde::Serialize;

use regent_sdk::{ExpectedState, ManagedHost};

#[tokio::main]
async fn main() {
    // Build up the expected configuration of this host.
    // You can fetch this from a remote location (http endpoint, git, ftp...).
    let expected_state_description = r#"---
Attributes:
  - Name: http_service_up_and_running
    Privilege: !None
    Detail: !Service
      Name: httpd
      State: Started
      Enabled: true
"#;

    let localhost_expected_state =
        ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    let host_description = r#"---
Id: local_server
Endpoint: localhost
HostConnectionMethod: !Localhost
  UserKind: CurrentUser
"#;

    let localhost_manager = ManagedHostBuilder::from_raw_yaml(host_description)
        .unwrap()
        .build(None)
        .await
        .unwrap();

    let app_state = AppState {
        managed_host: localhost_manager,
        expected_state: localhost_expected_state,
    };

    let api_app = Router::new()
        .route("/health", get(health_check))
        .with_state(app_state);

    let api_endpoint = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(api_endpoint, api_app.into_make_service())
        .await
        .unwrap();
}

// This handler will run the healtcheck on localhost
async fn health_check(State(mut app_state): State<AppState>) -> impl IntoResponse {
    match app_state.check_localhost_health().await {
        Ok((status_code, health_check_content)) => {
            (status_code, Json(health_check_content)).into_response()
        }
        Err(error_detail) => {
            println!("[ERROR] {}", error_detail);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

#[derive(Serialize)]
struct HealthCheckResponse {
    date: String,
    status: HostStatus,
    remediations: Vec<String>,
}

#[derive(Serialize)]
enum HostStatus {
    Compliant,
    NotCompliant,
}

#[derive(Clone)]
struct AppState {
    managed_host: ManagedHost,
    expected_state: ExpectedState,
}

impl AppState {
    async fn check_localhost_health(
        &mut self,
    ) -> Result<(StatusCode, HealthCheckResponse), String> {
        match self
            .managed_host
            .assess_compliance(&self.expected_state, true)
            .await
        {
            Ok(compliance_status) => {
                let date = chrono::Utc::now()
                    .format("%Y-%m-%dT%H:%M:%S+00:00")
                    .to_string();

                if compliance_status.is_already_compliant() {
                    Ok((
                        StatusCode::OK,
                        HealthCheckResponse {
                            date,
                            status: HostStatus::Compliant,
                            remediations: Vec::new(),
                        },
                    ))
                } else {
                    let mut remediations_display: Vec<String> = Vec::new();

                    for remediation in compliance_status.all_remediations() {
                        remediations_display.push(remediation.display());
                    }

                    Ok((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        HealthCheckResponse {
                            date,
                            status: HostStatus::NotCompliant,
                            remediations: remediations_display,
                        },
                    ))
                }
            }
            Err(health_check_failure_details) => Err(format!(
                "Unable to perform healthcheck : {:?}",
                health_check_failure_details
            )),
        }
    }
}
