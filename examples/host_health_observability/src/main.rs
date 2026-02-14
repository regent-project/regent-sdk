use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Router, extract::State, routing::get};
use serde::Serialize;

use regent_sdk::attribute::system::service::{
    ServiceBlockExpectedState, ServiceExpectedAutoStart, ServiceExpectedStatus,
};
use regent_sdk::{Attribute, ExpectedState};
use regent_sdk::{LocalHostHandler, ManagedHost, Privilege, WhichUser};

#[tokio::main]
async fn main() {
    // Build up the expected configuration of this host.
    // You can fetch this from a remote location (http endpoint, git, ftp...).
    let httpd_service_active_and_enabled = ServiceBlockExpectedState::builder("httpd")
        .with_service_state(ServiceExpectedStatus::Active)
        .with_autostart_state(ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    let localhost_expected_state = ExpectedState::new()
        .with_attribute(Attribute::service(
            httpd_service_active_and_enabled,
            Privilege::None,
        ))
        .build();

    let mut localhost_manager =
        ManagedHost::new("localhost", LocalHostHandler::new(WhichUser::CurrentUser));

    // Create a state for the webapp, holding the host expected configuration and how regent is supposed to interact with it
    let app_state = AppState {
        managed_host: localhost_manager,
        expected_state: localhost_expected_state,
    };

    // Finally, create the http endpoint with a dedicated route for the healthcheck
    let api_app = Router::new()
        .route("/health", get(health_check))
        .with_state(app_state);

    let api_endpoint = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(api_endpoint, api_app.into_make_service()).await;
}

// This handler will run the healtcheck on localhost
async fn health_check(State(mut app_state): State<AppState>) -> impl IntoResponse {
    match app_state.check_localhost_health() {
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
    managed_host: ManagedHost<LocalHostHandler>,
    expected_state: ExpectedState,
}

impl AppState {
    fn check_localhost_health(&mut self) -> Result<(StatusCode, HealthCheckResponse), String> {
        match self.managed_host.assess_compliance(&self.expected_state) {
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
