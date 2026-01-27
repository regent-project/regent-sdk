use axum::Json;
use axum::response::Result;
use axum::{Router, extract::State, routing::get};
use regent_sdk::{
    connection::connectionmode::localhost::WhichUser,
    expected_state::global_state::{CompliancyStatus, DryRunMode, ExpectedState},
    task::moduleblock::ModuleApiCall,
    {Attribute, ManagedHost, NewConnectionDetails, Privilege, Service},
};
use serde::Serialize;

#[tokio::main]
async fn main() {
    // Build up the expected configuration of this host.
    // You can fetch this from a remote location (http endpoint, git, ftp...).
    let httpd_service_active_and_enabled = Service::ServiceBlockExpectedState::builder("httpd")
        .with_service_state(Service::ServiceExpectedStatus::Active)
        .with_autostart_state(Service::ServiceExpectedAutoStart::Enabled)
        .build()
        .unwrap();

    let localhost_expected_state = ExpectedState::new()
        .with_attribute(Attribute::Service(httpd_service_active_and_enabled))
        .build();

    let localhost_manager = ManagedHost::from(
        NewConnectionDetails::LocalHost(WhichUser::CurrentUser),
        Privilege::Usual,
    )
    .unwrap();

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
async fn health_check(State(mut app_state): State<AppState>) -> Result<Json<HealthCheckResponse>> {
    let health_check_result = app_state.check_localhost_health()?;
    Ok(Json(health_check_result))
}
#[derive(Serialize)]
struct HealthCheckResponse {
    date: String,
    status: HostStatus,
    remediations: Vec<String>
}

#[derive(Serialize)]
enum HostStatus {
    Compliant,
    NotCompliant
}

#[derive(Clone)]
struct AppState {
    managed_host: ManagedHost,
    expected_state: ExpectedState,
}

impl AppState {
    fn check_localhost_health(&mut self) -> Result<HealthCheckResponse> {
        match self
            .managed_host
            .assess_compliance_with(&self.expected_state, DryRunMode::Parallel)
        {
            Ok(compliancy_status) => {
                let date = chrono::Utc::now()
                    .format("%Y-%m-%dT%H:%M:%S+00:00")
                    .to_string();

                match compliancy_status {
                    CompliancyStatus::Compliant => Ok(HealthCheckResponse {
                        date,
                        status: HostStatus::Compliant,
                        remediations: Vec::new()
                    }),
                    CompliancyStatus::NotCompliant(step_changes) => {
                        let mut changes = Vec::new();
                        for step in step_changes {
                            if let ModuleApiCall::None(_) = step {
                                // Filtering out all criterias which are already matched here
                            } else {
                                changes.push(format!("{}", step));
                            }
                        }
                        Ok(HealthCheckResponse {
                            date,
                            status: HostStatus::NotCompliant,
                            remediations: changes
                        })
                    }
                }
            }
            Err(health_check_failure_details) => {
                println!("Healthcheck nok : {:?}", health_check_failure_details);
                Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR.into())
            }
        }
    }
}
