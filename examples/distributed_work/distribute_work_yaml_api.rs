use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool};
use regent_sdk::task::Job;
use regent_sdk::task::{RegentTask, RegentTaskResult};
use regent_sdk::{ExpectedState, RegentError};

#[tokio::main]
async fn main() {
    // Sending end
    let serialized_regent_task = create_a_regent_task();
    println!("{:?}", serialized_regent_task);
    // ...
    // Pass this content across a network or gRPC or RabbitMQ...
    // ...

    // Receiving end
    let secret_providers =
        SecretProvidersPool::with_default_provider(&SecretProvider::env_var("env_vars"));

    let regent_task_result =
        run_a_given_regent_task(serialized_regent_task, Some(secret_providers)).await;
    println!("{:?}", regent_task_result);
}

fn create_a_regent_task() -> String {
    let host_description = r#"---
Id: <host-id>
Endpoint: <address:port>
HostConnectionMethod: !Localhost
  UserKind: !User
    SecRef: MY_CREDENTIALS_ENV_VAR_NAME
    Provider: env_vars
"#;

    let managed_host_builder = ManagedHostBuilder::from_raw_yaml(host_description).unwrap();

    let expected_state_description = r#"---
Attributes:
  - Name: apache package is installed
    Privilege: !WithSudo
    Detail: !Pacman
      Package: apache
      State: Present
"#;

    let expected_state = ExpectedState::from_raw_yaml(expected_state_description).unwrap();

    let regent_task = RegentTask::from(managed_host_builder, expected_state, Job::Assess);

    serde_json::to_string(&regent_task).unwrap()
}

async fn run_a_given_regent_task(
    raw_regent_task: String,
    secret_provider: Option<SecretProvidersPool>,
) -> Result<RegentTaskResult, RegentError> {
    let mut regent_task = serde_json::from_str::<RegentTask>(&raw_regent_task).unwrap();

    regent_task.run(secret_provider).await
}
