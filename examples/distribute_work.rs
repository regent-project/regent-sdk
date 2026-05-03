use regent_sdk::attribute::package::pacman::{PackageExpectedState, PacmanBlockExpectedState};
use regent_sdk::hosts::handlers::ConnectionMethod;
use regent_sdk::hosts::handlers::TargetUser;
use regent_sdk::hosts::managed_host::ManagedHostBuilder;
use regent_sdk::secrets::SecretProvider;
use regent_sdk::task::Job;
use regent_sdk::task::{RegentTask, RegentTaskResult};
use regent_sdk::{Attribute, ExpectedState};
use regent_sdk::{Privilege, RegentError};

fn main() {
    // Sending end
    // Create a RegentTask out of multiple inputs
    let serialized_regent_task = create_a_regent_task();
    println!("{:?}", serialized_regent_task);
    // ...
    // Pass this content across a network or gRPC or RabbitMQ...
    // ...

    // Receiving end
    // Build a SecretProvider
    let secret_provider = SecretProvider::env_var();

    let regent_task_result = run_a_given_regent_task(serialized_regent_task, Some(secret_provider));
    println!("{:?}", regent_task_result);
}

fn create_a_regent_task() -> String {
    // Describe the ManagedHost through a ManagedHostBuilder
    let managed_host_builder = ManagedHostBuilder::new(
        "<host-id>",
        "<address:port>",
        Some(ConnectionMethod::Localhost(TargetUser::user(
            "MY_CREDENTIALS_ENV_VAR_NAME",
        ))),
    );

    // Describe the expected state
    let apache_expected_state = PacmanBlockExpectedState::builder()
        .with_package_state("apache", PackageExpectedState::Present)
        .build()
        .unwrap();

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::pacman(
            apache_expected_state,
            Privilege::WithSudo,
            None,
        ))
        .build();

    let regent_task = RegentTask::from(managed_host_builder, expected_state, Job::Assess);

    serde_json::to_string(&regent_task).unwrap()
}

fn run_a_given_regent_task(
    raw_regent_task: String,
    secret_provider: Option<SecretProvider>,
) -> Result<RegentTaskResult, RegentError> {
    let mut regent_task = serde_json::from_str::<RegentTask>(&raw_regent_task).unwrap();

    regent_task.run(secret_provider)
}
