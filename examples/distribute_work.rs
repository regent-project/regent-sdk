use regent_sdk::attribute::package::pacman::{PacmanBlockExpectedState, PackageExpectedState};
use regent_sdk::task::{RegentTask, RegentTaskResult};
use regent_sdk::{Attribute, ExpectedState};
use regent_sdk::task::Job;
use regent_sdk::{LocalHostHandler, ManagedHost, Privilege, WhichUser, Error};

fn main() {
    // Sending end
    // Create a RegentTask out of multiple inputs
    let serialized_regent_task = create_a_regent_task();
    println!("{:?}", serialized_regent_task);
    // ...
    // Pass this content across a network or gRPC or RabbitMQ...
    // ...

    // Receiving end
    let regent_task_result = run_a_given_regent_task(serialized_regent_task);
    println!("{:?}", regent_task_result);

}

fn create_a_regent_task() -> String {
    // Describe the ManagedHost
    let managed_host = ManagedHost::new("localhost", LocalHostHandler::new(WhichUser::CurrentUser));

    // Describe the expected state
    let apache_expected_state = PacmanBlockExpectedState::builder()
        .with_package_state("apache", PackageExpectedState::Present)
        .build()
        .unwrap();

    let expected_state = ExpectedState::new()
        .with_attribute(Attribute::pacman(apache_expected_state, Privilege::WithSudo))
        .build();

    let regent_task = RegentTask::from(managed_host, expected_state, Job::Assess);
    
    serde_json::to_string(&regent_task).unwrap()
}

fn run_a_given_regent_task(raw_regent_task: String) -> Result<RegentTaskResult, Error> {
    let mut regent_task = serde_json::from_str::<RegentTask<LocalHostHandler>>(&raw_regent_task).unwrap();

    regent_task.run()
}