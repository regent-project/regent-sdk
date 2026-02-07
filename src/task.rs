//! Task module
//!
//! This module is meant to allow distributing the workload. A Task is a unit of work. It holds everything needed to handle a managed host and what state this host is supposed to be in. A Task is serializable/deserializable, meaning you can send it accross a wire (gRPC, AMQP, REST...) as JSON or YAML, have it handled by a worker node, and get back the outcome. A Task contains a correlation id which you can use to track the workload accross a distributed architecture.
//!
//! # Example usage
//! ```no_run
//! let task_description = TaskDescriptionBuilder::new()
//!     .
//! ```

use crate::host_handler::host_handler::HostHandler;
use crate::managed_host::HostLevelOperationOutcome;
use crate::managed_host::ManagedHost;
use crate::state::ExpectedState;

use nanoid::nanoid;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct TaskDescription<Handler: HostHandler> {
    host: ManagedHost<Handler>,
    expected_state: ExpectedState,
    mission: Mission,
    correlation_id: Option<String>,
}

impl<Handler: HostHandler> TaskDescription<Handler> {
    pub fn from(host: ManagedHost<Handler>,
    expected_state: ExpectedState,
    mission: Mission,
    correlation_id: Option<String>) -> Self {
        Self {
            host,
            expected_state,
            mission,
            correlation_id
        }
    }

    pub fn get_correlation_id(&self) -> &Option<String> {
        &self.correlation_id
    }

    pub fn run(&self) -> HostLevelOperationOutcome {
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
pub enum Mission {
    Assess,
    Reach,
}

#[derive(Serialize, Deserialize)]
pub struct TaskResult {
    correlation_id: Option<String>,
    outcome: HostLevelOperationOutcome,
}
