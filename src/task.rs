//! RegentTask module
//!
//! This module is meant to allow distributing the workload. A RegentTask is a unit of work. It holds everything needed to handle a managed host and what state this host is supposed to be in. A RegentTask is serializable/deserializable, meaning you can send it accross a wire (gRPC, AMQP, REST...) as JSON or YAML, have it handled by a worker node, and get back the outcome. A RegentTask contains a correlation id which you can use to track the workload accross a distributed architecture.
//!
//! # Example usage
//! ```no_run
//! let task_description = RegentTaskDescriptionBuilder::new()
//!     .
//! ```

use crate::secrets::SecretProvider;
use crate::state::ExpectedState;
use crate::state::compliance::ManagedHostStatus;
use crate::{error::Error, hosts::managed_host::ManagedHostBuilder};

use nanoid::nanoid;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RegentTask {
    managed_host_builder: ManagedHostBuilder,
    expected_state: ExpectedState,
    job: Job,
    correlation_id: String,
}

impl RegentTask {
    pub fn from(
        managed_host_builder: ManagedHostBuilder,
        expected_state: ExpectedState,
        job: Job,
    ) -> Self {
        Self {
            managed_host_builder,
            expected_state,
            job,
            correlation_id: nanoid!(),
        }
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    pub fn run(
        &mut self,
        secret_provider: &Option<SecretProvider>,
    ) -> Result<RegentTaskResult, Error> {
        // Build a ManagedHost
        let mut managed_host = self.managed_host_builder.clone().build(secret_provider)?;

        managed_host.connect()?;

        let host_status = match self.job {
            Job::Assess => managed_host.assess_compliance(&self.expected_state)?,
            Job::Reach => managed_host.reach_compliance(&self.expected_state)?,
        };

        Ok(RegentTaskResult::from(
            self.correlation_id.clone(),
            host_status,
        ))
    }
}

#[derive(Serialize, Deserialize)]
pub enum Job {
    Assess,
    Reach,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegentTaskResult {
    correlation_id: String,
    host_status: ManagedHostStatus,
}

impl RegentTaskResult {
    pub fn from(correlation_id: String, host_status: ManagedHostStatus) -> Self {
        Self {
            correlation_id,
            host_status,
        }
    }
}
