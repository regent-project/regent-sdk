//! Task distribution module
//!
//! This module provides the [`RegentTask`] type for distributing configuration management
//! workloads across multiple workers. A `RegentTask` is a self-contained unit of work
//! that can be serialized and sent across a network (via gRPC, AMQP, REST, etc.) to be
//! processed by a worker node.
//!
//! ## Idempotency: Attribute-level vs Task-level
//!
//! Regent SDK implements idempotency at two distinct levels:
//!
//! - **Attribute-level idempotency**: Is the host compliant with its expected state, as described by its attributes ?
//!
//! - **Task-level idempotency**: Has this task already been executed, meaning has this host compliance already been checked/fixed by some other worker ? The idempotency key in [`RegentTask`] is a helper that allows external middleware to implement task-level idempotency. If the same task is delivered multiple times (due to network retries, message queue redelivery, etc.), external systems can use this key to deduplicate the task execution. Note: **The regent-sdk crate itself does not handle task idempotency** — it only provides the key. You must implement deduplication logic in your message queue, API gateway, or other middleware.
//!

use crate::secrets::SecretProvidersPool;
use crate::state::ExpectedState;
use crate::state::compliance::ManagedHostStatus;
use crate::{error::RegentError, hosts::managed_host::ManagedHostBuilder};

use nanoid::nanoid;
use serde::{Deserialize, Serialize};

/// A unit of work for distributed configuration management.
///
/// # Example
/// ```no_run
/// let host_builder = ManagedHostBuilder::new(
///     "server-01",
///     "192.168.1.100:22",
///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
/// );
///
/// let expected_state = ExpectedState::new();
/// let task = RegentTask::from(host_builder, expected_state, Job::Assess);
/// ```
#[derive(Serialize, Deserialize)]
pub struct RegentTask {
    managed_host_builder: ManagedHostBuilder,
    expected_state: ExpectedState,
    job: Job,
    idempotency_key: String,
}

impl RegentTask {
    /// Create a new `RegentTask` from a host builder, expected state, and job type.
    /// Returns a new `RegentTask` with a randomly generated idempotency key for task-level idempotency.
    /// This allows external systems to detect and skip duplicate task deliveries.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::task::{RegentTask, Job};
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    /// use regent_sdk::state::ExpectedState;
    /// use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
    ///
    /// let host_builder = ManagedHostBuilder::new(
    ///     "my-host",
    ///     "localhost",
    ///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    /// );
    ///
    /// let expected_state = ExpectedState::new();
    /// let task = RegentTask::from(host_builder, expected_state, Job::Assess);
    /// ```
    pub fn from(
        managed_host_builder: ManagedHostBuilder,
        expected_state: ExpectedState,
        job: Job,
    ) -> Self {
        Self {
            managed_host_builder,
            expected_state,
            job,
            idempotency_key: nanoid!(
                16,
                &[
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                ]
            ),
        }
    }

    /// Get the task-level idempotency key for this task.
    ///
    /// This key is a unique identifier that enables task-level idempotency. When the same
    /// task is delivered multiple times to a worker, external systems can use this key to
    /// deduplicate the execution. Note: this is separate from attribute-level idempotency,
    /// which ensures each configuration change is safely repeatable
    /// 
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Execute the task.
    ///
    /// This method builds the managed host, connects to it, and performs the
    /// specified job (assess or reach compliance).
    /// 
    pub async fn run(
        &mut self,
        optional_secret_provider: Option<SecretProvidersPool>,
    ) -> Result<RegentTaskResult, RegentError> {
        // Build a ManagedHost
        let mut managed_host = self
            .managed_host_builder
            .clone()
            .build(optional_secret_provider)
            .await?;

        managed_host.connect().await?;

        let host_status = match self.job {
            Job::Assess => managed_host.assess_compliance(&self.expected_state).await?,
            Job::Reach => managed_host.reach_compliance(&self.expected_state).await?,
        };

        Ok(RegentTaskResult::from(
            self.idempotency_key.clone(),
            host_status,
        ))
    }
}

/// The type of job for a [`RegentTask`] to perform.
/// 
#[derive(Serialize, Deserialize)]
pub enum Job {
    /// Assess compliance only (read-only operation).
    ///
    /// This will check if the host is compliant with the expected state
    /// and return the compliance status without making any changes.
    Assess,
    /// Assess and remediate compliance (read-write operation).
    ///
    /// This will check compliance and automatically perform the necessary
    /// remediations to bring the host into the expected state.
    Reach,
}

/// Result of executing a [`RegentTask`].
///
/// Contains the task-level idempotency key for deduplication purposes, along with the
/// host's compliance status. This key allows external systems to identify duplicate
/// task deliveries, which is separate from attribute-level idempotency.
///
#[derive(Serialize, Deserialize, Debug)]
pub struct RegentTaskResult {
    /// The idempotency key of the task that produced this result.
    idempotency_key: String,
    /// The compliance status of the host after task execution.
    host_status: ManagedHostStatus,
}

impl RegentTaskResult {
    /// Create a new task result.
    /// 
    pub fn from(idempotency_key: String, host_status: ManagedHostStatus) -> Self {
        Self {
            idempotency_key,
            host_status,
        }
    }
}
