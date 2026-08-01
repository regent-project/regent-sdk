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
//! - **Attribute-level idempotency**: Each [`crate::state::attribute::Attribute`] is designed to be
//!   idempotent when applied to a host. For example, a service attribute that ensures nginx is
//!   running will only start the service if it's not already running, and will not cause errors
//!   if applied multiple times. This is the core idempotency of the configuration management system.
//!
//! - **Task-level idempotency**: The idempotency key in [`RegentTask`] is a helper that allows
//!   external middleware to implement task-level idempotency. If the same task is delivered
//!   multiple times (due to network retries, message queue redelivery, etc.), external systems
//!   can use this key to deduplicate the task execution. Note: **The regent-sdk crate itself does
//!   not handle task idempotency** — it only provides the key. You must implement deduplication
//!   logic in your message queue, API gateway, or other middleware.
//!
//! ## Features
//!
//! - **Serializable**: Tasks can be serialized as JSON or YAML for network transport
//! - **Self-contained**: Each task includes all information needed for execution
//! - **Task-level idempotency keys**: Unique identifiers that allow external systems to deduplicate task execution
//! - **Result reporting**: Structured results with compliance status and actions taken
//!
//! ## Quick Start
//!
//! ```no_run
//! use regent_sdk::task::{RegentTask, Job};
//! use regent_sdk::hosts::managed_host::ManagedHostBuilder;
//! use regent_sdk::state::ExpectedState;
//! use regent_sdk::hosts::handlers::ConnectionMethod;
//!
//! // Create a task
//! let managed_host_builder = ManagedHostBuilder::new(
//!     "web-server-01",
//!     "192.168.1.100:22",
//!     Some(ConnectionMethod::Localhost(TargetUser::CurrentUser)),
//! );
//!
//! let expected_state = ExpectedState::new();
//!
//! let task = RegentTask::from(
//!     managed_host_builder,
//!     expected_state,
//!     Job::Assess, // or Job::Reach for remediation
//! );
//!
//! // Serialize and send across network
//! let json = serde_json::to_string(&task).unwrap();
//!
//! // On worker: deserialize and execute
//! let mut task: RegentTask = serde_json::from_str(&json).unwrap();
//! let result = task.run(Some(secrets_pool)).await.unwrap();
//! ```

use crate::secrets::SecretProvidersPool;
use crate::state::ExpectedState;
use crate::state::compliance::ManagedHostStatus;
use crate::{error::RegentError, hosts::managed_host::ManagedHostBuilder};

use nanoid::nanoid;
use serde::{Deserialize, Serialize};

/// A unit of work for distributed configuration management.
///
/// A `RegentTask` is a self-contained task that can be serialized and sent across
/// a network to be processed by a worker node. It contains all the information needed
/// to connect to a host, assess or remediate its compliance with an expected state,
/// and return the results.
///
/// Each task has a unique idempotency key that enables task-level idempotency.
/// If the same task is delivered multiple times (e.g., due to message queue redelivery),
/// external systems can use this key to deduplicate the task execution. This is separate from
/// attribute-level idempotency, which is inherent to each attribute's design.
///
/// # Serialization
///
/// Tasks implement `Serialize` and `Deserialize`, allowing them to be transmitted
/// as JSON or YAML:
///
/// ```no_run
/// use regent_sdk::task::RegentTask;
///
/// let task = /* create task */;
/// let json = serde_json::to_string(&task).unwrap();
/// let yaml = serde_yaml::to_string(&task).unwrap();
/// ```
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
///     "server-01",
///     "192.168.1.100:22",
///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
/// );
///
/// let expected_state = ExpectedState::new();
/// let task = RegentTask::from(host_builder, expected_state, Job::Assess);
///
/// println!("Task idempotency key: {}", task.idempotency_key());
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
    ///
    /// # Arguments
    ///
    /// * `managed_host_builder` - Builder for the target host
    /// * `expected_state` - The expected state to assess/remedy
    /// * `job` - The type of job to perform (`Assess` or `Reach`)
    ///
    /// # Returns
    ///
    /// A new `RegentTask` with a randomly generated idempotency key for task-level idempotency.
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
    /// which ensures each configuration change is safely repeatable.
    ///
    /// # Returns
    ///
    /// A reference to the idempotency key string.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::task::RegentTask;
    ///
    /// let task = /* create task */;
    /// println!("Idempotency key: {}", task.idempotency_key());
    /// ```
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Execute the task.
    ///
    /// This method builds the managed host, connects to it, and performs the
    /// specified job (assess or reach compliance).
    ///
    /// # Arguments
    ///
    /// * `optional_secret_provider` - Optional secret providers pool for retrieving secrets
    ///
    /// # Returns
    ///
    /// A [`RegentTaskResult`] containing the idempotency key and host status,
    /// or a [`RegentError`] if execution failed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::task::RegentTask;
    /// use regent_sdk::secrets::{SecretProvider, SecretProvidersPoolBuilder};
    ///
    /// let mut task = /* create task */;
    /// let secrets_pool = SecretProvidersPoolBuilder::new()
    ///     .add_default_provider("files", SecretProvider::files())
    ///     .build()
    ///     .unwrap();
    ///
    /// let result = task.run(Some(secrets_pool)).await.unwrap();
    /// ```
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
/// # Variants
///
/// - `Assess`: Only assess compliance and return the current state (read-only)
/// - `Reach`: Assess compliance and automatically perform remediation to reach the expected state
///
/// # Example
///
/// ```no_run
/// use regent_sdk::task::Job;
///
/// // For read-only compliance checking
/// let job = Job::Assess;
///
/// // For automatic remediation
/// let job = Job::Reach;
/// ```
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
/// # Example
///
/// ```no_run
/// use regent_sdk::task::RegentTaskResult;
/// use regent_sdk::state::compliance::ManagedHostStatus;
///
/// let result = RegentTaskResult::from(
///     "abc123".to_string(),
///     ManagedHostStatus::already_compliant(),
/// );
///
/// assert_eq!(result.idempotency_key(), "abc123");
/// assert!(result.host_status().is_already_compliant());
/// ```
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
    /// # Arguments
    ///
    /// * `idempotency_key` - The task-level idempotency key for deduplication of task deliveries
    /// * `host_status` - The host's compliance status
    ///
    /// # Returns
    ///
    /// A new [`RegentTaskResult`] instance.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::task::RegentTaskResult;
    /// use regent_sdk::state::compliance::ManagedHostStatus;
    ///
    /// let result = RegentTaskResult::from(
    ///     "task-123".to_string(),
    ///     ManagedHostStatus::already_compliant(),
    /// );
    /// ```
    pub fn from(idempotency_key: String, host_status: ManagedHostStatus) -> Self {
        Self {
            idempotency_key,
            host_status,
        }
    }
}
