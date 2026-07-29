//! Task distribution module
//!
//! This module provides the [`RegentTask`] type for distributing configuration management
//! workloads across multiple workers. A `RegentTask` is a self-contained unit of work
//! that can be serialized and sent across a network (via gRPC, AMQP, REST, etc.) to be
//! processed by a worker node.
//!
//! ## Features
//!
//! - **Serializable**: Tasks can be serialized as JSON or YAML for network transport
//! - **Self-contained**: Each task includes all information needed for execution
//! - **Correlation IDs**: Unique identifiers for tracking tasks across distributed systems
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
/// Each task has a unique correlation ID that can be used to track the task
/// across a distributed architecture.
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
/// println!("Task correlation ID: {}", task.correlation_id());
/// ```
#[derive(Serialize, Deserialize)]
pub struct RegentTask {
    managed_host_builder: ManagedHostBuilder,
    expected_state: ExpectedState,
    job: Job,
    correlation_id: String,
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
    /// A new `RegentTask` with a randomly generated correlation ID.
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
            correlation_id: nanoid!(
                16,
                &[
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                ]
            ),
        }
    }

    /// Get the correlation ID for this task.
    ///
    /// The correlation ID is a unique identifier that can be used to track
    /// this task across a distributed architecture.
    ///
    /// # Returns
    ///
    /// A reference to the correlation ID string.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use regent_sdk::task::RegentTask;
    ///
    /// let task = /* create task */;
    /// println!("Tracking ID: {}", task.correlation_id());
    /// ```
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
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
    /// A [`RegentTaskResult`] containing the correlation ID and host status,
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
            self.correlation_id.clone(),
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
/// Contains the correlation ID for tracking and the host's compliance status.
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
/// assert_eq!(result.correlation_id(), "abc123");
/// assert!(result.host_status().is_already_compliant());
/// ```
#[derive(Serialize, Deserialize, Debug)]
pub struct RegentTaskResult {
    /// The correlation ID of the task that produced this result.
    correlation_id: String,
    /// The compliance status of the host after task execution.
    host_status: ManagedHostStatus,
}

impl RegentTaskResult {
    /// Create a new task result.
    ///
    /// # Arguments
    ///
    /// * `correlation_id` - The correlation ID of the task
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
    pub fn from(correlation_id: String, host_status: ManagedHostStatus) -> Self {
        Self {
            correlation_id,
            host_status,
        }
    }
}
