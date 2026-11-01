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

use chrono::{DateTime, Utc};
use nanoid::nanoid;
use serde::{Deserialize, Serialize};

/// A unit of work for distributed configuration management.
///
/// # Example
/// ```no_run
/// # use regent_sdk::task::{RegentTask, Job};
/// # use regent_sdk::hosts::managed_host::ManagedHostBuilder;
/// # use regent_sdk::state::ExpectedState;
/// # use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
/// let host_builder = ManagedHostBuilder::new(
///     "server-01",
///     "192.168.1.100:22",
///     Some(ConnectionMethod::Localhost(TargetUser::current_user())),
/// );
///
/// let expected_state = ExpectedState::new();
/// let task = RegentTask::from(host_builder, expected_state, Job::Assess);
/// ```
#[derive(Serialize, Deserialize, Clone)]
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

    /// Let the caller choose the idempotency key.
    ///
    /// Useful when several producers may create the same logical task (e.g. replicated
    /// schedulers firing the same recurring rule): deriving the key deterministically
    /// lets consumers deduplicate them.
    ///
    /// # Choosing a key
    ///
    /// Two producers must derive the **same** key for the same logical task, and
    /// **different** keys for tasks that must both run. Build it only from facts every
    /// producer agrees on (host id, job, rule or order id, scheduled time, …) and never
    /// from producer-local data (replica name, process id, `Utc::now()` at firing time,
    /// random values). Including the host id and the job keeps keys from colliding
    /// across hosts and between `Assess` and `Reach`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::{DateTime, Utc};
    /// use regent_sdk::hosts::managed_host::ManagedHostBuilder;
    /// use regent_sdk::state::ExpectedState;
    /// use regent_sdk::task::{Job, RegentTask};
    ///
    /// let web_01 = ManagedHostBuilder::new("web-01", "10.0.0.1:22", None);
    ///
    /// // 1. Recurring rule: host + rule + scheduled slot. Every replica computes the
    /// //    same slot from the rule's period, whatever the instant it actually fires.
    /// //    Rule "rule-42": assess web-01 every 10 minutes.
    /// let period_secs: i64 = 600;
    /// let now = Utc::now().timestamp();
    /// let slot = DateTime::<Utc>::from_timestamp(now - now.rem_euclid(period_secs), 0).unwrap();
    /// let recurring = RegentTask::from(web_01.clone(), ExpectedState::new(), Job::Assess)
    ///     .with_idempotency_key(format!("web-01:assess:rule-42:{}", slot.to_rfc3339()));
    /// // e.g. "web-01:assess:rule-42:2026-11-01T10:00:00+00:00"
    ///
    /// // 2. User order: the id of the request that triggered the task, generated once
    /// //    on the client side. A double click or a resubmit after a timeout reuses it.
    /// let order_id = "01JBX4Z8Q7R3V2K9M5N6P0T1WS";
    /// let user_order = RegentTask::from(web_01.clone(), ExpectedState::new(), Job::Reach)
    ///     .with_idempotency_key(format!("order:{order_id}:web-01:reach"));
    ///
    /// // 3. Change of expected state: the revision that changed it (e.g. a Git commit).
    /// //    Every watcher noticing the same commit produces the same key; the next
    /// //    commit produces a new one.
    /// let commit_sha = "3f9c2a1e";
    /// let state_change = RegentTask::from(web_01, ExpectedState::new(), Job::Reach)
    ///     .with_idempotency_key(format!("web-01:reach:git:{commit_sha}"));
    ///
    /// // 4. Fan-out of a batch: batch id + host. A batch targeting a whole inventory
    /// //    yields one key per host, and re-publishing the batch is harmless.
    /// let batch_id = "batch-2026-11-01-001";
    /// let batch: Vec<RegentTask> = ["web-01", "web-02", "db-01"]
    ///     .into_iter()
    ///     .map(|host_id| {
    ///         RegentTask::from(
    ///             ManagedHostBuilder::new(host_id, host_id, None),
    ///             ExpectedState::new(),
    ///             Job::Assess,
    ///         )
    ///         .with_idempotency_key(format!("{batch_id}:{host_id}:assess"))
    ///     })
    ///     .collect();
    /// ```
    ///
    /// A key built from a hash of the task content alone (host + job + expected state)
    /// also deduplicates, but it suppresses *legitimate* repetitions of an identical
    /// task too; add a time slot or a trigger id as above. Note also that
    /// `std::hash::DefaultHasher` output is not guaranteed stable across Rust releases,
    /// so use a stable hash (e.g. SHA-256) if producers may run different builds.
    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = idempotency_key.into();
        self
    }

    /// Identifier of the managed host this task targets.
    pub fn host_id(&self) -> &str {
        &self.managed_host_builder.id
    }

    /// The job this task performs (assess or reach compliance).
    pub fn job(&self) -> Job {
        self.job
    }

    /// The host builder this task will use to reach the managed host.
    pub fn managed_host_builder(&self) -> &ManagedHostBuilder {
        &self.managed_host_builder
    }

    /// The expected state this task assesses or enforces.
    pub fn expected_state(&self) -> &ExpectedState {
        &self.expected_state
    }

    /// Execute the task.
    ///
    /// This method builds the managed host, connects to it, and performs the
    /// specified job (assess or reach compliance).
    ///
    /// Always returns a [`RegentTaskResult`]: a failure (host unreachable, secret
    /// missing, ...) is reported in its outcome, with the same timestamps as a success.
    ///
    pub async fn run(
        &mut self,
        optional_secret_provider: Option<SecretProvidersPool>,
    ) -> RegentTaskResult {
        let started_at = Utc::now();
        let outcome = self.execute(optional_secret_provider).await;

        RegentTaskResult::from(
            self.idempotency_key.clone(),
            self.managed_host_builder.id.clone(),
            self.job,
            started_at,
            Utc::now(),
            outcome,
        )
    }

    async fn execute(
        &self,
        optional_secret_provider: Option<SecretProvidersPool>,
    ) -> Result<ManagedHostStatus, RegentError> {
        // Build a ManagedHost
        let mut managed_host = self
            .managed_host_builder
            .clone()
            .build(optional_secret_provider)
            .await?;

        managed_host.connect().await?;

        match self.job {
            Job::Assess => {
                managed_host
                    .assess_compliance(&self.expected_state, true)
                    .await
            }
            Job::Reach => managed_host.reach_compliance(&self.expected_state).await,
        }
    }
}

/// The type of job for a [`RegentTask`] to perform.
///
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
/// Contains the task-level idempotency key for deduplication purposes, the host and job
/// it concerns, when it started and finished, and its outcome: the host's compliance
/// status, or the error that made the task fail. This key allows external systems
/// to identify duplicate task deliveries, which is separate from attribute-level idempotency.
///
#[derive(Serialize, Deserialize, Debug)]
pub struct RegentTaskResult {
    /// The idempotency key of the task that produced this result.
    idempotency_key: String,
    /// Identifier of the managed host the task ran against.
    host_id: String,
    /// The job that was performed.
    job: Job,
    /// When the task started (before connecting to the host).
    started_at: DateTime<Utc>,
    /// When the task finished, successfully or not.
    finished_at: DateTime<Utc>,
    /// The compliance status of the host, or the error that made the task fail.
    outcome: Result<ManagedHostStatus, RegentError>,
}

impl RegentTaskResult {
    /// Create a new task result.
    ///
    pub fn from(
        idempotency_key: String,
        host_id: String,
        job: Job,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        outcome: Result<ManagedHostStatus, RegentError>,
    ) -> Self {
        Self {
            idempotency_key,
            host_id,
            job,
            started_at,
            finished_at,
            outcome,
        }
    }

    /// When the task started (before connecting to the host).
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// When the task finished, successfully or not.
    pub fn finished_at(&self) -> DateTime<Utc> {
        self.finished_at
    }

    /// The idempotency key of the task that produced this result.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Identifier of the managed host the task ran against.
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// The job that was performed.
    pub fn job(&self) -> Job {
        self.job
    }

    /// Whether the task ran to completion, i.e. a compliance status was obtained.
    ///
    /// This says nothing about the host being compliant: an assessment that finds the
    /// host non-compliant still ran to completion. Check [`Self::host_status`] for that.
    pub fn task_ran_to_completion(&self) -> bool {
        self.outcome.is_ok()
    }

    /// The outcome of the task: the host's compliance status, or the error that made it fail.
    pub fn outcome(&self) -> &Result<ManagedHostStatus, RegentError> {
        &self.outcome
    }

    /// The compliance status of the host, if the task succeeded.
    pub fn host_status(&self) -> Option<&ManagedHostStatus> {
        self.outcome.as_ref().ok()
    }

    /// The error that made the task fail, if any.
    pub fn error(&self) -> Option<&RegentError> {
        self.outcome.as_ref().err()
    }

    /// Consume the result and return its outcome.
    pub fn into_outcome(self) -> Result<ManagedHostStatus, RegentError> {
        self.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::compliance::ManagedHostStatus;

    fn sample_task() -> RegentTask {
        let host_builder = ManagedHostBuilder::new("server-01", "192.168.1.100:22", None);
        RegentTask::from(host_builder, ExpectedState::new(), Job::Reach)
    }

    #[test]
    fn task_accessors_survive_serde_roundtrip() {
        let task = sample_task().with_idempotency_key("fixed-key");
        let raw = serde_json::to_string(&task).unwrap();
        let task = serde_json::from_str::<RegentTask>(&raw).unwrap();

        assert_eq!(task.idempotency_key(), "fixed-key");
        assert_eq!(task.host_id(), "server-01");
        assert_eq!(task.job(), Job::Reach);
    }

    #[test]
    fn result_accessors_survive_serde_roundtrip() {
        let started_at = Utc::now();
        let finished_at = started_at + chrono::Duration::seconds(3);
        let result = RegentTaskResult::from(
            "fixed-key".to_string(),
            "server-01".to_string(),
            Job::Assess,
            started_at,
            finished_at,
            Ok(ManagedHostStatus::already_compliant()),
        );
        let raw = serde_json::to_string(&result).unwrap();
        let result = serde_json::from_str::<RegentTaskResult>(&raw).unwrap();

        assert_eq!(result.idempotency_key(), "fixed-key");
        assert_eq!(result.host_id(), "server-01");
        assert_eq!(result.job(), Job::Assess);
        assert_eq!(result.started_at(), started_at);
        assert_eq!(result.finished_at(), finished_at);
        assert!(result.task_ran_to_completion());
        assert!(result.host_status().unwrap().is_already_compliant());
    }

    #[test]
    fn failed_result_keeps_error_and_timestamps() {
        let started_at = Utc::now();
        let finished_at = started_at + chrono::Duration::seconds(1);
        let result = RegentTaskResult::from(
            "fixed-key".to_string(),
            "server-01".to_string(),
            Job::Reach,
            started_at,
            finished_at,
            Err(RegentError::FailureToEstablishConnection(
                "connection refused".to_string(),
            )),
        );
        let raw = serde_json::to_string(&result).unwrap();
        let result = serde_json::from_str::<RegentTaskResult>(&raw).unwrap();

        assert!(!result.task_ran_to_completion());
        assert!(result.host_status().is_none());
        assert_eq!(result.finished_at(), finished_at);
        assert!(matches!(
            result.error(),
            Some(RegentError::FailureToEstablishConnection(msg)) if msg == "connection refused"
        ));
    }
}
