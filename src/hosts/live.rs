//! Live view of a run (opt-in)
//!
//! By default, an assessment or an enforcement only gives its outcome once it is
//! over. With the live mode on ([`ManagedHost::enable_live`](crate::ManagedHost::enable_live),
//! [`RegentTask::enable_live`](crate::RegentTask::enable_live) for a task, or
//! [`LivingInventory::enable_live`](crate::hosts::inventory::LivingInventory::enable_live)
//! for every host), the run also reports what it does as it goes: attributes being
//! assessed, remediations being applied, and the commands they run on the host with
//! their output, **line by line, while the command is running**.
//!
//! The live view is extra information: the outcome of the run is exactly the same
//! with or without it.
//!
//! # Two outputs of the same events
//!
//! Each [`LiveEvent`] goes:
//!
//! - **to `tracing`**, always (when the live mode is on), as one flat event with
//!   the fields below, so that a log database (Grafana Loki, Elasticsearch...) can
//!   rebuild the live view of one run of one host. Targets: `regent_sdk::live` for
//!   the steps, `regent_sdk::live::output` for the output lines (filter it out to
//!   keep the steps only, e.g. `RUST_LOG=info,regent_sdk::live::output=off`);
//! - **to a [`LiveSink`]**, if one is given: typed [`LiveUpdate`]s for a program
//!   showing the live view itself (a terminal, a UI).
//!
//! Fields of the tracing events (every run also runs inside a `run` span with
//! `run_id`, `host_id` and `job`, so the SDK's other logs of the run carry them too):
//!
//! | Field | |
//! |---|---|
//! | `run_id` | one run of one host: the task's idempotency key for a [`RegentTask`](crate::RegentTask), a random id otherwise |
//! | `host_id`, `job` | the host, `assess` / `reach` |
//! | `seq` | position of the event in the run (from 1): the exact order, even when timestamps tie |
//! | `event` | `attribute_started`, `attribute_assessed`, `remediation_started`, `remediation_finished`, `command_started`, `output`, `command_finished`, `aborted` |
//! | `attribute_index`, `attribute` | the attribute being handled (index from 0, name) |
//! | `exec_id` | the command (from 1 within the run), on `command_*` and `output` |
//! | `command`, `stream`, `line`, `return_code`, `verdict`, `remediations`, `remediation`, `outcome`, `details`, `error` | the content of the event |
//!
//! Example query rebuilding one run in Loki:
//!
//! ```text
//! {service="reg"} | json | run_id="7F3C0A19B2D4E6F8" | target=~"regent_sdk::live.*"
//! ```
//!
//! # Delivery
//!
//! The run **never waits** for a consumer of the live view:
//!
//! - the sink is a bounded channel: when it is full, updates are dropped and
//!   counted, and a [`LiveEvent::Dropped`] tells the consumer how many were lost as
//!   soon as there is room again;
//! - tracing events are written by whatever subscriber the program installed: use a
//!   non-blocking writer (e.g. [`crate::logging::non_blocking_stdout`], feature
//!   `logging`) so that a slow log pipeline does not slow the run down.
//!
//! # Secrets
//!
//! - Commands are shown as the attribute wrote them, **before** privilege
//!   escalation is added: the sudo/su password embedded by the connection layer is
//!   never part of a [`LiveEvent::CommandStarted`].
//! - Every secret resolved during the run (through the host's
//!   [`SecretProvidersPool`](crate::secrets::SecretProvidersPool)) is replaced by
//!   [`REDACTED`] in commands, output lines, remediations and outcome details
//!   (see [`crate::secrets::redact`]). The tracing events only carry redacted text.
//!
//! Commands run by the SDK itself to probe the host (e.g. is this command
//! available?) are not shown.
//!
//! # Example
//!
//! ```no_run
//! use regent_sdk::hosts::live::{LiveEvent, LiveSink};
//! # async fn example(mut host: regent_sdk::ManagedHost, state: regent_sdk::ExpectedState) {
//! let (sink, mut updates) = LiveSink::channel(1024);
//! host.enable_live(Some(sink));
//!
//! let printer = tokio::spawn(async move {
//!     while let Some(update) = updates.recv().await {
//!         if let LiveEvent::Output { line, .. } = &update.event {
//!             println!("[{}] {}", update.host_id, line);
//!         }
//!     }
//! });
//!
//! let status = host.assess_compliance(&state, false).await;
//! host.disable_live(); // drops the last sender: the printer ends
//! printer.await.unwrap();
//! # }
//! ```

use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::error::RegentError;
use crate::hosts::command::CommandResult;
use crate::hosts::handlers::HostHandler;
use crate::hosts::lock::{HostLock, HostLockMode, HostLockSettings};
use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::hosts::privilege::Privilege;
use crate::secrets::redact::{Redaction, Redactor};
use crate::state::attribute::Remediation;
use crate::task::Job;

pub use crate::secrets::redact::REDACTED;

/// Lines longer than this (in bytes) are split, so that a command printing without
/// newlines still shows up while it runs.
const MAX_LINE_BYTES: usize = 8192;

/// Which output stream of a command a line comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputStream {
    /// Standard output (and standard error when the command merges it with `2>&1`,
    /// which the SDK does for Unix commands).
    Stdout,
    /// Standard error.
    Stderr,
}

impl OutputStream {
    /// `"stdout"` or `"stderr"` (as in logs).
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        }
    }
}

/// Result of the assessment of one attribute.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AttributeVerdict {
    /// The host is compliant with this attribute.
    Compliant,
    /// The host is not compliant; this many remediations would fix it.
    NonCompliant {
        /// Number of remediations proposed.
        remediations: usize,
    },
    /// The host is not compliant and no remediation is possible.
    NonCompliantFatal {
        /// Why (secrets redacted).
        details: String,
    },
    /// The assessment itself failed.
    Failed {
        /// The error (secrets redacted).
        error: String,
    },
}

/// One step of a run.
///
/// `index` is the position of the attribute in the expected state (from 0);
/// `exec_id` identifies a command within one host's run (from 1).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LiveEvent {
    /// The assessment of an attribute starts (also during an enforcement, which
    /// assesses each attribute first).
    AttributeStarted {
        /// Position of the attribute in the expected state.
        index: usize,
        /// Its name ([`Attribute::name`](crate::Attribute::name)).
        name: String,
    },
    /// The attribute has been assessed.
    AttributeAssessed {
        /// Position of the attribute in the expected state.
        index: usize,
        /// The result.
        verdict: AttributeVerdict,
    },
    /// A remediation of the attribute starts (enforcement only).
    RemediationStarted {
        /// Position of the attribute in the expected state.
        index: usize,
        /// The remediation being applied.
        remediation: Remediation,
    },
    /// The remediation is over; `None` if it could not be applied at all (the
    /// run then ends with an error).
    RemediationFinished {
        /// Position of the attribute in the expected state.
        index: usize,
        /// Its outcome (details redacted).
        outcome: Option<InternalApiCallOutcome>,
    },
    /// A command starts on the host.
    CommandStarted {
        /// Identifier of the command within this host's run.
        exec_id: u64,
        /// The command, without privilege escalation, secrets redacted.
        command: String,
    },
    /// One line printed by a running command (without its line terminator,
    /// secrets redacted).
    Output {
        /// The command printing it.
        exec_id: u64,
        /// Which stream.
        stream: OutputStream,
        /// The line.
        line: String,
    },
    /// The command is over; `return_code` is `None` if it could not be run
    /// (connection lost, ...).
    CommandFinished {
        /// The command.
        exec_id: u64,
        /// Its exit code.
        return_code: Option<i64>,
    },
    /// The run was aborted (cancellation).
    Aborted,
    /// This many updates were lost because the sink's consumer did not keep up.
    /// They may come from any host sharing the sink. Sink only (not logged).
    Dropped {
        /// How many.
        updates: u64,
    },
}

/// A [`LiveEvent`] of one run of one host, timestamped.
#[derive(Debug, Clone)]
pub struct LiveUpdate {
    /// The run it belongs to (see the module documentation).
    pub run_id: String,
    /// The host it comes from.
    pub host_id: String,
    /// The job of the run.
    pub job: Job,
    /// Position of the event in the run (from 1); 0 for [`LiveEvent::Dropped`].
    pub seq: u64,
    /// When it happened.
    pub at: DateTime<Utc>,
    /// What happened.
    pub event: LiveEvent,
}

/// Where a run sends its [`LiveUpdate`]s. Cheap to clone: one sink can be shared by
/// many hosts (each update carries its host id and run id).
#[derive(Clone, Debug)]
pub struct LiveSink {
    tx: mpsc::Sender<LiveUpdate>,
    dropped: Arc<AtomicU64>,
}

impl LiveSink {
    /// A sink over an existing channel.
    pub fn new(tx: mpsc::Sender<LiveUpdate>) -> Self {
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A new bounded channel holding at most `capacity` updates, and its sink.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<LiveUpdate>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self::new(tx), rx)
    }

    /// Send an update without ever waiting (see the module documentation).
    fn send(&self, update: LiveUpdate) {
        if self.tx.is_closed() {
            return;
        }
        let lost = self.dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let dropped = LiveUpdate {
                seq: 0,
                event: LiveEvent::Dropped { updates: lost },
                ..update.clone()
            };
            if self.tx.try_send(dropped).is_err() {
                self.dropped.fetch_add(lost + 1, Ordering::Relaxed);
                return;
            }
        }
        if self.tx.try_send(update).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The live view of a run, kept once it is over: its [`LiveUpdate`]s in order, up to
/// a size limit.
///
/// Fill it from the receiver of a [`LiveSink`] while forwarding the updates
/// elsewhere (a UI, a collector), then store it with the run's outcome. Beyond
/// `limit_bytes` (an estimate of the text the updates hold, see
/// [`LiveUpdate::approx_size`]), later updates are not kept but counted
/// ([`RunLog::omitted_updates`]): a cropped log says so ([`RunLog::is_truncated`]).
///
/// ```
/// use regent_sdk::hosts::live::RunLog;
/// let log = RunLog::new(1024 * 1024);
/// assert!(!log.is_truncated());
/// ```
#[derive(Debug, Clone, Default)]
pub struct RunLog {
    /// The updates kept, in the order they were received.
    updates: Vec<LiveUpdate>,
    /// Maximum size kept, in bytes (estimate); 0 = no limit.
    limit_bytes: u64,
    /// Size of the updates kept, in bytes (estimate).
    size_bytes: u64,
    /// Updates not kept because of the limit.
    omitted_updates: u64,
    /// Updates the run produced but the sink lost ([`LiveEvent::Dropped`]).
    dropped_updates: u64,
}

impl RunLog {
    /// An empty log keeping at most `limit_bytes` (estimate; 0 = no limit).
    pub fn new(limit_bytes: u64) -> Self {
        Self {
            limit_bytes,
            ..Self::default()
        }
    }

    /// Add an update; returns `false` if it was not kept (limit reached).
    /// [`LiveEvent::Dropped`] is never kept: it is added to
    /// [`RunLog::dropped_updates`].
    pub fn push(&mut self, update: LiveUpdate) -> bool {
        if let LiveEvent::Dropped { updates } = update.event {
            self.dropped_updates += updates;
            return false;
        }
        let size = update.approx_size() as u64;
        if self.omitted_updates > 0
            || (self.limit_bytes > 0 && self.size_bytes + size > self.limit_bytes)
        {
            self.omitted_updates += 1;
            return false;
        }
        self.size_bytes += size;
        self.updates.push(update);
        true
    }

    /// Apply a smaller limit to a log already filled (e.g. by a collector enforcing
    /// its own limit on logs it receives): the updates beyond it are removed and
    /// counted as omitted. A limit of 0, or one larger than the current limit,
    /// changes nothing.
    pub fn crop(&mut self, limit_bytes: u64) {
        if limit_bytes == 0 || (self.limit_bytes != 0 && limit_bytes >= self.limit_bytes) {
            return;
        }
        self.limit_bytes = limit_bytes;
        let mut size = 0u64;
        let keep = self
            .updates
            .iter()
            .take_while(|update| {
                size += update.approx_size() as u64;
                size <= limit_bytes
            })
            .count();
        let removed = self.updates.len() - keep;
        if removed > 0 {
            self.updates.truncate(keep);
            self.omitted_updates += removed as u64;
            self.size_bytes = self.updates.iter().map(|u| u.approx_size() as u64).sum();
        }
    }

    /// The updates kept, in order.
    pub fn updates(&self) -> &[LiveUpdate] {
        &self.updates
    }

    /// The updates kept, in order.
    pub fn into_updates(self) -> Vec<LiveUpdate> {
        self.updates
    }

    /// Maximum size kept, in bytes (estimate); 0 = no limit.
    pub fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    /// Size of the updates kept, in bytes (estimate).
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Updates not kept because the limit was reached.
    pub fn omitted_updates(&self) -> u64 {
        self.omitted_updates
    }

    /// Updates lost by the sink before they reached this log.
    pub fn dropped_updates(&self) -> u64 {
        self.dropped_updates
    }

    /// Whether the log is incomplete (limit reached, or updates lost by the sink).
    pub fn is_truncated(&self) -> bool {
        self.omitted_updates > 0 || self.dropped_updates > 0
    }
}

impl LiveUpdate {
    /// Estimated size of the update in bytes: its text plus a fixed overhead (used
    /// by [`RunLog`]'s limit; close to, not equal to, its encoded size).
    pub fn approx_size(&self) -> usize {
        const OVERHEAD: usize = 32;
        let content = match &self.event {
            LiveEvent::AttributeStarted { name, .. } => name.len(),
            LiveEvent::AttributeAssessed { verdict, .. } => match verdict {
                AttributeVerdict::NonCompliantFatal { details } => details.len(),
                AttributeVerdict::Failed { error } => error.len(),
                _ => 0,
            },
            LiveEvent::RemediationStarted { remediation, .. } => format!("{remediation:?}").len(),
            LiveEvent::RemediationFinished { outcome, .. } => format!("{outcome:?}").len(),
            LiveEvent::CommandStarted { command, .. } => command.len(),
            LiveEvent::Output { line, .. } => line.len(),
            LiveEvent::CommandFinished { .. } | LiveEvent::Aborted | LiveEvent::Dropped { .. } => 0,
        };
        OVERHEAD + self.run_id.len() + self.host_id.len() + content
    }
}

/// The live mode of a host: on, with or without a sink.
#[derive(Clone, Debug, Default)]
pub(crate) struct LiveMode {
    pub(crate) sink: Option<LiveSink>,
}

/// Everything one run of one host needs to report live events.
pub(crate) struct LiveContext {
    sink: Option<LiveSink>,
    run_id: String,
    host_id: String,
    job: Job,
    redactor: Redactor,
    seq: AtomicU64,
    next_exec_id: AtomicU64,
    /// The attribute being handled (set by `AttributeStarted`).
    attribute: Mutex<Option<(usize, String)>>,
    /// The latest snapshot of the run's secrets (to redact typed values in logs).
    redaction: Mutex<Redaction>,
}

impl LiveContext {
    pub(crate) fn new(
        mode: &LiveMode,
        run_id: &str,
        host_id: &str,
        job: Job,
        redactor: Redactor,
    ) -> Self {
        Self {
            sink: mode.sink.clone(),
            run_id: run_id.to_string(),
            host_id: host_id.to_string(),
            job,
            redactor,
            seq: AtomicU64::new(1),
            next_exec_id: AtomicU64::new(1),
            attribute: Mutex::new(None),
            redaction: Mutex::new(Redaction::default()),
        }
    }

    /// The secrets resolved so far (also kept for the tracing form of events).
    pub(crate) async fn redaction(&self) -> Redaction {
        let redaction = self.redactor.snapshot().await;
        *self.redaction.lock().unwrap_or_else(|e| e.into_inner()) = redaction.clone();
        redaction
    }

    /// Report an event (its text must already be redacted).
    pub(crate) fn emit(&self, event: LiveEvent) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if let LiveEvent::AttributeStarted { index, name } = &event {
            *self.attribute.lock().unwrap_or_else(|e| e.into_inner()) =
                Some((*index, name.clone()));
        }
        self.log(seq, &event);
        if let Some(sink) = &self.sink {
            sink.send(LiveUpdate {
                run_id: self.run_id.clone(),
                host_id: self.host_id.clone(),
                job: self.job,
                seq,
                at: Utc::now(),
                event,
            });
        }
    }

    /// The tracing form of an event: flat fields, see the module documentation.
    fn log(&self, seq: u64, event: &LiveEvent) {
        let attribute = self
            .attribute
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let attribute_index = attribute.as_ref().map(|(index, _)| *index as u64);
        let attribute = attribute.as_ref().map(|(_, name)| name.as_str());
        let run_id = self.run_id.as_str();
        let host_id = self.host_id.as_str();
        let job = self.job.as_str();

        // The common fields, then the event's own ones
        macro_rules! live {
            ($macro:ident, $target:literal, $event:literal, $message:literal $(, $($field:tt)*)?) => {
                $macro!(
                    target: $target,
                    run_id, host_id, job, seq, attribute_index, attribute,
                    event = $event,
                    $($($field)*,)?
                    $message
                )
            };
        }

        match event {
            LiveEvent::AttributeStarted { .. } => {
                live!(
                    info,
                    "regent_sdk::live",
                    "attribute_started",
                    "attribute started"
                )
            }
            LiveEvent::AttributeAssessed { verdict, .. } => match verdict {
                AttributeVerdict::Compliant => live!(
                    info,
                    "regent_sdk::live",
                    "attribute_assessed",
                    "attribute assessed",
                    verdict = "compliant"
                ),
                AttributeVerdict::NonCompliant { remediations } => live!(
                    info,
                    "regent_sdk::live",
                    "attribute_assessed",
                    "attribute assessed",
                    verdict = "non_compliant",
                    remediations = *remediations as u64
                ),
                AttributeVerdict::NonCompliantFatal { details } => live!(
                    warn,
                    "regent_sdk::live",
                    "attribute_assessed",
                    "attribute assessed",
                    verdict = "non_compliant_fatal",
                    details = details.as_str()
                ),
                AttributeVerdict::Failed { error } => live!(
                    warn,
                    "regent_sdk::live",
                    "attribute_assessed",
                    "attribute assessed",
                    verdict = "failed",
                    error = error.as_str()
                ),
            },
            LiveEvent::RemediationStarted { remediation, .. } => {
                let remediation = self
                    .redaction
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .debug(remediation);
                live!(
                    info,
                    "regent_sdk::live",
                    "remediation_started",
                    "remediation started",
                    remediation = remediation.as_str()
                )
            }
            LiveEvent::RemediationFinished { outcome, .. } => match outcome {
                Some(InternalApiCallOutcome::Success(details)) => live!(
                    info,
                    "regent_sdk::live",
                    "remediation_finished",
                    "remediation finished",
                    outcome = "success",
                    details = details.as_deref()
                ),
                Some(InternalApiCallOutcome::AllowedFailure(details)) => live!(
                    info,
                    "regent_sdk::live",
                    "remediation_finished",
                    "remediation finished",
                    outcome = "allowed_failure",
                    details = details.as_str()
                ),
                Some(InternalApiCallOutcome::Failure(details)) => live!(
                    warn,
                    "regent_sdk::live",
                    "remediation_finished",
                    "remediation finished",
                    outcome = "failure",
                    details = details.as_str()
                ),
                None => live!(
                    warn,
                    "regent_sdk::live",
                    "remediation_finished",
                    "remediation finished",
                    outcome = "error"
                ),
            },
            LiveEvent::CommandStarted { exec_id, command } => live!(
                info,
                "regent_sdk::live",
                "command_started",
                "command started",
                exec_id = *exec_id,
                command = command.as_str()
            ),
            LiveEvent::Output {
                exec_id,
                stream,
                line,
            } => live!(
                info,
                "regent_sdk::live::output",
                "output",
                "output",
                exec_id = *exec_id,
                stream = stream.as_str(),
                line = line.as_str()
            ),
            LiveEvent::CommandFinished {
                exec_id,
                return_code,
            } => live!(
                info,
                "regent_sdk::live",
                "command_finished",
                "command finished",
                exec_id = *exec_id,
                return_code = *return_code
            ),
            LiveEvent::Aborted => live!(warn, "regent_sdk::live", "aborted", "run aborted"),
            LiveEvent::Dropped { .. } => {}
        }
    }
}

/// Turns output chunks into [`LiveEvent::Output`] lines.
struct LineSplitter<'a> {
    live: &'a LiveContext,
    redaction: &'a Redaction,
    exec_id: u64,
    stdout: PartialLine,
    stderr: PartialLine,
}

/// The unterminated end of a stream's output.
#[derive(Default)]
struct PartialLine {
    bytes: Vec<u8>,
    /// The last byte seen was a '\r' (so a '\n' right after it ends no new line).
    after_cr: bool,
}

impl LineSplitter<'_> {
    fn new<'a>(live: &'a LiveContext, redaction: &'a Redaction, exec_id: u64) -> LineSplitter<'a> {
        LineSplitter {
            live,
            redaction,
            exec_id,
            stdout: PartialLine::default(),
            stderr: PartialLine::default(),
        }
    }

    fn push(&mut self, stream: OutputStream, bytes: &[u8]) {
        for &byte in bytes {
            let partial = self.partial(stream);
            let after_cr = std::mem::replace(&mut partial.after_cr, byte == b'\r');
            match byte {
                b'\n' if after_cr => {}
                b'\n' | b'\r' => self.flush(stream),
                _ => {
                    partial.bytes.push(byte);
                    if partial.bytes.len() >= MAX_LINE_BYTES {
                        self.flush(stream);
                    }
                }
            }
        }
    }

    /// Send what remains (output not ending with a line terminator).
    fn finish(&mut self) {
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            if !self.partial(stream).bytes.is_empty() {
                self.flush(stream);
            }
        }
    }

    fn partial(&mut self, stream: OutputStream) -> &mut PartialLine {
        match stream {
            OutputStream::Stdout => &mut self.stdout,
            OutputStream::Stderr => &mut self.stderr,
        }
    }

    fn flush(&mut self, stream: OutputStream) {
        let bytes = std::mem::take(&mut self.partial(stream).bytes);
        let line = self.redaction.apply(&String::from_utf8_lossy(&bytes));
        self.live.emit(LiveEvent::Output {
            exec_id: self.exec_id,
            stream,
            line,
        });
    }
}

/// The handler given to attributes: forwards everything to the real handler and,
/// when the live mode is on, reports the commands it runs.
pub(crate) struct LiveHandler<'a, H: HostHandler> {
    inner: &'a mut H,
    live: Option<&'a LiveContext>,
}

impl<'a, H: HostHandler> LiveHandler<'a, H> {
    pub(crate) fn new(inner: &'a mut H, live: Option<&'a LiveContext>) -> Self {
        Self { inner, live }
    }
}

impl LiveContext {
    async fn command_started(&self, command: &str) -> (u64, Redaction) {
        let redaction = self.redaction().await;
        let exec_id = self.next_exec_id.fetch_add(1, Ordering::Relaxed);
        self.emit(LiveEvent::CommandStarted {
            exec_id,
            command: redaction.apply(command),
        });
        (exec_id, redaction)
    }

    fn command_finished(&self, exec_id: u64, result: &Result<CommandResult, RegentError>) {
        self.emit(LiveEvent::CommandFinished {
            exec_id,
            return_code: result.as_ref().ok().map(|output| output.return_code),
        });
    }
}

impl<H: HostHandler> HostHandler for LiveHandler<'_, H> {
    async fn connect(&mut self, endpoint: &str) -> Result<(), RegentError> {
        self.inner.connect(endpoint).await
    }

    async fn is_connected(&mut self) -> bool {
        self.inner.is_connected().await
    }

    async fn disconnect(&mut self) -> Result<(), RegentError> {
        self.inner.disconnect().await
    }

    async fn is_this_command_available(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<bool, RegentError> {
        self.inner
            .is_this_command_available(command, privilege)
            .await
    }

    async fn run_command(
        &mut self,
        command: &str,
        privilege: &Privilege,
    ) -> Result<CommandResult, RegentError> {
        let Some(live) = self.live else {
            return self.inner.run_command(command, privilege).await;
        };
        let (exec_id, redaction) = live.command_started(command).await;
        let mut lines = LineSplitter::new(live, &redaction, exec_id);
        let result = self
            .inner
            .run_command_observed(command, privilege, &mut |stream, bytes| {
                lines.push(stream, bytes)
            })
            .await;
        lines.finish();
        live.command_finished(exec_id, &result);
        result
    }

    #[cfg(feature = "windows")]
    async fn run_windows_command(&mut self, command: &str) -> Result<CommandResult, RegentError> {
        let Some(live) = self.live else {
            return self.inner.run_windows_command(command).await;
        };
        let (exec_id, redaction) = live.command_started(command).await;
        let mut lines = LineSplitter::new(live, &redaction, exec_id);
        let result = self
            .inner
            .run_windows_command_observed(command, &mut |stream, bytes| lines.push(stream, bytes))
            .await;
        lines.finish();
        live.command_finished(exec_id, &result);
        result
    }

    async fn get_file(&mut self, path: PathBuf) -> Result<Vec<u8>, RegentError> {
        self.inner.get_file(path).await
    }

    async fn acquire_host_lock(
        &mut self,
        settings: &HostLockSettings,
        mode: HostLockMode,
    ) -> Result<HostLock, RegentError> {
        self.inner.acquire_host_lock(settings, mode).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(capacity: usize) -> (LiveContext, mpsc::Receiver<LiveUpdate>) {
        let (sink, rx) = LiveSink::channel(capacity);
        let mode = LiveMode { sink: Some(sink) };
        (
            LiveContext::new(&mode, "R1", "h1", Job::Assess, Redactor::default()),
            rx,
        )
    }

    fn lines(rx: &mut mpsc::Receiver<LiveUpdate>) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(update) = rx.try_recv() {
            if let LiveEvent::Output { line, .. } = update.event {
                lines.push(line);
            }
        }
        lines
    }

    #[test]
    fn splits_chunks_into_lines() {
        let (live, mut rx) = context(64);
        let redaction = Redaction::of(&["s3cr3t"]);
        let mut splitter = LineSplitter::new(&live, &redaction, 1);
        splitter.push(OutputStream::Stdout, b"hel");
        splitter.push(OutputStream::Stdout, b"lo\r\nwor");
        splitter.push(OutputStream::Stdout, b"ld\n\npassword=s3c");
        splitter.push(OutputStream::Stdout, b"r3t");
        splitter.finish();
        assert_eq!(
            lines(&mut rx),
            ["hello", "world", "", "password=********"].map(String::from)
        );
    }

    #[test]
    fn updates_are_numbered_and_carry_the_run() {
        let (live, mut rx) = context(8);
        live.emit(LiveEvent::AttributeStarted {
            index: 0,
            name: "a".into(),
        });
        live.emit(LiveEvent::Aborted);
        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert_eq!((first.seq, second.seq), (1, 2));
        assert_eq!((second.run_id.as_str(), second.job), ("R1", Job::Assess));
    }

    #[test]
    fn never_blocks_and_reports_drops() {
        let (live, mut rx) = context(2);
        for _ in 0..5 {
            live.emit(LiveEvent::Aborted);
        }
        assert_eq!(rx.try_recv().unwrap().host_id, "h1");
        rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());
        live.emit(LiveEvent::Aborted);
        assert!(matches!(
            rx.try_recv().unwrap().event,
            LiveEvent::Dropped { updates: 3 }
        ));
        assert!(matches!(rx.try_recv().unwrap().event, LiveEvent::Aborted));
    }

    fn update(seq: u64, event: LiveEvent) -> LiveUpdate {
        LiveUpdate {
            run_id: "R1".into(),
            host_id: "h1".into(),
            job: Job::Reach,
            seq,
            at: Utc::now(),
            event,
        }
    }

    fn line(seq: u64, text: &str) -> LiveUpdate {
        update(
            seq,
            LiveEvent::Output {
                exec_id: 1,
                stream: OutputStream::Stdout,
                line: text.into(),
            },
        )
    }

    #[test]
    fn run_log_keeps_updates_up_to_its_limit() {
        let one = line(1, "0123456789").approx_size() as u64;
        let mut log = RunLog::new(2 * one);
        assert!(log.push(line(1, "0123456789")));
        assert!(log.push(line(2, "0123456789")));
        assert!(!log.is_truncated());
        assert!(!log.push(line(3, "0123456789")));
        // once cropped, nothing later is kept (no hole in the middle of the log)
        assert!(!log.push(line(4, "")));
        assert_eq!(log.updates().len(), 2);
        assert_eq!((log.omitted_updates(), log.size_bytes()), (2, 2 * one));
        assert!(log.is_truncated());
    }

    #[test]
    fn run_log_crop_applies_a_smaller_limit_only() {
        let one = line(1, "0123456789").approx_size() as u64;
        let mut log = RunLog::new(0);
        for seq in 1..=5 {
            log.push(line(seq, "0123456789"));
        }
        log.crop(3 * one);
        assert_eq!((log.updates().len(), log.omitted_updates()), (3, 2));
        assert_eq!((log.limit_bytes(), log.size_bytes()), (3 * one, 3 * one));
        log.crop(10 * one); // larger: no change
        log.crop(0);
        assert_eq!((log.updates().len(), log.limit_bytes()), (3, 3 * one));
        assert!(log.is_truncated());
    }

    #[test]
    fn run_log_counts_sink_drops_and_has_no_limit_at_zero() {
        let mut log = RunLog::new(0);
        for seq in 1..=100 {
            assert!(log.push(line(seq, "some output")));
        }
        assert!(!log.push(update(0, LiveEvent::Dropped { updates: 7 })));
        assert_eq!((log.updates().len(), log.dropped_updates()), (100, 7));
        assert!(log.is_truncated());
    }
}

#[cfg(feature = "proto")]
#[path = "../proto/conv/hosts__live.rs"]
mod proto_conv;
