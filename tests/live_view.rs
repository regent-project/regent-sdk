//! Live view (`regent_sdk::hosts::live`) of a run on localhost: the sink, and (with
//! feature `logging`) its tracing form, redaction included.

use regent_sdk::hosts::handlers::{ConnectionMethod, TargetUser};
use regent_sdk::hosts::live::{AttributeVerdict, LiveEvent, LiveSink, REDACTED};
use regent_sdk::secrets::{SecretProvider, SecretProvidersPool, SecretProvidersPoolBuilder};
use regent_sdk::{ExpectedState, ManagedHost, ManagedHostBuilder};
use std::time::{Duration, Instant};

/// A command (read from a secret) printing its own command line: the secret shows
/// up in its output, hence in the outcome's details and in the logs.
const SECRET_CMD: &str = r"tr '\0' ' ' < /proc/$$/cmdline";

const STATE: &str = r#"---
Attributes:
  - Name: slow
    Privilege: !None
    Detail: !Command
      Cmd: "printf 'first\n'; sleep 1; printf 'second\n'"
  - Name: from a secret
    Privilege: !None
    Detail: !Command
      Cmd:
        SecRef: REGENT_LIVE_VIEW_TEST_CMD
        Provider: env
"#;

fn secrets() -> SecretProvidersPool {
    // SAFETY: the only environment variable of these tests, always set to the same
    // value before being read
    unsafe { std::env::set_var("REGENT_LIVE_VIEW_TEST_CMD", SECRET_CMD) };
    SecretProvidersPoolBuilder::new()
        .with_default_provider(&SecretProvider::env_var("env"))
        .build()
        .unwrap()
}

fn localhost() -> ManagedHostBuilder {
    let mut builder = ManagedHostBuilder::new(
        "local",
        "localhost",
        Some(ConnectionMethod::Localhost(TargetUser::current_user())),
    );
    builder.set_host_lock(None);
    builder
}

async fn connected_host() -> ManagedHost {
    let mut host = localhost().build(Some(secrets())).await.unwrap();
    host.connect().await.unwrap();
    host
}

#[tokio::test]
async fn reach_streams_commands_while_they_run() {
    let mut host = connected_host().await;
    let (sink, mut updates) = LiveSink::channel(1024);
    host.enable_live(Some(sink));

    // Receive while the run goes on, noting when each update arrived
    let receiver = tokio::spawn(async move {
        let mut received = Vec::new();
        while let Some(update) = updates.recv().await {
            received.push((Instant::now(), update));
        }
        received
    });

    let state = ExpectedState::from_raw_yaml(STATE).unwrap();
    let status = host.reach_compliance(&state).await.unwrap();
    assert!(status.is_reach_compliance_success());
    host.disable_live(); // last sender: ends the receiver
    let received = receiver.await.unwrap();

    // One run of one host, numbered in order
    let first = &received[0].1;
    assert_eq!(first.host_id, "local");
    assert!(
        received
            .iter()
            .all(|(_, update)| update.run_id == first.run_id)
    );
    let seqs: Vec<u64> = received.iter().map(|(_, update)| update.seq).collect();
    assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<_>>());
    let events: Vec<&LiveEvent> = received.iter().map(|(_, update)| &update.event).collect();

    // Attribute and remediation steps, in order
    assert!(matches!(events[0], LiveEvent::AttributeStarted { index: 0, name } if name == "slow"));
    assert!(matches!(
        events[1],
        LiveEvent::AttributeAssessed {
            index: 0,
            verdict: AttributeVerdict::NonCompliant { remediations: 1 }
        }
    ));
    assert!(matches!(
        events[2],
        LiveEvent::RemediationStarted { index: 0, .. }
    ));

    // The slow command: its lines come one second apart, i.e. while it runs
    assert!(matches!(
        events[3],
        LiveEvent::CommandStarted { exec_id: 1, command } if command.starts_with("printf 'first")
    ));
    let line_at = |wanted: &str| {
        received
            .iter()
            .find_map(|(at, update)| match &update.event {
                LiveEvent::Output {
                    exec_id: 1, line, ..
                } if line == wanted => Some(*at),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no line {wanted:?} in {events:#?}"))
    };
    assert!(line_at("second") - line_at("first") >= Duration::from_millis(800));
    assert!(events.iter().any(|event| matches!(
        event,
        LiveEvent::CommandFinished {
            exec_id: 1,
            return_code: Some(0)
        }
    )));

    // The secret is hidden in the command, its output and the outcome's details
    assert!(events.iter().any(|event| matches!(
        event,
        LiveEvent::CommandStarted { exec_id: 2, command } if command == REDACTED
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        LiveEvent::Output { exec_id: 2, line, .. } if line.trim() == format!("sh -c {REDACTED}")
    )));
    assert!(matches!(
        events.last().unwrap(),
        LiveEvent::RemediationFinished {
            index: 1,
            outcome: Some(_)
        }
    ));
    assert!(!format!("{events:?}").contains("/proc/"));
    let outcome = serde_json::to_string(&status).unwrap();
    assert!(outcome.contains(REDACTED) && !outcome.contains("/proc/"));
}

#[tokio::test]
async fn no_live_view_by_default() {
    let host = localhost().build(None).await.unwrap();
    assert!(!host.is_live());
}

#[cfg(feature = "logging")]
mod logs {
    use super::*;
    use regent_sdk::logging::{JsonLayer, non_blocking};
    use regent_sdk::task::{Job, RegentTask};
    use serde_json::Value;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `run` with the JSON layer installed (on this thread), return the lines.
    /// (Boxed: a run's future is large in debug builds, keep it off the stack.)
    async fn json_logs(run: std::pin::Pin<Box<dyn Future<Output = ()>>>) -> (String, Vec<Value>) {
        let buffer = Buffer::default();
        let (writer, guard) = non_blocking(buffer.clone(), 4096);
        let subscriber = tracing_subscriber::registry().with(JsonLayer::new(writer));
        let default = tracing::subscriber::set_default(subscriber);
        run.await;
        drop(default);
        drop(guard);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        (text, lines)
    }

    #[tokio::test]
    async fn live_events_are_flat_tracing_events_of_the_run() {
        let (text, lines) = json_logs(Box::pin(async {
            let mut host = connected_host().await;
            host.enable_live(None); // logs only
            let state = ExpectedState::from_raw_yaml(STATE).unwrap();
            host.reach_compliance(&state).await.unwrap();
        }))
        .await;

        // Nothing shows the secret: live events, the SDK's other logs, spans
        assert!(!text.contains("/proc/"), "secret in logs:\n{text}");

        let live: Vec<&Value> = lines
            .iter()
            .filter(|line| {
                line["target"]
                    .as_str()
                    .unwrap()
                    .starts_with("regent_sdk::live")
            })
            .collect();
        let run_id = live[0]["run_id"].as_str().unwrap();
        assert_eq!(run_id.len(), 16);
        for (n, line) in live.iter().enumerate() {
            assert_eq!(line["run_id"], run_id);
            assert_eq!(line["host_id"], "local");
            assert_eq!(line["job"], "reach");
            assert_eq!(line["seq"], n as u64 + 1, "in order, numbered from 1");
        }
        let output: Vec<&Value> = live
            .iter()
            .copied()
            .filter(|line| line["target"] == "regent_sdk::live::output")
            .collect();
        assert_eq!(output[0]["event"], "output");
        assert_eq!(output[0]["line"], "first");
        assert_eq!(output[0]["exec_id"], 1);
        assert_eq!(output[0]["stream"], "stdout");
        assert_eq!(output[0]["attribute_index"], 0);
        assert_eq!(output[0]["attribute"], "slow");

        // The SDK's other logs of the run carry the run too (through its span)
        let not_compliant = lines
            .iter()
            .find(|line| line["message"] == "Not compliant")
            .unwrap();
        assert_eq!(not_compliant["run_id"], run_id);
    }

    #[tokio::test]
    async fn a_task_run_is_identified_by_its_key() {
        let (_, lines) = json_logs(Box::pin(async {
            let state = ExpectedState::from_raw_yaml(STATE).unwrap();
            let mut task = RegentTask::from(localhost(), state, Job::Assess)
                .with_idempotency_key("task-key-1");
            task.run(Some(secrets())).await;
        }))
        .await;
        let not_compliant = lines
            .iter()
            .find(|line| line["message"] == "Not compliant")
            .unwrap();
        assert_eq!(not_compliant["run_id"], "task-key-1");
        assert_eq!(not_compliant["job"], "assess");
    }
}
