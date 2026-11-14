//! Logging helpers for programs built on the SDK (feature `logging`).
//!
//! - [`JsonLayer`]: a `tracing-subscriber` layer writing **one flat JSON object per
//!   line**, the fields of the enclosing spans merged in (innermost wins), so a log
//!   database (Grafana Loki, Elasticsearch...) can filter on any of them, e.g. the
//!   `run_id` / `host_id` of a run and the fields of the live view
//!   ([`crate::hosts::live`]).
//! - [`non_blocking`] / [`non_blocking_stdout`]: a writer that never blocks the
//!   program: lines go through a bounded queue to a dedicated thread; when the queue
//!   is full (output slower than the logs), lines are dropped and counted rather than
//!   slowing the run down.
//!
//! ```no_run
//! use regent_sdk::logging::{JsonLayer, non_blocking_stdout};
//! use tracing_subscriber::layer::SubscriberExt;
//! use tracing_subscriber::util::SubscriberInitExt;
//!
//! let (writer, guard) = non_blocking_stdout();
//! tracing_subscriber::registry()
//!     .with(JsonLayer::new(writer.clone()).with_field("service", "my-tool"))
//!     .init();
//! // ... run ...
//! drop(guard); // writes what is still queued
//! if writer.dropped_lines() > 0 {
//!     eprintln!("{} log lines dropped", writer.dropped_lines());
//! }
//! ```
//!
//! A line looks like:
//!
//! ```json
//! {"timestamp":"2026-11-14T09:23:15.123456Z","level":"info","service":"reg",
//!  "target":"regent_sdk::live::output","message":"output","span":"remediation",
//!  "spans":["run","attribute","remediation"],"run_id":"7F3C0A19B2D4E6F8",
//!  "host_id":"web1","job":"reach","seq":42,"event":"output","exec_id":3,
//!  "stream":"stdout","line":"Setting up nginx (1.26.0-1) ..."}
//! ```
//!
//! An event field clashing with a fixed key (`timestamp`, `level`, `target`,
//! `message`, `span`, `spans`, or one added with [`JsonLayer::with_field`]) is
//! renamed `field_<name>`. Keep ids (`run_id`, `host_id`...) as JSON fields, not
//! Loki labels (high cardinality).

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Keys every line has.
const FIXED_KEYS: [&str; 6] = ["timestamp", "level", "target", "message", "span", "spans"];

/// Default capacity of [`non_blocking_stdout`]'s queue, in lines.
pub const DEFAULT_QUEUE_LINES: usize = 16_384;

/// How long [`NonBlockingGuard`] waits for the queued lines to be written.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// JSON lines

/// The flat JSON-lines layer (see the module documentation).
pub struct JsonLayer<W> {
    fixed: Map<String, Value>,
    make_writer: W,
}

impl<W> JsonLayer<W> {
    /// A layer writing to `make_writer` (e.g. a [`NonBlocking`] writer).
    pub fn new(make_writer: W) -> Self {
        Self {
            fixed: Map::new(),
            make_writer,
        }
    }

    /// Add a field to every line (e.g. `service`, `version`, `instance`).
    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.fixed.insert(key.to_string(), value.into());
        self
    }
}

/// Fields of a span, stored in its extensions.
struct SpanFields(BTreeMap<String, Value>);

struct Collector<'a>(&'a mut BTreeMap<String, Value>);

impl Collector<'_> {
    fn put(&mut self, field: &Field, value: Value) {
        self.0.insert(field.name().to_string(), value);
    }
}

impl Visit for Collector<'_> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::from(value));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::from(value));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, Value::from(value.to_string()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, Value::from(format!("{value:?}")));
    }
}

impl<S, W> Layer<S> for JsonLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut values = BTreeMap::new();
        attrs.record(&mut Collector(&mut values));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(values));
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        record: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<SpanFields>()
        {
            record.record(&mut Collector(&mut fields.0));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut merged: BTreeMap<String, Value> = BTreeMap::new();
        let mut span_names = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            // root first, so inner spans override outer ones
            for span in scope.from_root() {
                span_names.push(Value::from(span.name()));
                if let Some(fields) = span.extensions().get::<SpanFields>() {
                    merged.extend(fields.0.clone());
                }
            }
        }
        let mut own = BTreeMap::new();
        event.record(&mut Collector(&mut own));
        let message = own.remove("message").unwrap_or(Value::from(""));
        merged.extend(own);

        let metadata = event.metadata();
        let mut line = Map::new();
        line.insert(
            "timestamp".into(),
            Value::from(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
        );
        line.insert(
            "level".into(),
            Value::from(metadata.level().as_str().to_ascii_lowercase()),
        );
        line.extend(self.fixed.clone());
        line.insert("target".into(), Value::from(metadata.target()));
        line.insert("message".into(), message);
        if let Some(innermost) = span_names.last() {
            line.insert("span".into(), innermost.clone());
        }
        if span_names.len() > 1 {
            line.insert("spans".into(), Value::Array(span_names));
        }
        for (key, value) in merged {
            // `log` crate records forwarded by tracing-log
            if key.starts_with("log.") {
                continue;
            }
            if FIXED_KEYS.contains(&key.as_str()) || self.fixed.contains_key(&key) {
                line.insert(format!("field_{key}"), value);
            } else {
                line.insert(key, value);
            }
        }
        if let Ok(mut bytes) = serde_json::to_vec(&Value::Object(line)) {
            bytes.push(b'\n');
            // one write per line, so concurrent lines never interleave
            let _ = self.make_writer.make_writer().write_all(&bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Non-blocking writer

enum Message {
    Line(Vec<u8>),
    /// Write everything queued before, then answer.
    Flush(SyncSender<()>),
}

/// A [`MakeWriter`] that never blocks: see [`non_blocking`]. Cheap to clone.
#[derive(Clone)]
pub struct NonBlocking {
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}

impl NonBlocking {
    /// Lines dropped so far because the queue was full.
    pub fn dropped_lines(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Writes what is still queued when dropped (waiting at most 5 s), so that the last
/// lines of a program are not lost. Keep it alive until the program ends (drop it
/// explicitly before `std::process::exit`, which runs no destructor).
pub struct NonBlockingGuard {
    tx: SyncSender<Message>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for NonBlockingGuard {
    fn drop(&mut self) {
        let (done_tx, done_rx) = sync_channel(1);
        // Blocking send on purpose: the program is ending, the queue must drain
        if self.tx.send(Message::Flush(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(FLUSH_TIMEOUT);
        }
        // The thread keeps serving other clones of the writer, if any; never joined
        // (it ends with the process)
        drop(self.thread.take());
    }
}

/// One line being formatted; queued when dropped (i.e. once complete).
pub struct LineWriter {
    buffer: Vec<u8>,
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}

impl Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let line = std::mem::take(&mut self.buffer);
        match self.tx.try_send(Message::Line(line)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl<'a> MakeWriter<'a> for NonBlocking {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> LineWriter {
        LineWriter {
            buffer: Vec::new(),
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
        }
    }
}

/// A non-blocking writer to `output`: each line (one `make_writer()` = one line) is
/// queued (at most `capacity` lines) and written by a dedicated thread. A full queue
/// drops the line and counts it ([`NonBlocking::dropped_lines`]).
pub fn non_blocking<W: Write + Send + 'static>(
    output: W,
    capacity: usize,
) -> (NonBlocking, NonBlockingGuard) {
    let (tx, rx) = sync_channel(capacity.max(1));
    let thread = std::thread::Builder::new()
        .name("regent-log-writer".into())
        .spawn(move || write_lines(output, rx))
        .expect("cannot start the log writer thread");
    (
        NonBlocking {
            tx: tx.clone(),
            dropped: Arc::new(AtomicU64::new(0)),
        },
        NonBlockingGuard {
            tx,
            thread: Some(thread),
        },
    )
}

/// [`non_blocking`] to stdout, with [`DEFAULT_QUEUE_LINES`].
pub fn non_blocking_stdout() -> (NonBlocking, NonBlockingGuard) {
    non_blocking(std::io::stdout(), DEFAULT_QUEUE_LINES)
}

fn write_lines<W: Write>(mut output: W, rx: Receiver<Message>) {
    while let Ok(message) = rx.recv() {
        let mut next = Some(message);
        // Write everything already queued, then flush once
        while let Some(message) = next.take() {
            match message {
                Message::Line(line) => {
                    let _ = output.write_all(&line);
                }
                Message::Flush(done) => {
                    let _ = output.flush();
                    let _ = done.send(());
                }
            }
            next = rx.try_recv().ok();
        }
        let _ = output.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
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

    /// An output stuck until released (a slow log pipeline).
    struct Stuck(Arc<Mutex<()>>, Buffer);

    impl Write for Stuck {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _wait = self.0.lock().unwrap();
            self.1.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lines_are_flat_json_with_span_fields() {
        let buffer = Buffer::default();
        let (writer, guard) = non_blocking(buffer.clone(), 16);
        let subscriber = tracing_subscriber::registry()
            .with(JsonLayer::new(writer).with_field("service", "reg"));
        tracing::subscriber::with_default(subscriber, || {
            let outer = tracing::info_span!("run", run_id = "R1", host_id = "web-01");
            let _o = outer.enter();
            let inner = tracing::info_span!("attribute", attr_name = "nginx");
            let _i = inner.enter();
            tracing::info!(seq = 3u64, service = "spoof", line = "hello", "output");
        });
        drop(guard);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1);
        let line: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["level"], "info");
        assert_eq!(line["service"], "reg");
        assert_eq!(line["field_service"], "spoof");
        assert_eq!(line["message"], "output");
        assert_eq!(line["run_id"], "R1");
        assert_eq!(line["attr_name"], "nginx");
        assert_eq!(line["seq"], 3);
        assert_eq!(line["span"], "attribute");
        assert_eq!(line["spans"], serde_json::json!(["run", "attribute"]));
    }

    #[test]
    fn a_stuck_output_never_blocks_and_counts_drops() {
        let gate = Arc::new(Mutex::new(()));
        let buffer = Buffer::default();
        let held = gate.lock().unwrap();
        let (writer, guard) = non_blocking(Stuck(gate.clone(), buffer.clone()), 2);
        let started = std::time::Instant::now();
        for i in 0..100 {
            let _ = writeln!(writer.make_writer(), "line {i}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "logging blocked"
        );
        // 1 line held by the thread + 2 queued; the rest dropped
        assert!(writer.dropped_lines() >= 97);
        drop(held);
        drop(guard);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(text.starts_with("line 0\n"));
    }
}
