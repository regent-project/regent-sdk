# Release v0.24.0

## What's Changed

### Live view of runs (opt-in)

A run can now report what it does **while it runs**, instead of only giving its
outcome at the end: attributes being assessed, remediations being applied, and the
commands they run on the host with their output, line by line. Off by default; the
outcome of a run is the same with or without it.

- New module `hosts::live`: `LiveSink` (bounded channel, `LiveSink::channel(capacity)`),
  `LiveUpdate { run_id, host_id, job, seq, at, event }`, `LiveEvent`
  (`AttributeStarted`, `AttributeAssessed`, `RemediationStarted`,
  `RemediationFinished`, `CommandStarted`, `Output`, `CommandFinished`, `Aborted`,
  `Dropped`), `AttributeVerdict`, `OutputStream`.
- `ManagedHost::enable_live(Option<LiveSink>)` / `disable_live()` / `is_live()`, and
  the same on `LivingInventory` (every host). Without a sink, the events only go to
  the logs.
- A run never waits for the live view: when the sink is full, updates are dropped
  and counted (`LiveEvent::Dropped`).
- Output is streamed by all connection methods (localhost, SSH, SSHOQ; Windows
  commands with the `windows` feature): `HostHandler::run_command_observed` /
  `run_windows_command_observed`, with a default implementation for other
  `HostHandler` implementors (giving the whole output at once).

### Runs in the logs

- Every live event is also a flat `tracing` event (target `regent_sdk::live`, output
  lines `regent_sdk::live::output`) with `run_id`, `host_id`, `job`, `seq`, `event`,
  `attribute_index`, `attribute`, `exec_id` and its content, so one run of one host
  can be rebuilt from a log database (filter on `run_id`, sort on `seq`).
- Every run runs inside a `run{run_id, host_id, job}` span, so the SDK's other log
  lines of the run carry these fields too. `run_id` is the task's idempotency key for
  `RegentTask::run` / `run_with_cancellation` (the span also covers building and
  connecting), a random 16-character id otherwise.
- The inventory's `host` span field is renamed from `id` to `host_id`.
- New `Job::as_str()` (`"assess"` / `"reach"`).

### New feature `logging`

- `regent_sdk::logging::JsonLayer`: a `tracing-subscriber` layer writing one flat
  JSON object per line, fields of the enclosing spans merged in.
- `regent_sdk::logging::non_blocking` / `non_blocking_stdout`: a log writer that never
  blocks the program (bounded queue, dedicated thread; lines dropped and counted
  when the output cannot keep up; a guard writes the queued lines at exit).

### Secrets redaction

New module `secrets::redact`: every secret resolved during a run (and each line of a
multi-line secret) is replaced by `********`:

- in the live view (commands, output lines, remediations, outcome details);
- in the SDK's logs of a run (non-compliance, remediation outcomes, errors) and in
  the `remediation` span;
- **in the outcome**: the details of the actions taken (`InternalApiCallOutcome`,
  often a command's output) are redacted before being recorded.

Commands are shown before privilege escalation is added, so the sudo/su password of
a connection never appears. Limits: a value the command transforms (e.g. its base64)
is not caught; error values (`RegentError`) returned to the caller are not redacted.

### Other changes

- Localhost commands are spawned and their output read as it comes (same stdin,
  environment and `kill_on_drop` as before).
- tokio features `sync` and `io-util` enabled.
- docs.rs documents the `logging` and `schema` features.

### Upgrade notes

- Additive release: no change is needed for code that does not use the new APIs.
- Outcomes (`RegentTaskResult`, `ManagedHostStatus`) may now contain `********` in
  the details of actions where a secret value used to appear.
- Log consumers: the inventory's `host` span field is now `host_id` (was `id`), and
  runs add a `run` span.
- `RegentTask`'s serde and protobuf forms are unchanged.
