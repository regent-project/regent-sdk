# Release v0.25.0

## What's Changed

### Live view of tasks

- `RegentTask::enable_live(Option<LiveSink>)` / `disable_live()` / `is_live()`: the
  live view (0.24.0) for runs of a `RegentTask`, whose updates carry the task's
  idempotency key as `run_id`. Not part of the task's serialized form (a worker turns
  it on itself); the serde and protobuf forms of `RegentTask` are unchanged.
- New `hosts::live::RunLog` (re-exported as `regent_sdk::RunLog`): the live view of a
  run kept once it is over, up to a size limit (`RunLog::new(limit_bytes)`, estimate
  from `LiveUpdate::approx_size`). Beyond it later updates are counted
  (`omitted_updates`), as are updates lost by the sink (`dropped_updates`);
  `is_truncated()` says the log is incomplete; `crop(limit_bytes)` applies a smaller
  limit afterwards (e.g. a collector enforcing its own).

### Protobuf (features `proto` / `grpc`)

- `LiveUpdate` and `RunLog` are mirrored in `model.proto` (with everything they
  contain): `to_proto` / `from_proto` / `to_proto_bytes` / `from_proto_bytes`, like
  `RegentTaskResult`. A `LiveEvent` variant unknown to the reader is a
  `ProtoError::UnknownVariant` (skip the update).
- `Reporting` service: new client-streaming `ReportLive(stream ReportLiveRequest)`
  (batches of `LiveUpdate`s of a pass, best effort), and `ReportOutcomeRequest`
  gains `run_log` (field 3).

### Upgrade notes

- **gRPC servers** implementing `Reporting` must add `report_live` (e.g. answer
  `Status::unimplemented`). Clients and the protobuf wire format are unaffected
  (additive).

# Release v0.24.1

## What's Changed

- Fix: in debug builds, a run on localhost overflowed the stack of a tokio worker
  thread (2 MiB; 0.24.0 needed about 2.1 MiB, 0.23.1 about 0.3 MiB). The read
  buffers of a command's output were part of its future, which debug builds copy
  along each `.await`; they are now on the heap. Release builds were not affected.
- New test: a run (live view on) fits in a 1 MiB thread stack.
