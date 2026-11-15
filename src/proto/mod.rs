//! Protobuf mirror of regent-sdk's outcome types (feature `proto`).
//!
//! The serde layout of [`RegentTaskResult`](crate::task::RegentTaskResult) changes
//! between regent-sdk versions, so a producer and a consumer built on different
//! versions cannot exchange it as JSON. Its protobuf form can: field numbers never
//! change (see `proto/regent/v1/protogen.lock.json`), and a reader keeps the fields
//! it does not know and writes them back unchanged when it re-serializes the
//! message (Google's protobuf runtime).
//!
//! - Schema: `proto/regent/v1/model.proto` (generated from the Rust types by
//!   `tools/protogen`; never edit it by hand) and `proto/regent/v1/reporting.proto`
//!   (hand-written service, feature `grpc`).
//! - Messages: the types re-exported from this module (`regent_sdk::proto::RegentTaskResult`, …).
//! - Conversions: [`RegentTaskResult::to_proto`](crate::task::RegentTaskResult::to_proto),
//!   [`RegentTaskResult::from_proto`](crate::task::RegentTaskResult::from_proto) and their
//!   `_bytes` variants.
//!
//! Converting a message into Rust types drops what this version does not know: a
//! variant added by a newer regent-sdk becomes `Remediation::None(..)` (unknown
//! remediation) or `RegentError::AnyOtherError(..)` (unknown error). To pass data on
//! without loss, forward the message (or its bytes) rather than the Rust value.
//!
//! # Example
//!
//! ```no_run
//! # fn example(result: regent_sdk::task::RegentTaskResult) -> Result<(), regent_sdk::proto::ProtoError> {
//! use regent_sdk::task::RegentTaskResult;
//!
//! let bytes = result.to_proto_bytes()?;            // e.g. published on a message queue
//! let back = RegentTaskResult::from_proto_bytes(&bytes)?;
//! assert_eq!(back.idempotency_key(), result.idempotency_key());
//! # Ok(())
//! # }
//! ```

mod generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/protobuf_generated/regent/v1/generated.rs"
    ));
}

pub(crate) mod convert;
#[cfg(feature = "grpc")]
pub mod grpc;

pub use generated::*;

/// Re-export of the protobuf runtime, so callers use the same version.
pub use protobuf as runtime;

use convert::{FromProtoValue, IntoProtoValue};
use protobuf::{Parse, Serialize};

/// Error converting between protobuf messages and regent-sdk types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// A `oneof` holds a variant this version does not know (sent by a newer
    /// regent-sdk), or none at all.
    #[error("unknown variant of `{0}` (from a newer regent-sdk?)")]
    UnknownVariant(&'static str),
    /// A required field is absent.
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    /// A number does not fit the Rust type.
    #[error("value out of range in `{0}`")]
    OutOfRange(&'static str),
    /// A value cannot be parsed (e.g. an invalid IP address).
    #[error("invalid value in `{field}`: {details}")]
    InvalidValue {
        field: &'static str,
        details: String,
    },
    /// A string field is not valid UTF-8.
    #[error("invalid UTF-8 in a string field")]
    InvalidUtf8,
    /// The bytes are not a valid protobuf message.
    #[error("cannot parse protobuf message: {0}")]
    Parse(String),
    /// The message cannot be serialized.
    #[error("cannot serialize protobuf message: {0}")]
    Serialize(String),
}

/// `to_proto` / `from_proto` / `to_proto_bytes` / `from_proto_bytes` of a mirrored root type.
macro_rules! proto_root {
    ($rust:path, $message:ident, $what:literal) => {
        impl $rust {
            #[doc = concat!("Convert ", $what, " into its protobuf message.")]
            pub fn to_proto(&self) -> $message {
                self.into_proto_value()
            }

            #[doc = concat!("Convert ", $what, " from its protobuf message. Variants unknown to this")]
            /// version are replaced where a fallback exists (see the
            /// [module docs](crate::proto)); other inconsistencies are errors.
            pub fn from_proto(message: &$message) -> Result<Self, ProtoError> {
                Self::from_proto_value(message.as_view())
            }

            /// Serialize as protobuf bytes.
            pub fn to_proto_bytes(&self) -> Result<Vec<u8>, ProtoError> {
                self.to_proto()
                    .serialize()
                    .map_err(|e| ProtoError::Serialize(format!("{e:?}")))
            }

            /// Parse protobuf bytes.
            pub fn from_proto_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
                let message =
                    $message::parse(bytes).map_err(|e| ProtoError::Parse(format!("{e:?}")))?;
                Self::from_proto(&message)
            }
        }
    };
}

proto_root!(
    crate::task::RegentTaskResult,
    RegentTaskResult,
    "a task result"
);
proto_root!(crate::hosts::live::LiveUpdate, LiveUpdate, "a live update");
proto_root!(crate::hosts::live::RunLog, RunLog, "a run log");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RegentError;
    use crate::state::compliance::ManagedHostStatus;
    use crate::task::Job;
    use chrono::Utc;

    fn sample(outcome: Result<ManagedHostStatus, RegentError>) -> crate::task::RegentTaskResult {
        let started_at = Utc::now();
        crate::task::RegentTaskResult::from(
            "key-1".to_string(),
            "web-01".to_string(),
            Job::Reach,
            started_at,
            started_at + chrono::Duration::milliseconds(1500),
            outcome,
        )
    }

    #[test]
    fn task_result_roundtrips_through_bytes() {
        for result in [
            sample(Ok(ManagedHostStatus::already_compliant())),
            sample(Ok(ManagedHostStatus::aborted(Vec::new()))),
            sample(Err(RegentError::HostBusy("held".to_string()))),
        ] {
            let bytes = result.to_proto_bytes().unwrap();
            let back = crate::task::RegentTaskResult::from_proto_bytes(&bytes).unwrap();
            assert_eq!(
                serde_json::to_value(&result).unwrap(),
                serde_json::to_value(&back).unwrap()
            );
        }
    }

    #[test]
    fn live_update_and_run_log_roundtrip_through_bytes() {
        use crate::hosts::live::{LiveEvent, LiveUpdate, OutputStream, RunLog};
        let update = |seq, event| LiveUpdate {
            run_id: "key-1".into(),
            host_id: "web-01".into(),
            job: Job::Reach,
            seq,
            at: Utc::now(),
            event,
        };
        let mut log = RunLog::new(0);
        for (seq, event) in [
            (
                1,
                LiveEvent::AttributeStarted {
                    index: 0,
                    name: "nginx".into(),
                },
            ),
            (
                2,
                LiveEvent::CommandStarted {
                    exec_id: 1,
                    command: "apt-get install nginx".into(),
                },
            ),
            (
                3,
                LiveEvent::Output {
                    exec_id: 1,
                    stream: OutputStream::Stderr,
                    line: "done".into(),
                },
            ),
            (
                4,
                LiveEvent::CommandFinished {
                    exec_id: 1,
                    return_code: Some(0),
                },
            ),
            (5, LiveEvent::Aborted),
        ] {
            let one = update(seq, event);
            let back = LiveUpdate::from_proto_bytes(&one.to_proto_bytes().unwrap()).unwrap();
            assert_eq!(format!("{one:?}"), format!("{back:?}"));
            log.push(one);
        }
        log.push(update(0, LiveEvent::Dropped { updates: 2 }));
        let back = RunLog::from_proto_bytes(&log.to_proto_bytes().unwrap()).unwrap();
        assert_eq!(format!("{log:?}"), format!("{back:?}"));
        assert_eq!((back.updates().len(), back.dropped_updates()), (5, 2));
    }

    #[test]
    fn unknown_fields_survive_reserialization() {
        let mut bytes = sample(Ok(ManagedHostStatus::already_compliant()))
            .to_proto_bytes()
            .unwrap();
        // field 999 (length-delimited "newer"), as a newer regent-sdk could add
        bytes.extend_from_slice(&[0xba, 0x3e, 5, b'n', b'e', b'w', b'e', b'r']);
        let message = RegentTaskResult::parse(&bytes).unwrap();
        let reserialized = message.serialize().unwrap();
        assert!(reserialized.windows(5).any(|w| w == b"newer"));
        // and the known part still converts
        assert!(crate::task::RegentTaskResult::from_proto(&message).is_ok());
    }

    #[test]
    fn unknown_error_variant_falls_back() {
        let mut message = sample(Err(RegentError::HostBusy("held".to_string()))).to_proto();
        // an error message with no known variant set, as sent by a newer regent-sdk
        message.set_outcome_err(super::RegentError::new());
        let back = crate::task::RegentTaskResult::from_proto(&message).unwrap();
        assert!(matches!(back.error(), Some(RegentError::AnyOtherError(_))));
    }

    #[test]
    fn unknown_remediation_falls_back() {
        let mut action = super::Action::new();
        action.set_remediation(super::Remediation::new());
        let mut actions = super::ListOf_Action::new();
        actions.items_mut().push(action);
        let mut status = ManagedHostStatus::already_compliant().into_proto_value();
        status.set_actions_taken(actions);
        let mut message = sample(Ok(ManagedHostStatus::already_compliant())).to_proto();
        message.set_outcome_ok(status);
        let back = crate::task::RegentTaskResult::from_proto(&message).unwrap();
        let json = serde_json::to_string(back.host_status().unwrap()).unwrap();
        assert!(
            json.contains("unknown remediation from a newer regent-sdk"),
            "{json}"
        );
    }
}
