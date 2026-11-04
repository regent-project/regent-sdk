//! Runtime used by the generated conversions (`src/proto/conv/*.rs`).

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use protobuf::ProtoStr;

use super::ProtoError;

/// Rust value → owned protobuf value (message or scalar).
pub(crate) trait IntoProtoValue {
    type Out;
    fn into_proto_value(&self) -> Self::Out;
}

/// Protobuf view (message view or scalar) → Rust value.
pub(crate) trait FromProtoValue<'a>: Sized {
    type In;
    fn from_proto_value(value: Self::In) -> Result<Self, ProtoError>;
}

pub(crate) fn required<T>(value: Option<T>, field: &'static str) -> Result<T, ProtoError> {
    value.ok_or(ProtoError::MissingField(field))
}

pub(crate) fn string_from(value: &ProtoStr) -> Result<String, ProtoError> {
    value
        .to_str()
        .map(str::to_string)
        .map_err(|_| ProtoError::InvalidUtf8)
}

pub(crate) fn ip_from(value: &ProtoStr, field: &'static str) -> Result<IpAddr, ProtoError> {
    string_from(value)?
        .parse()
        .map_err(|e: std::net::AddrParseError| ProtoError::InvalidValue {
            field,
            details: e.to_string(),
        })
}

pub(crate) fn narrow<T: TryFrom<S>, S>(value: S, field: &'static str) -> Result<T, ProtoError> {
    T::try_from(value).map_err(|_| ProtoError::OutOfRange(field))
}

#[allow(dead_code)] // used once a mirrored type holds a Duration
pub(crate) fn duration_to_proto(value: &Duration) -> super::RustDuration {
    let mut out = super::RustDuration::new();
    out.set_seconds(value.as_secs());
    out.set_nanos(value.subsec_nanos());
    out
}

#[allow(dead_code)]
pub(crate) fn duration_from_proto(
    value: protobuf::View<'_, super::RustDuration>,
    field: &'static str,
) -> Result<Duration, ProtoError> {
    if value.nanos() >= 1_000_000_000 {
        return Err(ProtoError::OutOfRange(field));
    }
    Ok(Duration::new(value.seconds(), value.nanos()))
}

pub(crate) fn timestamp_to_proto(value: &DateTime<Utc>) -> super::Timestamp {
    let mut out = super::Timestamp::new();
    out.set_seconds(value.timestamp());
    out.set_nanos(value.timestamp_subsec_nanos());
    out
}

pub(crate) fn timestamp_from_proto(
    value: protobuf::View<'_, super::Timestamp>,
    field: &'static str,
) -> Result<DateTime<Utc>, ProtoError> {
    DateTime::from_timestamp(value.seconds(), value.nanos()).ok_or(ProtoError::OutOfRange(field))
}

/// Sample values of a type, for the generated round-trip tests.
#[cfg(test)]
pub(crate) trait ProtoSample: Sized {
    fn proto_samples() -> Vec<Self>;
}

#[cfg(test)]
pub(crate) fn first_sample<T: ProtoSample>() -> T {
    T::proto_samples()
        .into_iter()
        .next()
        .expect("every type has at least one sample")
}

/// Rust → protobuf → bytes → protobuf → Rust gives back the same value (compared
/// through its serde form).
#[cfg(test)]
pub(crate) fn assert_roundtrip<T, M>(value: &T)
where
    T: IntoProtoValue<Out = M>
        + for<'a> FromProtoValue<'a, In = protobuf::View<'a, M>>
        + serde::Serialize,
    M: protobuf::Message,
{
    use protobuf::{AsView, Parse, Serialize};

    let bytes = value.into_proto_value().serialize().expect("serialize");
    let parsed = M::parse(&bytes).expect("parse");
    let back = T::from_proto_value(parsed.as_view()).expect("convert back");
    assert_eq!(
        serde_json::to_value(value).expect("serde"),
        serde_json::to_value(&back).expect("serde"),
        "protobuf round trip changed the value"
    );
}

/// Same as [`assert_roundtrip`], compared through `Debug`, for types without serde.
#[cfg(test)]
pub(crate) fn assert_roundtrip_debug<T, M>(value: &T)
where
    T: IntoProtoValue<Out = M>
        + for<'a> FromProtoValue<'a, In = protobuf::View<'a, M>>
        + std::fmt::Debug,
    M: protobuf::Message,
{
    use protobuf::{AsView, Parse, Serialize};

    let bytes = value.into_proto_value().serialize().expect("serialize");
    let parsed = M::parse(&bytes).expect("parse");
    let back = T::from_proto_value(parsed.as_view()).expect("convert back");
    assert_eq!(
        format!("{value:?}"),
        format!("{back:?}"),
        "protobuf round trip changed the value"
    );
}
