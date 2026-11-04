//! gRPC `Reporting` service (feature `grpc`), on tonic.
//!
//! - Client: [`reporting::reporting_client::ReportingClient`].
//! - Server: implement [`reporting::reporting_server::Reporting`] and serve
//!   [`reporting::reporting_server::ReportingServer`].
//!
//! Messages are Google protobuf messages (see [`crate::proto`]), carried by
//! [`ProtobufCodec`]; [`tonic`] is re-exported so callers use the same version
//! (enable its TLS features, e.g. `tls-ring`, in your own `Cargo.toml`).

use std::marker::PhantomData;

use bytes::{Buf, BufMut};
use tonic::Status;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

pub use tonic;

/// Generated client and server stubs of `regent.v1.Reporting`.
pub mod reporting {
    include!(concat!(env!("OUT_DIR"), "/regent.v1.Reporting.rs"));
}

/// tonic codec for Google protobuf messages.
pub struct ProtobufCodec<E, D>(PhantomData<fn() -> (E, D)>);

impl<E, D> Default for ProtobufCodec<E, D> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<E, D> Codec for ProtobufCodec<E, D>
where
    E: protobuf::Message + 'static,
    D: protobuf::Message + 'static,
{
    type Encode = E;
    type Decode = D;
    type Encoder = ProtobufEncoder<E>;
    type Decoder = ProtobufDecoder<D>;

    fn encoder(&mut self) -> Self::Encoder {
        ProtobufEncoder(PhantomData)
    }

    fn decoder(&mut self) -> Self::Decoder {
        ProtobufDecoder(PhantomData)
    }
}

/// Encoder half of [`ProtobufCodec`].
pub struct ProtobufEncoder<E>(PhantomData<fn() -> E>);

impl<E: protobuf::Message> Encoder for ProtobufEncoder<E> {
    type Item = E;
    type Error = Status;

    fn encode(&mut self, item: E, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        let bytes = item
            .serialize()
            .map_err(|e| Status::internal(format!("cannot serialize message: {e:?}")))?;
        dst.put_slice(&bytes);
        Ok(())
    }
}

/// Decoder half of [`ProtobufCodec`].
pub struct ProtobufDecoder<D>(PhantomData<fn() -> D>);

impl<D: protobuf::Message> Decoder for ProtobufDecoder<D> {
    type Item = D;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<D>, Status> {
        let bytes = src.copy_to_bytes(src.remaining());
        D::parse(&bytes)
            .map(Some)
            .map_err(|e| Status::invalid_argument(format!("cannot parse message: {e:?}")))
    }
}
