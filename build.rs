//! Code generation for the optional `proto` and `grpc` features.
//!
//! - `proto`: compiles `proto/regent/v1/*.proto` with Google's protobuf
//!   code generator. Requires `protoc` of the exact version matching the
//!   `protobuf` crate (see Cargo.toml), on `PATH` or through `PROTOC`.
//! - `grpc`: generates the `Reporting` service client/server stubs (tonic,
//!   with a codec for Google protobuf messages; no prost).

fn main() {
    #[cfg(feature = "proto")]
    proto();
    #[cfg(feature = "grpc")]
    grpc();
}

#[cfg(feature = "proto")]
fn proto() {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-env-changed=PROTOC");
    if let Err(details) = protobuf_codegen::CodeGen::new()
        .inputs(["regent/v1/model.proto", "regent/v1/reporting.proto"])
        .include("proto")
        .generate_and_compile()
    {
        panic!("protobuf code generation failed: {details}");
    }
}

#[cfg(feature = "grpc")]
fn grpc() {
    use tonic_build::manual::{Builder, Method, Service};

    let method = |name: &str, route: &str, input: &str, output: &str| {
        Method::builder()
            .name(name)
            .route_name(route)
            .input_type(format!("crate::proto::{input}"))
            .output_type(format!("crate::proto::{output}"))
            .codec_path("crate::proto::grpc::ProtobufCodec")
            .build()
    };
    let reporting = Service::builder()
        .name("Reporting")
        .package("regent.v1")
        .comment("Outcome reporting, see proto/regent/v1/reporting.proto.")
        .method(method(
            "report_outcome",
            "ReportOutcome",
            "ReportOutcomeRequest",
            "ReportOutcomeResponse",
        ))
        .method(method(
            "enroll",
            "Enroll",
            "EnrollRequest",
            "EnrollResponse",
        ))
        .method(method(
            "renew_certificate",
            "RenewCertificate",
            "RenewCertificateRequest",
            "RenewCertificateResponse",
        ))
        .build();
    Builder::new().compile(&[reporting]);
}
