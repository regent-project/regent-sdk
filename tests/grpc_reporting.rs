//! End-to-end test of the `Reporting` gRPC service (feature `grpc`): an
//! in-process server and client exchange a RegentTaskResult.
#![cfg(feature = "grpc")]

use std::sync::{Arc, Mutex};

use chrono::Utc;
use regent_sdk::proto;
use regent_sdk::proto::grpc::reporting::reporting_client::ReportingClient;
use regent_sdk::proto::grpc::reporting::reporting_server::{Reporting, ReportingServer};
use regent_sdk::proto::grpc::tonic::{self, Request, Response, Status};
use regent_sdk::state::compliance::ManagedHostStatus;
use regent_sdk::task::{Job, RegentTaskResult};

#[derive(Default, Clone)]
struct Collector {
    received: Arc<Mutex<Vec<proto::ReportOutcomeRequest>>>,
}

#[tonic::async_trait]
impl Reporting for Collector {
    async fn report_outcome(
        &self,
        request: Request<proto::ReportOutcomeRequest>,
    ) -> Result<Response<proto::ReportOutcomeResponse>, Status> {
        self.received.lock().unwrap().push(request.into_inner());
        Ok(Response::new(proto::ReportOutcomeResponse::new()))
    }

    async fn enroll(
        &self,
        _request: Request<proto::EnrollRequest>,
    ) -> Result<Response<proto::EnrollResponse>, Status> {
        Err(Status::unimplemented("no built-in CA in this test"))
    }

    async fn renew_certificate(
        &self,
        _request: Request<proto::RenewCertificateRequest>,
    ) -> Result<Response<proto::RenewCertificateResponse>, Status> {
        Err(Status::unimplemented("no built-in CA in this test"))
    }
}

#[tokio::test]
async fn report_outcome_reaches_the_collector() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let collector = Collector::default();
    let server = tonic::transport::Server::builder()
        .add_service(ReportingServer::new(collector.clone()))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));
    tokio::spawn(server);

    let started_at = Utc::now();
    let result = RegentTaskResult::from(
        "key-1".to_string(),
        "web-01".to_string(),
        Job::Assess,
        started_at,
        started_at,
        Ok(ManagedHostStatus::already_compliant()),
    );
    let mut reporter = proto::ReporterInfo::new();
    reporter.set_agent("test");
    let mut request = proto::ReportOutcomeRequest::new();
    request.set_result(result.to_proto());
    request.set_reporter(reporter);

    let mut client = ReportingClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    client.report_outcome(request).await.unwrap();

    let received = collector.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    let back = RegentTaskResult::from_proto(&received[0].result().to_owned()).unwrap();
    assert_eq!(back.idempotency_key(), "key-1");
    assert_eq!(back.host_id(), "web-01");
    assert!(back.host_status().unwrap().is_already_compliant());
    assert_eq!(received[0].reporter().agent(), "test");
}
