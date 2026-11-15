//! End-to-end test of the `Reporting` gRPC service (feature `grpc`): an
//! in-process server and client exchange a RegentTaskResult and a live view.
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
    live: Arc<Mutex<Vec<proto::LiveUpdate>>>,
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

    async fn report_live(
        &self,
        request: Request<tonic::Streaming<proto::ReportLiveRequest>>,
    ) -> Result<Response<proto::ReportLiveResponse>, Status> {
        let mut stream = request.into_inner();
        let mut accepted = 0;
        while let Some(batch) = stream.message().await? {
            let mut live = self.live.lock().unwrap();
            for update in batch.updates() {
                live.push(update.to_owned());
                accepted += 1;
            }
        }
        let mut response = proto::ReportLiveResponse::new();
        response.set_accepted(accepted);
        Ok(Response::new(response))
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

async fn serve() -> (Collector, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let collector = Collector::default();
    let server = tonic::transport::Server::builder()
        .add_service(ReportingServer::new(collector.clone()))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));
    tokio::spawn(server);
    (collector, address)
}

#[tokio::test]
async fn report_outcome_reaches_the_collector() {
    let (collector, address) = serve().await;

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

#[tokio::test]
async fn report_live_streams_batches_and_run_log_travels_with_the_outcome() {
    use regent_sdk::hosts::live::{LiveEvent, LiveUpdate, OutputStream, RunLog};
    let (collector, address) = serve().await;
    let update = |seq| LiveUpdate {
        run_id: "key-1".into(),
        host_id: "web-01".into(),
        job: Job::Reach,
        seq,
        at: Utc::now(),
        event: LiveEvent::Output {
            exec_id: 1,
            stream: OutputStream::Stdout,
            line: format!("line {seq}"),
        },
    };
    let batches: Vec<proto::ReportLiveRequest> = (0..3)
        .map(|batch| {
            let mut request = proto::ReportLiveRequest::new();
            for seq in 1..=2 {
                request
                    .updates_mut()
                    .push(update(batch * 2 + seq).to_proto());
            }
            request
        })
        .collect();
    let mut client = ReportingClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let response = client
        .report_live(tokio_stream::iter(batches))
        .await
        .unwrap();
    assert_eq!(response.get_ref().accepted(), 6);
    {
        let live = collector.live.lock().unwrap();
        let seqs: Vec<u64> = live
            .iter()
            .map(|u| LiveUpdate::from_proto(u).unwrap().seq)
            .collect();
        assert_eq!(seqs, (1..=6).collect::<Vec<_>>());
    }

    let mut log = RunLog::new(0);
    log.push(update(1));
    let started_at = Utc::now();
    let result = RegentTaskResult::from(
        "key-1".to_string(),
        "web-01".to_string(),
        Job::Reach,
        started_at,
        started_at,
        Ok(ManagedHostStatus::already_compliant()),
    );
    let mut request = proto::ReportOutcomeRequest::new();
    request.set_result(result.to_proto());
    request.set_run_log(log.to_proto());
    client.report_outcome(request).await.unwrap();
    let received = collector.received.lock().unwrap();
    let back = RunLog::from_proto(&received[0].run_log().to_owned()).unwrap();
    assert_eq!(back.updates().len(), 1);
}
