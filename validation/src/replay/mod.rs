use std::{path::PathBuf, time::Duration};

use anyhow::{ensure, Context};
use buffa::Message;
use exoware_sdk::{common::Entry, ingest::PutRequest, PrefixedStoreClient, StoreWriteBatch};
use serde::Serialize;

use crate::{
    capture::{Batch, FileGenerator},
    client::{build_client, ClientConfig, RequestCompression},
};

mod output;
mod schedule;

/// Replays complete captured batches against an isolated dataset.
#[derive(clap::Args, Clone, Debug, Serialize)]
pub struct Args {
    #[arg(long)]
    pub capture: PathBuf,
    #[arg(long, default_value = "http://localhost:10000")]
    pub url: String,
    #[arg(long, default_value_t = 0)]
    pub seed: u64,
    #[arg(long, default_value_t = 0)]
    pub start_pass: u64,
    #[arg(long, default_value_t = 1)]
    pub passes: u64,
    #[arg(long, default_value_t = 1.0)]
    pub speed: f64,
    #[arg(long, default_value_t = 16)]
    pub concurrency: usize,
    /// Maximum prepared batches waiting for admission.
    #[arg(long, default_value_t = 16)]
    pub buffer_batches: usize,
    #[arg(long, default_value_t = 1000)]
    pub max_lag_ms: u64,
    #[arg(long, default_value_t = 30000)]
    pub request_timeout_ms: u64,
    /// Stops issuing new requests after this many seconds and drains issued requests.
    #[arg(long)]
    pub duration_secs: Option<u64>,
    #[arg(long, value_enum, default_value_t = RequestCompression::None)]
    pub request_compression: RequestCompression,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    args.validate()?;
    let path = args.capture.clone();
    let seed = args.seed;
    let generator = tokio::task::spawn_blocking(move || FileGenerator::open(path, seed)).await??;
    generator.validate_passes(args.start_pass, args.passes)?;
    let schedule = schedule::Schedule {
        repeat_period_ns: generator.repeat_period_ns(),
        last_offset_ns: generator.last_offset_ns(),
        event_count: generator.event_count(),
    };
    let output = if let Some(path) = args.output.clone() {
        let header = output::Header {
            capture_sha256: generator.capture_sha256().to_owned(),
            source: generator.source().clone(),
            settings: args.clone(),
        };
        Some(tokio::task::spawn_blocking(move || output::Writer::create(path, header)).await??)
    } else {
        None
    };
    let client = build_client(
        &ClientConfig::new(&args.url, 1)?.with_request_compression(args.request_compression),
    )?;
    let (input, preparation) = prepare(generator, &args).await?;
    let (records, writer) = match output {
        Some(mut output) => {
            let (sender, mut receiver) = tokio::sync::mpsc::channel(args.concurrency);
            let writer = tokio::task::spawn_blocking(move || {
                while let Some(request) = receiver.blocking_recv() {
                    output.record(&request)?;
                }
                anyhow::Ok(output)
            });
            (Some(sender), Some(writer))
        }
        None => (None, None),
    };
    let result = schedule::run(
        &args,
        schedule,
        input,
        move |batch| {
            let client = client.clone();
            async move { issue(&client, batch).await }
        },
        records,
    )
    .await;
    let prepared = preparation.await;
    let output = match writer {
        Some(writer) => Some(writer.await??),
        None => None,
    };
    let report = result?;
    prepared?;
    println!(
        "{} requests issued, {} succeeded, {} failed, stopped {}",
        report.issued, report.succeeded, report.failed, report.stop_reason,
    );
    let error = report.error.clone();
    if let Some(output) = output {
        tokio::task::spawn_blocking(move || output.finish(&report)).await??;
    }
    if let Some(error) = error {
        anyhow::bail!(error);
    }
    Ok(())
}

async fn prepare(
    mut generator: FileGenerator,
    args: &Args,
) -> anyhow::Result<(
    tokio::sync::mpsc::Receiver<anyhow::Result<schedule::PreparedBatch>>,
    tokio::task::JoinHandle<()>,
)> {
    let (sender, receiver) = tokio::sync::mpsc::channel(args.buffer_batches);
    let (ready, primed) = tokio::sync::oneshot::channel();
    let start_pass = args.start_pass;
    let passes = args.passes;
    let capacity = args.buffer_batches;
    let worker = tokio::task::spawn_blocking(move || {
        let mut ready = Some(ready);
        let mut buffered = 0;
        let result = (|| -> anyhow::Result<()> {
            for iteration in 0..passes {
                if sender.is_closed() {
                    return Ok(());
                }
                if iteration != 0 {
                    generator.rewind()?;
                }
                let pass = start_pass + iteration;
                let mut event = 0;
                while !sender.is_closed() {
                    let Some(batch) = generator.next_batch(pass)? else {
                        break;
                    };
                    if sender
                        .blocking_send(Ok(schedule::PreparedBatch { pass, event, batch }))
                        .is_err()
                    {
                        return Ok(());
                    }
                    event += 1;
                    if ready.is_some() {
                        buffered += 1;
                    }
                    if buffered == capacity {
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(());
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        if let Err(error) = result {
            let _ = sender.blocking_send(Err(error));
        }
    });
    primed.await.context("capture preparation stopped")?;
    Ok((receiver, worker))
}

impl Args {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.passes > 0, "--passes must be positive");
        ensure!(
            self.speed.is_finite() && self.speed > 0.0,
            "--speed must be finite and positive"
        );
        ensure!(self.concurrency > 0, "--concurrency must be positive");
        ensure!(self.buffer_batches > 0, "--buffer-batches must be positive");
        ensure!(self.max_lag_ms > 0, "--max-lag-ms must be positive");
        ensure!(
            self.request_timeout_ms > 0,
            "--request-timeout-ms must be positive"
        );
        ensure!(
            self.duration_secs != Some(0),
            "--duration-secs must be positive"
        );
        ensure!(
            !matches!(self.request_compression, RequestCompression::Gzip),
            "replay supports none or zstd request compression"
        );
        Ok(())
    }

    fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

async fn issue(client: &PrefixedStoreClient, batch: Batch) -> anyhow::Result<u64> {
    // The unary SDK encoder panics on oversized messages. Its fallible size check keeps
    // an unrepresentable captured batch on the ordinary request-error path.
    PutRequest {
        kvs: batch
            .rows
            .iter()
            .map(|row| Entry {
                key: row.key.to_vec(),
                value: row.value.clone(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
    .try_encoded_len()?;

    let mut request = StoreWriteBatch::new();
    request.reserve(batch.rows.len());
    for row in batch.rows {
        request.push(client, &row.key, row.value)?;
    }
    Ok(request.commit(client.client()).await?)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use bytes::Bytes;
    use connectrpc::{ConnectRpcService, RequestContext, ServiceRequest};
    use exoware_sdk::ingest::{PutRequest, PutResponse, Service, ServiceServer};

    use super::*;
    use crate::capture::Row;

    type Received = Arc<Mutex<Vec<Vec<(Vec<u8>, Vec<u8>)>>>>;

    #[derive(Clone)]
    struct Harness(Received);

    #[allow(refining_impl_trait)]
    impl Service for Harness {
        async fn put(
            &self,
            _ctx: RequestContext,
            request: ServiceRequest<'_, PutRequest>,
        ) -> connectrpc::ServiceResult<PutResponse> {
            let request = request.to_owned_message();
            self.0.lock().unwrap().push(
                request
                    .kvs
                    .into_iter()
                    .map(|row| (row.key, row.value.to_vec()))
                    .collect(),
            );
            connectrpc::Response::ok(PutResponse {
                sequence_number: 91,
                ..Default::default()
            })
        }
    }

    #[tokio::test]
    async fn oversized_unary_batch_returns_an_error() {
        let client = build_client(
            &ClientConfig::new("http://127.0.0.1:9", 1)
                .unwrap()
                .with_request_compression(RequestCompression::None),
        )
        .unwrap();
        let value = Bytes::from(vec![0; 1024 * 1024]);
        let batch = Batch {
            offset_ns: 0,
            rows: (0u64..2048)
                .map(|index| Row {
                    family: 1,
                    key: Bytes::copy_from_slice(&index.to_be_bytes()),
                    value: value.clone(),
                })
                .collect(),
        };
        let result = issue(&client, batch).await;
        assert!(result.unwrap_err().to_string().contains("2 GiB"));
    }

    #[tokio::test]
    async fn sdk_issues_one_rpc_with_original_physical_keys_and_row_order() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let service = ConnectRpcService::new(ServiceServer::new(Harness(received.clone())));
        let app = Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = build_client(
            &ClientConfig::new(url, 1)
                .unwrap()
                .with_request_compression(RequestCompression::None),
        )
        .unwrap();
        let batch = Batch {
            offset_ns: 0,
            rows: vec![
                Row {
                    family: 1,
                    key: Bytes::from_static(&[3, 0, 9]),
                    value: Bytes::from_static(b"row"),
                },
                Row {
                    family: 2,
                    key: Bytes::from_static(&[0, 3, 5]),
                    value: Bytes::new(),
                },
            ],
        };
        assert_eq!(issue(&client, batch).await.unwrap(), 91);
        assert_eq!(
            *received.lock().unwrap(),
            vec![vec![
                (vec![3, 0, 9], b"row".to_vec()),
                (vec![0, 3, 5], vec![])
            ]]
        );
        server.abort();
    }

    #[tokio::test]
    async fn incremental_replay_preserves_duplicates_and_streams_complete_reports() {
        use crate::capture::{Bundle, Domain, Endian, Family, Offset, Patch, Profile, Target};
        use std::collections::BTreeMap;

        for compression in [RequestCompression::None, RequestCompression::Zstd] {
            let received = Arc::new(Mutex::new(Vec::new()));
            let service = ConnectRpcService::new(ServiceServer::new(Harness(received.clone())));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, Router::new().fallback_service(service))
                    .await
                    .unwrap();
            });
            let temp = tempfile::tempdir().unwrap();
            let capture = temp.path().join("capture");
            let output = temp.path().join("report.json");
            let row = Row {
                family: 1,
                key: Bytes::from_static(&[0xaa, 1]),
                value: Bytes::from(vec![42; 1024]),
            };
            Bundle {
                profile: Profile {
                    version: 1,
                    domains: BTreeMap::from([("id".into(), Domain::Numeric { width: 1 })]),
                    families: vec![Family {
                        id: 1,
                        name: "rows".into(),
                        key_prefix_hex: "aa".into(),
                        fresh_key: 0,
                        patches: vec![Patch {
                            target: Target::Key,
                            offset: Offset::Start(1),
                            domain: "id".into(),
                            endian: Endian::Big,
                        }],
                    }],
                },
                source: BTreeMap::from([("producer".into(), "duplicate-test".into())]),
                repeat_period_ns: 1_000_000,
                batches: vec![Batch {
                    offset_ns: 0,
                    rows: vec![row.clone(), row],
                }],
            }
            .write(&capture)
            .unwrap();
            let args = Args {
                capture,
                url,
                seed: 7,
                start_pass: 0,
                passes: 20,
                speed: 1.0,
                concurrency: 2,
                buffer_batches: 3,
                max_lag_ms: 1000,
                request_timeout_ms: 1000,
                duration_secs: None,
                request_compression: compression,
                output: Some(output.clone()),
            };
            run(args.clone()).await.unwrap();
            for occupied in [&output, &args.capture.join("rows.bin")] {
                let original = std::fs::read(occupied).unwrap();
                let mut rejected = args.clone();
                rejected.output = Some(occupied.clone());
                let error = run(rejected).await.unwrap_err();
                assert!(error.to_string().contains("creating report"));
                assert_eq!(std::fs::read(occupied).unwrap(), original);
                assert_eq!(received.lock().unwrap().len(), 20);
            }
            let records = received.lock().unwrap();
            assert_eq!(records.len(), 20);
            for rows in records.iter() {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0], rows[1]);
                assert_eq!(rows[0].1, vec![42; 1024]);
            }
            let mut keys: Vec<_> = records.iter().map(|rows| rows[0].0.clone()).collect();
            keys.sort();
            assert_eq!(keys, (1..=20).map(|id| vec![0xaa, id]).collect::<Vec<_>>());
            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
            assert_eq!(report["format_version"], 2);
            assert_eq!(report["run"]["issued"], 20);
            assert_eq!(report["run"]["succeeded"], 20);
            assert_eq!(report["run"]["failed"], 0);
            assert_eq!(report["run"]["requests"].as_array().unwrap().len(), 20);
            assert_eq!(report["source"]["producer"], "duplicate-test");
            server.abort();
        }
    }
}
