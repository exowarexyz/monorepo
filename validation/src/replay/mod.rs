use std::{path::PathBuf, time::Duration};

use anyhow::{ensure, Context};
use exoware_sdk::{PrefixedStoreClient, StoreWriteBatch};
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
    let mut request = StoreWriteBatch::new();
    request.reserve(batch.rows.len());
    for row in batch.rows {
        request.push(client, &row.key, row.value)?;
    }
    Ok(request.commit(client.client()).await?)
}

#[cfg(test)]
mod tests;
