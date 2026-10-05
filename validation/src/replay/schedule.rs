use std::{future::Future, task::Poll, time::Duration};

use anyhow::{ensure, Context};
use serde::Serialize;
use tokio::{sync::mpsc, task::JoinSet, time::Instant};

use super::Args;
use crate::capture::Batch;

pub(super) struct Schedule {
    pub repeat_period_ns: u64,
    pub last_offset_ns: u64,
    pub event_count: u64,
}

#[derive(Debug)]
pub(super) struct PreparedBatch {
    pub pass: u64,
    pub event: usize,
    pub batch: Batch,
}

#[derive(Debug, Serialize)]
pub(super) struct Request {
    pub pass: u64,
    pub event: usize,
    pub rows: usize,
    pub logical_bytes: u64,
    pub due_ns: u64,
    pub dispatched_ns: u64,
    pub completed_ns: u64,
    pub sequence_number: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    pub stop_reason: String,
    pub error: Option<String>,
    pub elapsed_ns: u64,
    pub issued: u64,
    pub succeeded: u64,
    pub failed: u64,
}

struct AdmittedBatch {
    prepared: PreparedBatch,
    rows: usize,
    logical_bytes: u64,
}

impl From<PreparedBatch> for AdmittedBatch {
    fn from(prepared: PreparedBatch) -> Self {
        let rows = prepared.batch.rows.len();
        let logical_bytes = prepared
            .batch
            .rows
            .iter()
            .map(|row| (row.key.len() + row.value.len()) as u64)
            .sum();
        Self {
            prepared,
            rows,
            logical_bytes,
        }
    }
}

struct Completion {
    request: Request,
    stop_reason: &'static str,
}

pub(super) async fn run<F, Fut>(
    args: &Args,
    schedule: Schedule,
    mut input: mpsc::Receiver<anyhow::Result<PreparedBatch>>,
    send: F,
    mut records: Option<mpsc::Sender<Request>>,
) -> anyhow::Result<Report>
where
    F: Fn(Batch) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = anyhow::Result<u64>> + Send + 'static,
{
    args.validate()?;
    ensure!(schedule.event_count > 0, "capture must contain events");
    let last_pass = args
        .start_pass
        .checked_add(args.passes - 1)
        .context("pass range overflows")?;
    ensure!(
        schedule.last_offset_ns < schedule.repeat_period_ns,
        "last event must precede the repeat period"
    );
    let last_due = due(
        args.passes - 1,
        schedule.repeat_period_ns,
        schedule.last_offset_ns,
        args.speed,
    )?;
    let started = Instant::now();
    let lag = Duration::from_millis(args.max_lag_ms);
    ensure!(
        started
            .checked_add(last_due)
            .and_then(|time| time.checked_add(lag))
            .and_then(|time| time.checked_add(args.request_timeout()))
            .is_some(),
        "replay schedule exceeds the monotonic clock range"
    );
    let cutoff = args
        .duration_secs
        .map(|seconds| {
            started
                .checked_add(Duration::from_secs(seconds))
                .context("duration exceeds the monotonic clock range")
        })
        .transpose()?;

    let mut pending = JoinSet::new();
    let mut report = Report {
        stop_reason: "complete".into(),
        error: None,
        elapsed_ns: 0,
        issued: 0,
        succeeded: 0,
        failed: 0,
    };
    let mut next = None;
    let mut previous: Option<(u64, usize, u64)> = None;
    loop {
        if records.as_ref().is_some_and(mpsc::Sender::is_closed) {
            stop(
                &mut report,
                "report_failed",
                "request report writer closed".into(),
            );
            records = None;
            break;
        }
        while let Some(result) = pending.try_join_next() {
            collect(&mut report, result, &mut records).await;
        }
        if report.error.is_some() {
            break;
        }
        let now = Instant::now();
        if cutoff.is_some_and(|cutoff| now >= cutoff) {
            report.stop_reason = "duration".into();
            break;
        }
        if let Some((prepared, offset)) = next.take() {
            let prepared: PreparedBatch = prepared;
            let scheduled = started + offset;
            let full = pending.len() >= args.concurrency;
            if now > scheduled + lag || (full && now >= scheduled + lag) {
                stop(
                    &mut report,
                    "overloaded",
                    lag_error(args, prepared.pass, prepared.event),
                );
                break;
            }
            if !full && now >= scheduled {
                let admitted = AdmittedBatch::from(prepared);
                let send = send.clone();
                let timeout = args.request_timeout();
                if cutoff.is_some_and(|cutoff| Instant::now() >= cutoff) {
                    report.stop_reason = "duration".into();
                    break;
                }
                if records.as_ref().is_some_and(mpsc::Sender::is_closed) {
                    stop(
                        &mut report,
                        "report_failed",
                        "request report writer closed".into(),
                    );
                    records = None;
                    break;
                }
                pending.spawn(execute(admitted, offset, started, lag, timeout, send));
                report.issued += 1;
                if previous.is_some_and(|(pass, event, _)| {
                    pass == last_pass && event as u64 == schedule.event_count - 1
                }) {
                    break;
                }
                continue;
            }
            next = Some((prepared, offset));
            let wake = if full { scheduled + lag } else { scheduled };
            let wake = cutoff.map_or(wake, |cutoff| wake.min(cutoff));
            tokio::select! {
                biased;
                _ = report_closed(&records) => {
                    stop(&mut report, "report_failed", "request report writer closed".into());
                    records = None;
                    break;
                }
                result = pending.join_next(), if !pending.is_empty() => {
                    collect(&mut report, result.expect("pending set is nonempty"), &mut records).await;
                }
                _ = tokio::time::sleep_until(wake) => {}
            }
            continue;
        }

        // The next offset is not available until preparation finishes. Its pass's
        // last offset bounds this wait without moving the original replay clock.
        let waiting_pass = previous.map_or(args.start_pass, |(pass, event, _)| {
            if event as u64 == schedule.event_count - 1 && pass < last_pass {
                pass + 1
            } else {
                pass
            }
        });
        let input_deadline = started
            + due(
                waiting_pass - args.start_pass,
                schedule.repeat_period_ns,
                schedule.last_offset_ns,
                args.speed,
            )?
            + lag;
        let wake = cutoff.map_or(input_deadline, |cutoff| input_deadline.min(cutoff));
        tokio::select! {
            biased;
            _ = report_closed(&records) => {
                stop(&mut report, "report_failed", "request report writer closed".into());
                records = None;
                break;
            }
            result = pending.join_next(), if !pending.is_empty() => {
                collect(&mut report, result.expect("pending set is nonempty"), &mut records).await;
            }
            item = input.recv() => {
                match item {
                    Some(Ok(prepared)) => {
                        if let Err(error) = validate_next(&prepared, previous, args, &schedule, last_pass) {
                            stop(&mut report, "preparation_failed", error.to_string());
                            break;
                        }
                        let offset = due(
                            prepared.pass - args.start_pass,
                            schedule.repeat_period_ns,
                            prepared.batch.offset_ns,
                            args.speed,
                        )?;
                        previous = Some((prepared.pass, prepared.event, prepared.batch.offset_ns));
                        next = Some((prepared, offset));
                    }
                    Some(Err(error)) => {
                        stop(&mut report, "preparation_failed", format!("{error:#}"));
                        break;
                    }
                    None => {
                        stop(&mut report, "preparation_failed", "prepared input ended before the final event".into());
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(wake) => {
                if cutoff.is_some_and(|cutoff| Instant::now() >= cutoff) {
                    report.stop_reason = "duration".into();
                } else {
                    stop(&mut report, "overloaded", "batch preparation exceeded the schedule lag limit".into());
                }
                break;
            }
        }
    }

    // Dropping the receiver releases blocked preparation workers before RPC drain.
    drop(input);
    drop(next);
    while let Some(result) = pending.join_next().await {
        collect(&mut report, result, &mut records).await;
    }
    report.elapsed_ns = nanos(Instant::now() - started);
    Ok(report)
}

async fn report_closed(records: &Option<mpsc::Sender<Request>>) {
    match records {
        Some(sender) => sender.closed().await,
        None => std::future::pending().await,
    }
}

fn validate_next(
    prepared: &PreparedBatch,
    previous: Option<(u64, usize, u64)>,
    args: &Args,
    schedule: &Schedule,
    last_pass: u64,
) -> anyhow::Result<()> {
    ensure!(
        prepared.pass <= last_pass,
        "prepared pass exceeds requested range"
    );
    ensure!(
        prepared.batch.offset_ns <= schedule.last_offset_ns,
        "prepared offset exceeds capture schedule"
    );
    ensure!(
        (prepared.event as u64) < schedule.event_count,
        "prepared event exceeds capture range"
    );
    if prepared.event as u64 == schedule.event_count - 1 {
        ensure!(
            prepared.batch.offset_ns == schedule.last_offset_ns,
            "final prepared offset differs from capture schedule"
        );
    }
    match previous {
        None => ensure!(
            prepared.pass == args.start_pass && prepared.event == 0,
            "prepared input does not start at the first requested event"
        ),
        Some((pass, event, offset)) => {
            let same_pass = prepared.pass == pass
                && event.checked_add(1) == Some(prepared.event)
                && prepared.batch.offset_ns >= offset;
            let next_pass = pass.checked_add(1) == Some(prepared.pass)
                && prepared.event == 0
                && event as u64 == schedule.event_count - 1;
            ensure!(same_pass || next_pass, "prepared input is out of order");
        }
    }
    Ok(())
}

async fn execute<F, Fut>(
    admitted: AdmittedBatch,
    offset: Duration,
    started: Instant,
    lag: Duration,
    timeout: Duration,
    send: F,
) -> Completion
where
    F: Fn(Batch) -> Fut,
    Fut: Future<Output = anyhow::Result<u64>>,
{
    let AdmittedBatch {
        prepared,
        rows,
        logical_bytes,
    } = admitted;

    // A spawned task can start long after admission. Measure at its first poll so
    // executor contention cannot hide behind a timely spawn timestamp.
    let dispatched = Instant::now();
    let deadline = dispatched + timeout;
    let mut request = Request {
        pass: prepared.pass,
        event: prepared.event,
        rows,
        logical_bytes,
        due_ns: nanos(offset),
        dispatched_ns: nanos(dispatched - started),
        completed_ns: 0,
        sequence_number: None,
        error: None,
    };
    let mut stop_reason = "request_failed";
    if dispatched > started + offset + lag {
        request.error = Some("task start exceeded the schedule lag limit".into());
        request.completed_ns = nanos(Instant::now() - started);
        stop_reason = "overloaded";
    } else {
        // Constructing the SDK future can itself do synchronous work. Both that
        // work and every future poll consume the same absolute timeout budget.
        let outcome = async move {
            if Instant::now() >= deadline {
                anyhow::bail!("request timed out");
            }
            let future = send(prepared.batch);
            tokio::pin!(future);
            let timer = tokio::time::sleep_until(deadline);
            tokio::pin!(timer);
            std::future::poll_fn(|cx| {
                if Instant::now() >= deadline {
                    return Poll::Ready(Err(anyhow::anyhow!("request timed out")));
                }
                let outcome = future.as_mut().poll(cx);
                if Instant::now() >= deadline {
                    return Poll::Ready(Err(anyhow::anyhow!("request timed out")));
                }
                match outcome {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => match timer.as_mut().poll(cx) {
                        Poll::Ready(()) => Poll::Ready(Err(anyhow::anyhow!("request timed out"))),
                        Poll::Pending => Poll::Pending,
                    },
                }
            })
            .await
        }
        .await;
        let completed = Instant::now();
        request.completed_ns = nanos(completed - started);
        if completed >= deadline {
            request.error = Some("request timed out".into());
        } else {
            match outcome {
                Ok(sequence) => request.sequence_number = Some(sequence),
                Err(error) => request.error = Some(format!("{error:#}")),
            }
        }
    }
    Completion {
        request,
        stop_reason,
    }
}

async fn collect(
    report: &mut Report,
    result: Result<Completion, tokio::task::JoinError>,
    records: &mut Option<mpsc::Sender<Request>>,
) {
    match result {
        Ok(completion) => {
            if let Some(error) = &completion.request.error {
                report.failed += 1;
                stop(report, completion.stop_reason, error.clone());
            } else {
                report.succeeded += 1;
            }
            if let Some(sender) = records {
                if sender.send(completion.request).await.is_err() {
                    stop(
                        report,
                        "report_failed",
                        "request report writer closed".into(),
                    );
                    *records = None;
                }
            }
        }
        Err(error) => {
            report.failed += 1;
            stop(report, "task_failed", error.to_string());
        }
    }
}

fn stop(report: &mut Report, reason: &str, error: String) {
    if report.error.is_none() {
        report.stop_reason = reason.into();
        report.error = Some(error);
    }
}

fn lag_error(args: &Args, pass: u64, event: usize) -> String {
    format!(
        "schedule lag exceeded {} ms at pass {pass} event {event}",
        args.max_lag_ms
    )
}

fn due(iteration: u64, period_ns: u64, offset_ns: u64, speed: f64) -> anyhow::Result<Duration> {
    let ns = u128::from(iteration) * u128::from(period_ns) + u128::from(offset_ns);
    let scaled = ns as f64 / speed;
    ensure!(
        scaled.is_finite() && scaled < u64::MAX as f64,
        "schedule exceeds nanosecond report range"
    );
    Ok(Duration::from_nanos(scaled as u64))
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use bytes::Bytes;

    use super::*;
    use crate::{capture::Row, client::RequestCompression};

    fn args() -> Args {
        Args {
            capture: "unused".into(),
            url: "http://localhost:10000".into(),
            seed: 0,
            start_pass: 3,
            passes: 2,
            speed: 2.0,
            concurrency: 2,
            buffer_batches: 2,
            max_lag_ms: 1000,
            request_timeout_ms: 1000,
            duration_secs: None,
            request_compression: RequestCompression::None,
            output: None,
        }
    }

    fn batch(pass: u64, event: usize, offset_ns: u64) -> PreparedBatch {
        PreparedBatch {
            pass,
            event,
            batch: Batch {
                offset_ns,
                rows: vec![Row {
                    family: 0,
                    key: Bytes::from(vec![(pass * 2 + event as u64 + 1) as u8]),
                    value: Bytes::from_static(b"value"),
                }],
            },
        }
    }

    fn fixture() -> (Schedule, mpsc::Receiver<anyhow::Result<PreparedBatch>>) {
        let schedule = Schedule {
            repeat_period_ns: 20_000_000,
            last_offset_ns: 10_000_000,
            event_count: 2,
        };
        let (sender, receiver) = mpsc::channel(4);
        for pass in 3..5 {
            for event in 0..2 {
                sender
                    .try_send(Ok(batch(pass, event, event as u64 * 10_000_000)))
                    .unwrap();
            }
        }
        (schedule, receiver)
    }

    fn single(args: &mut Args) -> (Schedule, mpsc::Receiver<anyhow::Result<PreparedBatch>>) {
        args.passes = 1;
        let (sender, receiver) = mpsc::channel(1);
        sender.try_send(Ok(batch(args.start_pass, 0, 0))).unwrap();
        (
            Schedule {
                repeat_period_ns: 1,
                last_offset_ns: 0,
                event_count: 1,
            },
            receiver,
        )
    }

    async fn recorded<F, Fut>(
        args: &Args,
        schedule: Schedule,
        input: mpsc::Receiver<anyhow::Result<PreparedBatch>>,
        send: F,
    ) -> (Report, Vec<Request>)
    where
        F: Fn(Batch) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = anyhow::Result<u64>> + Send + 'static,
    {
        let (sender, mut receiver) = mpsc::channel(1);
        let collector = tokio::spawn(async move {
            let mut requests = Vec::new();
            while let Some(request) = receiver.recv().await {
                requests.push(request);
            }
            requests
        });
        let report = run(args, schedule, input, send, Some(sender))
            .await
            .unwrap();
        (report, collector.await.unwrap())
    }

    #[tokio::test]
    async fn absolute_passes_share_one_schedule_and_keep_concurrency_bounded() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let (schedule, input) = fixture();
        let (report, mut requests) = recorded(&args(), schedule, input, {
            let active = active.clone();
            let maximum = maximum.clone();
            move |batch| {
                let active = active.clone();
                let maximum = maximum.clone();
                async move {
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(count, Ordering::SeqCst);
                    let delay = if batch.rows[0].key[0] == 7 { 120 } else { 20 };
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(batch.rows[0].key[0] as u64)
                }
            }
        })
        .await;
        assert!(report.error.is_none());
        assert_eq!((report.issued, report.succeeded, report.failed), (4, 4, 0));
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_ne!(requests[0].event, 0);
        requests.sort_by_key(|request| (request.pass, request.event));
        assert!(requests[2].dispatched_ns < requests[0].completed_ns);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.due_ns)
                .collect::<Vec<_>>(),
            [0, 5_000_000, 10_000_000, 15_000_000]
        );
        assert_eq!(
            requests
                .iter()
                .map(|request| request.sequence_number.unwrap())
                .collect::<Vec<_>>(),
            [7, 8, 9, 10]
        );
        assert!(requests
            .iter()
            .all(|request| request.completed_ns >= request.dispatched_ns));
    }

    #[tokio::test]
    async fn failure_stops_issuance_without_retrying() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut args = args();
        args.concurrency = 1;
        let (schedule, input) = fixture();
        let (report, requests) = recorded(&args, schedule, input, {
            let calls = calls.clone();
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { anyhow::bail!("rejected") }
            }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(requests.len(), 1);
        assert_eq!((report.issued, report.succeeded, report.failed), (1, 0, 1));
        assert_eq!(report.stop_reason, "request_failed");
        assert_eq!(report.error.as_deref(), Some("rejected"));
    }

    #[tokio::test]
    async fn overload_stops_issuance_but_drains_requests() {
        let mut args = args();
        args.concurrency = 1;
        args.max_lag_ms = 100;
        let (schedule, input) = fixture();
        let (report, requests) = recorded(&args, schedule, input, |_| async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            Ok(42)
        })
        .await;
        assert_eq!(report.stop_reason, "overloaded");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].sequence_number, Some(42));
    }

    #[tokio::test]
    async fn pending_request_has_a_terminal_timeout() {
        let mut args = args();
        args.request_timeout_ms = 50;
        let (schedule, input) = single(&mut args);
        let (report, requests) = recorded(&args, schedule, input, |_| std::future::pending()).await;
        assert_eq!(requests.len(), 1);
        assert_eq!(report.error.as_deref(), Some("request timed out"));
    }

    #[tokio::test]
    async fn duration_stops_issuance_and_preserves_inflight_outcome() {
        let mut args = args();
        args.passes = 1;
        args.speed = 1.0;
        args.duration_secs = Some(1);
        args.request_timeout_ms = 3000;
        let schedule = Schedule {
            repeat_period_ns: 3_000_000_000,
            last_offset_ns: 2_000_000_000,
            event_count: 2,
        };
        let (sender, input) = mpsc::channel(2);
        sender.try_send(Ok(batch(3, 0, 0))).unwrap();
        sender.try_send(Ok(batch(3, 1, 2_000_000_000))).unwrap();
        drop(sender);
        let (report, requests) = recorded(&args, schedule, input, |_| async {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            Ok(42)
        })
        .await;
        assert_eq!(report.stop_reason, "duration");
        assert!(report.error.is_none());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].sequence_number, Some(42));
        assert!(requests[0].completed_ns >= 1_000_000_000);
    }

    #[tokio::test]
    async fn delayed_task_start_records_actual_dispatch_and_skips_send() {
        let started = Instant::now();
        let calls = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(execute(
            batch(3, 0, 0).into(),
            Duration::ZERO,
            started,
            Duration::from_millis(50),
            Duration::from_secs(1),
            {
                let calls = calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(42) }
                }
            },
        ));
        // The current-thread executor cannot poll the spawned task during this block.
        std::thread::sleep(Duration::from_millis(100));
        let completion = task.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(completion.stop_reason, "overloaded");
        assert!(completion.request.dispatched_ns >= 100_000_000);
        assert!(completion.request.error.unwrap().contains("task start"));
    }

    #[tokio::test]
    async fn nonyielding_success_after_deadline_is_a_timeout() {
        let mut args = args();
        args.request_timeout_ms = 50;
        let (schedule, input) = single(&mut args);
        let (report, requests) = recorded(&args, schedule, input, |_| async {
            std::thread::sleep(Duration::from_millis(100));
            Ok(42)
        })
        .await;
        assert_eq!(report.error.as_deref(), Some("request timed out"));
        assert_eq!(requests[0].sequence_number, None);
        assert_eq!(report.succeeded, 0);
    }

    #[tokio::test]
    async fn synchronous_send_construction_consumes_timeout_before_first_future_poll() {
        let mut args = args();
        args.request_timeout_ms = 50;
        let polls = Arc::new(AtomicUsize::new(0));
        let (schedule, input) = single(&mut args);
        let (report, requests) = recorded(&args, schedule, input, {
            let polls = polls.clone();
            move |_| {
                std::thread::sleep(Duration::from_millis(100));
                let polls = polls.clone();
                async move {
                    polls.fetch_add(1, Ordering::SeqCst);
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(report.error.as_deref(), Some("request timed out"));
        assert_eq!(requests[0].sequence_number, None);
    }

    #[tokio::test]
    async fn every_repoll_checks_deadline_before_polling_send() {
        let started = Instant::now();
        let polls = Arc::new(AtomicUsize::new(0));
        let completion = execute(
            batch(3, 0, 0).into(),
            Duration::ZERO,
            started,
            Duration::from_secs(1),
            Duration::from_millis(50),
            {
                let polls = polls.clone();
                move |_| {
                    let polls = polls.clone();
                    std::future::poll_fn(move |cx| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        let waker = cx.waker().clone();
                        tokio::spawn(async move {
                            std::thread::sleep(Duration::from_millis(100));
                            waker.wake();
                        });
                        Poll::Pending
                    })
                }
            },
        )
        .await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            completion.request.error.as_deref(),
            Some("request timed out")
        );
    }

    #[tokio::test]
    async fn stalled_preparation_has_a_terminal_lag_failure() {
        let mut args = args();
        args.passes = 1;
        args.max_lag_ms = 50;
        let schedule = Schedule {
            repeat_period_ns: 1,
            last_offset_ns: 0,
            event_count: 1,
        };
        let (sender, input) = mpsc::channel(1);
        let report = run(
            &args,
            schedule,
            input,
            |_| async { panic!("must not send") },
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.issued, 0);
        assert_eq!(report.stop_reason, "overloaded");
        assert!(report.error.unwrap().contains("preparation"));
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn late_preparation_does_not_reset_due_time() {
        let mut args = args();
        args.passes = 1;
        args.speed = 1.0;
        args.max_lag_ms = 50;
        let schedule = Schedule {
            repeat_period_ns: 2_000_000_000,
            last_offset_ns: 1_000_000_000,
            event_count: 2,
        };
        let (sender, input) = mpsc::channel(1);
        let producer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            sender.send(Ok(batch(3, 0, 0))).await.unwrap();
        });
        let report = run(
            &args,
            schedule,
            input,
            |_| async { panic!("must not send") },
            None,
        )
        .await
        .unwrap();
        producer.await.unwrap();
        assert_eq!(report.issued, 0);
        assert_eq!(report.stop_reason, "overloaded");
    }

    #[tokio::test]
    async fn preparation_failure_drains_already_admitted_requests() {
        let mut args = args();
        args.passes = 1;
        let schedule = Schedule {
            repeat_period_ns: 1,
            last_offset_ns: 0,
            event_count: 2,
        };
        let (sender, input) = mpsc::channel(2);
        sender.try_send(Ok(batch(3, 0, 0))).unwrap();
        sender
            .try_send(Err(anyhow::anyhow!("read failed")))
            .unwrap();
        drop(sender);
        let (report, requests) = recorded(&args, schedule, input, |_| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(42)
        })
        .await;
        assert_eq!(report.stop_reason, "preparation_failed");
        assert_eq!(report.error.as_deref(), Some("read failed"));
        assert_eq!(report.succeeded, 1);
        assert_eq!(requests[0].sequence_number, Some(42));
    }

    #[tokio::test]
    async fn records_stream_before_input_closes_and_summary_retains_only_counts() {
        let mut args = args();
        args.passes = 1;
        args.max_lag_ms = 10_000;
        let schedule = Schedule {
            repeat_period_ns: 1,
            last_offset_ns: 0,
            event_count: 1000,
        };
        let (sender, input) = mpsc::channel(1);
        let (records, mut receiver) = mpsc::channel(1);
        let runner = tokio::spawn(async move {
            run(&args, schedule, input, |_| async { Ok(42) }, Some(records))
                .await
                .unwrap()
        });
        for event in 0..1000 {
            sender.send(Ok(batch(3, event, 0))).await.unwrap();
            let request = receiver.recv().await.unwrap();
            assert_eq!(request.event, event);
        }
        drop(sender);
        let report = runner.await.unwrap();
        assert_eq!(
            (report.issued, report.succeeded, report.failed),
            (1000, 1000, 0)
        );
        assert_eq!(receiver.recv().await.map(|request| request.event), None);
        assert!(serde_json::to_value(report)
            .unwrap()
            .get("requests")
            .is_none());
    }

    #[tokio::test]
    async fn closed_report_writer_prevents_admission() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let mut args = args();
        args.concurrency = 1;
        let (schedule, input) = fixture();
        let report = run(&args, schedule, input, |_| async { Ok(42) }, Some(sender))
            .await
            .unwrap();
        assert_eq!(report.stop_reason, "report_failed");
        assert_eq!((report.issued, report.succeeded, report.failed), (0, 0, 0));
    }

    #[tokio::test]
    async fn report_failure_after_accepting_record_wakes_waiter_and_drains() {
        for waiting_for_input in [false, true] {
            let mut args = args();
            args.passes = 1;
            args.speed = 1.0;
            args.concurrency = 2;
            let schedule = Schedule {
                repeat_period_ns: 120_000_000_000,
                last_offset_ns: 60_000_000_000,
                event_count: 3,
            };
            let (input_sender, input) = mpsc::channel(3);
            input_sender.try_send(Ok(batch(3, 0, 0))).unwrap();
            input_sender.try_send(Ok(batch(3, 1, 0))).unwrap();
            if !waiting_for_input {
                input_sender
                    .try_send(Ok(batch(3, 2, 60_000_000_000)))
                    .unwrap();
            }
            let (sender, mut receiver) = mpsc::channel::<Request>(1);
            let (release, delayed) = tokio::sync::oneshot::channel();
            let delayed = Arc::new(std::sync::Mutex::new(Some(delayed)));
            let calls = Arc::new(AtomicUsize::new(0));
            let run = tokio::spawn({
                let calls = calls.clone();
                async move {
                    super::run(
                        &args,
                        schedule,
                        input,
                        move |_| {
                            let index = calls.fetch_add(1, Ordering::SeqCst);
                            let delayed = delayed.clone();
                            async move {
                                if index == 1 {
                                    let delayed = delayed.lock().unwrap().take().unwrap();
                                    delayed.await.unwrap();
                                }
                                Ok(42)
                            }
                        },
                        Some(sender),
                    )
                    .await
                    .unwrap()
                }
            });
            receiver.recv().await.unwrap();
            drop(receiver);
            tokio::time::timeout(Duration::from_secs(2), input_sender.closed())
                .await
                .expect("writer failure must wake the scheduler before the next due time");
            assert!(!run.is_finished());
            release.send(()).unwrap();
            let report = run.await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(report.stop_reason, "report_failed");
            assert_eq!((report.issued, report.succeeded, report.failed), (2, 2, 0));
        }
    }

    #[tokio::test]
    async fn empty_or_out_of_order_input_is_preparation_failure() {
        for item in [None, Some(batch(4, 0, 0)), Some(batch(3, 1, 0))] {
            let (sender, input) = mpsc::channel(1);
            if let Some(item) = item {
                sender.try_send(Ok(item)).unwrap();
            }
            drop(sender);
            let schedule = Schedule {
                repeat_period_ns: 1,
                last_offset_ns: 0,
                event_count: 1,
            };
            let report = run(
                &args(),
                schedule,
                input,
                |_| async { panic!("must not send") },
                None,
            )
            .await
            .unwrap();
            assert_eq!(report.stop_reason, "preparation_failed");
            assert_eq!(report.issued, 0);
        }
    }

    #[test]
    fn schedule_rejects_unrepresentable_time() {
        assert_eq!(due(1, 100, 20, 2.0).unwrap(), Duration::from_nanos(60));
        assert!(due(u64::MAX, u64::MAX, 0, 1.0).is_err());
        assert!(due(0, 1, 1, f64::MIN_POSITIVE).is_err());
    }
}
