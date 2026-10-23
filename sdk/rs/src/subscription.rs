//! Resumable log subscriptions.

use crate::credential::{client_error_from_connect, Credential};
use crate::proto::transport::ErasedResponseBody;
use crate::{
    proto_decode_connect_error, ClientError, ObservedSequence, StoreBatch, StoreBatchEntry,
    StoreClient, StoreKeyPrefix,
};
use bytes::Bytes;
use connectrpc::client::ServerStream;
use connectrpc::{ConnectError, ErrorCode};
use exoware_proto::log::stream::v1::{SubscribeRequest, SubscribeResponseView};
use rand::RngExt as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

pub(crate) type SubscribeStream = ServerStream<ErasedResponseBody, SubscribeResponseView<'static>>;

const DEFAULT_OUTAGE_BUDGET: Duration = Duration::from_secs(60);
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(2);

/// Reconnect policy for [`StreamSubscription`].
///
/// A resuming subscription reconnects after a clean close, a reset, or a transient error. It
/// resubscribes with the same filters from the sequence after the last frame it received, so
/// the caller sees one stream with no gap and no duplicate. Authentication, permission, invalid
/// filter, and `BATCH_EVICTED` failures are returned without retrying.
///
/// An outage starts when a subscription fails, or when
/// [`crate::Stream::subscribe`] starts opening one. Any frame received within the budget ends
/// it. The outage budget bounds each outage, including backoff, stalled opens, and the wait for
/// the first frame of a reopened stream. An exhausted budget returns `DeadlineExceeded` naming
/// the last failure. Backoff doubles from the initial delay up to the maximum, and each delay is drawn
/// uniformly between half and all of that value.
///
/// A subscription opened without a cursor cannot resume until it receives a frame. If it fails
/// before then, the error is returned, because resubscribing without a cursor could skip batches.
/// A nonzero `since_sequence_number` provides a cursor, so opening it is retried.
///
/// This policy is separate from [`crate::RetryConfig`], and
/// [`crate::StoreClientBuilder::request_timeout`] does not bound subscriptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubscriptionRetryConfig {
    enabled: bool,
    outage_budget: Option<Duration>,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl SubscriptionRetryConfig {
    /// Resume within a 60 second outage budget, backing off from 100 ms up to 2 s.
    pub fn standard() -> Self {
        Self {
            enabled: true,
            outage_budget: Some(DEFAULT_OUTAGE_BUDGET),
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
        }
    }

    /// Resume until an error that retrying cannot fix, with the standard backoff.
    pub fn unlimited() -> Self {
        Self {
            outage_budget: None,
            ..Self::standard()
        }
    }

    /// Never resume.
    ///
    /// [`StreamSubscription::next`] returns `Ok(None)` when the server closes the stream and
    /// returns every error. Opening is a single attempt without a time bound.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::standard()
        }
    }

    /// Bound each outage by `budget`. Has no effect on a disabled policy.
    pub fn with_outage_budget(mut self, budget: Duration) -> Self {
        self.outage_budget = Some(budget);
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    pub(crate) fn backoff_delay(&self, failures: u32) -> Duration {
        let exponent = failures.saturating_sub(1).min(20);
        let capped = self
            .initial_backoff
            .saturating_mul(1 << exponent)
            .min(self.max_backoff);

        // Drawing from the upper half keeps some spacing while spreading reconnects after a
        // shared outage such as a rolling restart.
        let maximum = capped.as_nanos();
        let nanos = rand::rng().random_range(maximum / 2..=maximum);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

impl Default for SubscriptionRetryConfig {
    fn default() -> Self {
        Self::standard()
    }
}

/// Async stream of [`StoreBatch`] from a log subscription.
///
/// Reconnects according to the client's [`SubscriptionRetryConfig`]. Dropping a pending
/// [`Self::next`] call does not lose a batch, the resume cursor, outage progress, or an
/// in-flight reconnect, so callers may poll a fresh [`Self::next`] future each time.
pub struct StreamSubscription {
    stream: Option<SubscribeStream>,
    resume: Resume,
    pub(crate) key_prefix: Option<StoreKeyPrefix>,
    credential: Credential,
    pub(crate) observed_sequence: Option<Arc<ObservedSequence>>,
}

impl std::fmt::Debug for StreamSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSubscription").finish_non_exhaustive()
    }
}

impl StreamSubscription {
    /// Open a subscription, retrying the open only when `config` resumes and `request` carries
    /// a cursor.
    pub(crate) async fn open(
        client: StoreClient,
        request: SubscribeRequest,
        config: SubscriptionRetryConfig,
    ) -> Result<Self, ClientError> {
        let credential = client.credential;

        // Sequence zero is treated as a live subscription by the server, so it gives no cursor.
        let cursor = match request.since_sequence_number {
            Some(since) if since > 0 => Cursor::Next(since),
            _ => Cursor::Unknown,
        };

        // The outage clock starts with the call so a stalled open or a missing first frame is
        // bounded even though nothing has failed yet. A disabled policy has no budget to
        // spend, so its single attempt is unbounded.
        let mut resume = Resume {
            opener: Opener { client, request },
            config,
            cursor,
            outage: config
                .enabled
                .then(|| Outage::new(Instant::now(), config.outage_budget)),
            opening: Mutex::new(None),
            ended: false,
        };
        let stream = resume
            .reconnect()
            .await
            .map_err(|err| client_error_from_connect(err, credential))?;
        Ok(Self {
            stream: Some(stream),
            resume,
            key_prefix: None,
            credential,
            observed_sequence: None,
        })
    }

    /// Pull the next batch.
    ///
    /// `Ok(None)` means the subscription has ended. A resuming subscription ends only after
    /// returning an error. A subscription with a disabled [`SubscriptionRetryConfig`] also ends
    /// when the server closes the stream cleanly.
    pub async fn next(&mut self) -> Result<Option<StoreBatch>, ClientError> {
        // Every await below leaves the cursor, outage, pending backoff, in-flight open, and
        // open stream stored in self. A frame is applied without awaiting after it arrives, so
        // dropping this future never loses one.
        let credential = self.credential;
        let resume = &mut self.resume;
        loop {
            if resume.ended {
                return Ok(None);
            }

            if self.stream.is_none() {
                match resume.reconnect().await {
                    Ok(stream) => self.stream = Some(stream),
                    Err(err) => {
                        resume.ended = true;
                        return Err(client_error_from_connect(err, credential));
                    }
                }
            }
            let Some(stream) = self.stream.as_mut() else {
                continue;
            };

            // A reopened stream must deliver a frame within the outage budget, so a server that
            // accepts the request but never responds cannot stall the subscription.
            let Some(message) = within_budget(resume.outage.as_mut(), stream.message()).await
            else {
                self.stream = None;
                resume.ended = true;
                return Err(client_error_from_connect(resume.exhausted(), credential));
            };

            let failure = match message {
                Ok(Some(view)) => {
                    resume.outage = None;
                    let owned = view.to_owned_message();
                    let sequence_number = owned.sequence_number;

                    // A lagging server can replay batches that were already delivered.
                    if !resume.cursor.accepts(sequence_number) {
                        continue;
                    }

                    // Empty frames still move the cursor. The server uses them to hand out a
                    // checkpoint when a subscription opens.
                    let batch = if owned.entries.is_empty() {
                        None
                    } else {
                        match decode_batch(self.key_prefix.as_ref(), owned) {
                            Ok(batch) => Some(batch),
                            Err(err) => {
                                self.stream = None;
                                resume.ended = true;
                                return Err(err);
                            }
                        }
                    };
                    resume.cursor = Cursor::after(sequence_number);
                    let Some(batch) = batch else {
                        continue;
                    };
                    if let Some(observed) = &self.observed_sequence {
                        observed.observe(batch.sequence_number);
                    }
                    return Ok(Some(batch));
                }
                Ok(None) if !resume.config.enabled => {
                    self.stream = None;
                    resume.ended = true;
                    return Ok(None);
                }
                Ok(None) if resume.cursor == Cursor::Unknown => ConnectError::unavailable(
                    "subscription closed before its first frame, so resuming could skip batches",
                ),
                Ok(None) => ConnectError::unavailable("subscription closed by the server"),
                Err(err) => err,
            };
            self.stream = None;
            if let Err(err) = resume.schedule_retry(failure) {
                resume.ended = true;
                return Err(client_error_from_connect(err, credential));
            }
        }
    }
}

fn decode_batch(
    key_prefix: Option<&StoreKeyPrefix>,
    owned: exoware_proto::log::stream::v1::SubscribeResponse,
) -> Result<StoreBatch, ClientError> {
    let mut entries = Vec::with_capacity(owned.entries.len());
    for entry in owned.entries {
        let key = Bytes::from(entry.key);
        let key = match key_prefix {
            Some(prefix) => prefix.decode_key(&key)?,
            None => key,
        };
        entries.push(StoreBatchEntry {
            key,
            value: entry.value,
        });
    }
    Ok(StoreBatch {
        sequence_number: owned.sequence_number,
        entries,
    })
}

type OpenFuture = Pin<Box<dyn Future<Output = Result<SubscribeStream, ConnectError>> + Send>>;

struct Opener {
    client: StoreClient,
    request: SubscribeRequest,
}

impl Opener {
    // The future owns its client and request so it can outlive the `next()` call that
    // started it.
    fn open(&self, cursor: Cursor) -> OpenFuture {
        let mut request = self.request.clone();
        if let Cursor::Next(since) = cursor {
            request.since_sequence_number = Some(since);
        }
        let client = self.client.clone();
        Box::pin(async move { client.open_subscribe_stream(request).await })
    }
}

/// Where a reconnect must start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cursor {
    /// No frame has arrived and the caller gave no nonzero starting sequence.
    Unknown,
    /// The next sequence the caller has not seen.
    Next(u64),
    /// The last representable sequence was delivered, so no later batch can exist.
    Exhausted,
}

impl Cursor {
    fn after(sequence_number: u64) -> Self {
        sequence_number
            .checked_add(1)
            .map_or(Self::Exhausted, Self::Next)
    }

    fn accepts(self, sequence_number: u64) -> bool {
        match self {
            Self::Unknown => true,
            Self::Next(next) => sequence_number >= next,
            Self::Exhausted => false,
        }
    }
}

struct Outage {
    // The budget deadline is a stored timer rather than an instant so a caller that polls
    // fresh `next()` futures is still woken when it elapses.
    deadline: Option<Pin<Box<Sleep>>>,
    failures: u32,
    retry: Option<Pin<Box<Sleep>>>,
    last_error: Option<ConnectError>,
}

impl Outage {
    fn new(started: Instant, budget: Option<Duration>) -> Self {
        Self {
            deadline: budget
                .and_then(|budget| started.checked_add(budget))
                .map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
            failures: 0,
            retry: None,
            last_error: None,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline.as_ref().map(|sleep| sleep.deadline())
    }
}

// Progress observed after the budget elapsed cannot revive the outage. The clock decides,
// because the stored timer can still read as pending when the task's cooperative budget is
// exhausted or the timer driver has not run yet. `None` means the budget elapsed.
async fn within_budget<F: Future>(outage: Option<&mut Outage>, future: F) -> Option<F::Output> {
    let Some(deadline) = outage.and_then(|outage| outage.deadline.as_mut()) else {
        return Some(future.await);
    };
    let output = tokio::select! {
        biased;
        _ = deadline.as_mut() => return None,
        output = future => output,
    };
    (Instant::now() < deadline.deadline()).then_some(output)
}

struct Resume {
    opener: Opener,
    config: SubscriptionRetryConfig,
    cursor: Cursor,
    outage: Option<Outage>,
    // The transport future is not `Sync`. The mutex only lends it out through `get_mut`,
    // which keeps `StreamSubscription` shareable without ever locking.
    opening: Mutex<Option<OpenFuture>>,
    ended: bool,
}

impl Resume {
    /// Open a stream, retrying transient failures while a cursor exists.
    ///
    /// The backoff timer, the budget timer, and the in-flight open live in `self`, so a caller
    /// that drops this future and calls again continues them instead of starting over.
    async fn reconnect(&mut self) -> Result<SubscribeStream, ConnectError> {
        loop {
            if let Some(retry) = self
                .outage
                .as_mut()
                .and_then(|outage| outage.retry.as_mut())
            {
                retry.await;
            }

            // Clearing the backoff only after it elapses keeps a canceled caller from
            // reconnecting early on its next call.
            if let Some(outage) = self.outage.as_mut() {
                outage.retry = None;
            }

            // A backoff clamped to the deadline leaves no time for another attempt.
            if self
                .outage
                .as_ref()
                .and_then(Outage::deadline)
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Err(self.exhausted());
            }

            let opening = self
                .opening
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner);
            let open = opening.get_or_insert_with(|| self.opener.open(self.cursor));
            let Some(result) = within_budget(self.outage.as_mut(), open).await else {
                return Err(self.exhausted());
            };
            *opening = None;
            match result {
                Ok(stream) => return Ok(stream),
                Err(err) => self.schedule_retry(err)?,
            }
        }
    }

    /// Record a failure and schedule the next attempt, or return the failure if it is final.
    fn schedule_retry(&mut self, error: ConnectError) -> Result<(), ConnectError> {
        if !self.config.enabled || !matches!(self.cursor, Cursor::Next(_)) || !is_resumable(&error)
        {
            return Err(error);
        }

        let now = Instant::now();
        let budget = self.config.outage_budget;
        let outage = self.outage.get_or_insert_with(|| Outage::new(now, budget));
        outage.failures = outage.failures.saturating_add(1);
        let retry_at = now + self.config.backoff_delay(outage.failures);
        let retry_at = outage
            .deadline()
            .map_or(retry_at, |deadline| retry_at.min(deadline));
        outage.retry = Some(Box::pin(tokio::time::sleep_until(retry_at)));
        outage.last_error = Some(error);
        Ok(())
    }

    // An abandoned open is released with the outage so a dead subscription holds no request.
    fn exhausted(&mut self) -> ConnectError {
        *self
            .opening
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let last_error = self.outage.take().and_then(|outage| outage.last_error);
        let message = match last_error {
            Some(err) => format!("subscription outage budget exhausted after {err}"),
            None => "subscription did not deliver a frame within its outage budget".to_owned(),
        };
        ConnectError::deadline_exceeded(message)
    }
}

/// Classify failures that a reconnect from the cursor may clear.
///
/// `Internal` and `Unknown` match the read retry set because proxies report transient faults
/// that way. A failure that repeats before any frame arrives is bounded by the outage budget.
fn is_resumable(error: &ConnectError) -> bool {
    if is_batch_evicted(error) {
        return false;
    }
    matches!(
        error.code,
        ErrorCode::Aborted
            | ErrorCode::Unavailable
            | ErrorCode::ResourceExhausted
            | ErrorCode::Unknown
            | ErrorCode::Internal
            | ErrorCode::DeadlineExceeded
    )
}

fn is_batch_evicted(error: &ConnectError) -> bool {
    proto_decode_connect_error(error).is_ok_and(|decoded| {
        decoded
            .error_info
            .is_some_and(|info| info.domain == "log.stream" && info.reason == "BATCH_EVICTED")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Poll;

    // The timer only fires when the runtime's driver runs, which a blocked thread prevents,
    // so the clock has to decide whether a ready output arrived within the budget.
    #[tokio::test]
    async fn an_output_observed_after_the_deadline_is_discarded_when_the_timer_has_not_fired() {
        let mut outage = Outage::new(Instant::now(), Some(Duration::from_millis(50)));
        let mut polls = 0;
        let result = std::future::poll_fn(|cx| {
            polls += 1;
            let first = polls == 1;
            let output =
                std::future::poll_fn(move |_| if first { Poll::Pending } else { Poll::Ready(7) });
            let bounded = within_budget(Some(&mut outage), output);
            tokio::pin!(bounded);
            if first {
                assert!(bounded.poll(cx).is_pending());
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            std::thread::sleep(Duration::from_millis(100));
            Poll::Ready(bounded.poll(cx))
        })
        .await;

        assert_eq!(result, Poll::Ready(None));
    }
}
