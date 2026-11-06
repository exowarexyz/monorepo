//! Resumable log subscriptions.

use crate::{
    credential::{client_error_from_connect, Credential},
    proto::transport::ErasedResponseBody,
    ClientError, ObservedSequence, StoreBatch, StoreBatchEntry, StoreClient, StoreKeyPrefix,
};
use bytes::Bytes;
use connectrpc::{client::ServerStream, ConnectError, ErrorCode};
use exoware_proto::log::stream::v1::{SubscribeRequest, SubscribeResponse, SubscribeResponseView};
use futures::future::BoxFuture;
use rand::RngExt as _;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub(crate) type SubscribeStream = ServerStream<ErasedResponseBody, SubscribeResponseView<'static>>;

type OpenFuture = BoxFuture<'static, Result<SubscribeStream, ConnectError>>;

const DEFAULT_OUTAGE_BUDGET: Duration = Duration::from_secs(60);
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(2);

/// Reconnect policy for [StreamSubscription].
///
/// A resuming subscription reconnects after the server closes the stream, the
/// connection resets, or the call fails with `Unavailable`, `Aborted`,
/// `ResourceExhausted`, `Internal`, or `Unknown`. It resubscribes with the
/// same filters from the sequence after the last frame it received, so the
/// caller sees one stream with no gap and no duplicate. Every other error is
/// returned without retrying. That includes authentication and permission
/// failures, invalid filters, and `BATCH_EVICTED`.
///
/// An outage starts when [crate::Stream::subscribe] begins opening the
/// subscription, and again whenever its stream fails or ends. Only a received
/// frame ends an outage. The outage budget bounds the whole outage, including
/// backoff, stalled opens, and the wait for the first frame of a reopened
/// stream. A healthy stream may stay idle indefinitely. When the budget runs
/// out, the last error of the outage is returned, or `DeadlineExceeded` if the
/// outage had none. Backoff doubles from the initial delay up to the maximum, and
/// each delay is drawn uniformly between half and all of that value. It starts
/// over only once a frame advances the cursor, so a reopened stream that fails
/// again right after its opening checkpoint keeps backing off.
///
/// A subscription opened without a positive `since_sequence_number` has no
/// cursor until its first frame arrives. A failure before then is returned,
/// because resubscribing without a cursor could skip batches.
///
/// This policy is separate from [crate::RetryConfig], and
/// [crate::StoreClientBuilder::request_timeout] does not bound subscriptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubscriptionRetryConfig {
    enabled: bool,
    outage_budget: Option<Duration>,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl SubscriptionRetryConfig {
    /// Resume within a 60 second outage budget, backing off from 100 ms up to 2 s.
    pub const fn standard() -> Self {
        Self {
            enabled: true,
            outage_budget: Some(DEFAULT_OUTAGE_BUDGET),
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
        }
    }

    /// Resume until an error that resuming cannot fix, with the standard backoff.
    pub const fn unlimited() -> Self {
        Self {
            outage_budget: None,
            ..Self::standard()
        }
    }

    /// Never resume.
    ///
    /// The subscription is opened once without a time bound. [StreamSubscription::next]
    /// returns `Ok(None)` when the server closes the stream and returns every error.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::standard()
        }
    }

    /// Bounds each outage by `budget`.
    pub const fn with_outage_budget(mut self, budget: Duration) -> Self {
        self.outage_budget = Some(budget);
        self
    }

    pub const fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    pub const fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Whether subscriptions resume automatically.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// The budget for each outage, or `None` when outages are unbounded.
    pub const fn outage_budget(&self) -> Option<Duration> {
        self.outage_budget
    }

    pub(crate) fn backoff(&self, failures: u32) -> Duration {
        // `checked_shl` only rejects shifts of 128 bits or more, which saturate
        // the factor instead. The multiplication is what catches a product too
        // large for a u128, which means the delay has long passed the maximum.
        let max = self.max_backoff.max(self.initial_backoff).as_nanos();
        let factor = 1_u128
            .checked_shl(failures.saturating_sub(1))
            .unwrap_or(u128::MAX);
        let cap = self
            .initial_backoff
            .as_nanos()
            .checked_mul(factor)
            .map_or(max, |delay| delay.min(max));

        // Drawing from the upper half keeps attempts spaced while spreading the
        // reconnects of subscribers that lost the same server.
        let nanos = rand::rng().random_range(cap / 2..=cap);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

impl Default for SubscriptionRetryConfig {
    fn default() -> Self {
        Self::standard()
    }
}

/// Where a reconnect resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cursor {
    /// No frame has arrived and the caller gave no positive starting sequence.
    Unknown,
    /// The next sequence that has not been received.
    Next(u64),
    /// The last representable sequence was received, so nothing can follow it.
    Exhausted,
}

impl Cursor {
    fn after(sequence_number: u64) -> Self {
        sequence_number
            .checked_add(1)
            .map_or(Self::Exhausted, Self::Next)
    }

    const fn accepts(self, sequence_number: u64) -> bool {
        match self {
            Self::Unknown => true,
            Self::Next(next) => sequence_number >= next,
            Self::Exhausted => false,
        }
    }
}

const fn is_resumable(err: &ConnectError) -> bool {
    matches!(
        err.code,
        ErrorCode::Unavailable
            | ErrorCode::Aborted
            | ErrorCode::ResourceExhausted
            | ErrorCode::Internal
            | ErrorCode::Unknown
    )
}

struct Opener {
    client: StoreClient,
    request: SubscribeRequest,
}

impl Opener {
    // The future owns its client and request, so it outlives any `next()` call
    // that happens to poll it.
    fn open(&self, cursor: Cursor) -> OpenFuture {
        let mut request = self.request.clone();
        if let Cursor::Next(since) = cursor {
            request.since_sequence_number = Some(since);
        }
        let client = self.client.clone();
        Box::pin(async move { client.open_subscribe_stream(request).await })
    }
}

enum State {
    // The transport future is `Send` but not `Sync`. The mutex is only ever
    // reached through `get_mut`, so it never locks and only keeps the
    // subscription `Sync`.
    Opening(Mutex<OpenFuture>),
    Open(Box<SubscribeStream>),
    Backoff(Pin<Box<Sleep>>),
    Ended,
}

struct Outage {
    // A stored timer rather than an instant, so the task polling a fresh
    // `next()` future is still woken when the budget runs out.
    deadline: Option<Pin<Box<Sleep>>>,
    last_error: Option<ConnectError>,
}

impl Outage {
    fn start(budget: Option<Duration>) -> Self {
        Self {
            deadline: budget
                .and_then(|budget| Instant::now().checked_add(budget))
                .map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
            last_error: None,
        }
    }

    // Returns the error to report once the budget has run out.
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Option<ConnectError> {
        let deadline = self.deadline.as_mut()?;
        if deadline.as_mut().poll(cx).is_pending() {
            return None;
        }
        Some(self.last_error.take().unwrap_or_else(|| {
            ConnectError::deadline_exceeded(
                "subscription did not receive a frame within its outage budget",
            )
        }))
    }
}

/// Async stream of [StoreBatch] from a log subscription.
///
/// Reconnects according to the client's [SubscriptionRetryConfig]. Dropping a
/// pending [Self::next] future loses no batch, cursor, outage progress, backoff,
/// or in-flight reconnect, so callers may poll a fresh [Self::next] future each
/// time. Dropping the subscription cancels all of its work.
pub struct StreamSubscription {
    opener: Opener,
    config: SubscriptionRetryConfig,
    credential: Credential,
    cursor: Cursor,
    state: State,
    outage: Option<Outage>,
    // Reconnects since the cursor last advanced. A stale opening checkpoint
    // ends an outage without counting as progress, so this outlives outages.
    failures: u32,
    pub(crate) key_prefix: Option<StoreKeyPrefix>,
    pub(crate) observed_sequence: Option<Arc<ObservedSequence>>,
}

impl std::fmt::Debug for StreamSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSubscription").finish_non_exhaustive()
    }
}

impl StreamSubscription {
    /// Opens a subscription, retrying the open only when it can resume from a cursor.
    pub(crate) async fn open(
        client: StoreClient,
        request: SubscribeRequest,
        config: SubscriptionRetryConfig,
    ) -> Result<Self, ClientError> {
        // Sequence zero asks the server for a live subscription, so it is not a cursor.
        let cursor = match request.since_sequence_number {
            Some(since) if since > 0 => Cursor::Next(since),
            _ => Cursor::Unknown,
        };
        let credential = client.credential;
        let opener = Opener { client, request };
        let mut subscription = Self {
            state: State::Opening(Mutex::new(opener.open(cursor))),
            opener,
            config,
            credential,
            cursor,
            outage: config.enabled.then(|| Outage::start(config.outage_budget)),
            failures: 0,
            key_prefix: None,
            observed_sequence: None,
        };
        std::future::poll_fn(|cx| subscription.poll_connected(cx)).await?;
        Ok(subscription)
    }

    /// Pulls the next batch.
    ///
    /// `Ok(None)` means the subscription has ended. A resuming subscription
    /// ends only after returning an error, or after receiving the last
    /// representable sequence. A subscription with a disabled
    /// [SubscriptionRetryConfig] also ends when the server closes the stream.
    pub async fn next(&mut self) -> Result<Option<StoreBatch>, ClientError> {
        std::future::poll_fn(|cx| self.poll_next(cx)).await
    }

    // All progress lives in the subscription, so a `next()` future dropped
    // after one poll loses nothing.
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<StoreBatch>, ClientError>> {
        loop {
            if matches!(self.state, State::Ended) {
                return Poll::Ready(Ok(None));
            }
            if let Err(err) = std::task::ready!(self.poll_connected(cx)) {
                return Poll::Ready(Err(err));
            }
            let State::Open(stream) = &mut self.state else {
                continue;
            };

            // `message` keeps its partial reads in the stream, so a future
            // dropped after one poll loses nothing.
            let message = {
                let message = stream.message();
                std::pin::pin!(message).poll(cx)
            };
            let failure = match message {
                Poll::Pending => return self.pending(cx),
                Poll::Ready(Ok(Some(view))) => match self.receive(view.to_owned_message()) {
                    Ok(Some(batch)) => return Poll::Ready(Ok(Some(batch))),
                    Ok(None) => continue,
                    Err(err) => return Poll::Ready(Err(self.end(err))),
                },
                Poll::Ready(Ok(None)) => match self.cursor {
                    _ if !self.config.enabled => {
                        self.state = State::Ended;
                        return Poll::Ready(Ok(None));
                    }
                    Cursor::Exhausted => {
                        self.state = State::Ended;
                        return Poll::Ready(Ok(None));
                    }
                    Cursor::Unknown => ConnectError::unavailable(
                        "subscription closed before its first frame, so resuming could skip batches",
                    ),
                    Cursor::Next(_) => {
                        self.reconnect(None);
                        continue;
                    }
                },
                Poll::Ready(Err(err)) => err,
            };
            if let Err(err) = self.recover(failure) {
                return Poll::Ready(Err(err));
            }
        }
    }

    // Drives backoff and reopening until a stream is open or the subscription ends.
    fn poll_connected(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ClientError>> {
        loop {
            match &mut self.state {
                State::Open(_) | State::Ended => return Poll::Ready(Ok(())),
                State::Backoff(sleep) => {
                    if sleep.as_mut().poll(cx).is_pending() {
                        return self.pending(cx);
                    }
                    self.state = State::Opening(Mutex::new(self.opener.open(self.cursor)));
                }
                State::Opening(open) => {
                    let open = open.get_mut().unwrap_or_else(PoisonError::into_inner);
                    match open.as_mut().poll(cx) {
                        Poll::Pending => return self.pending(cx),
                        Poll::Ready(Ok(stream)) => self.state = State::Open(Box::new(stream)),
                        Poll::Ready(Err(err)) => self.recover(err)?,
                    }
                }
            }
        }
    }

    // Waits for progress, ending the subscription if the outage budget ran out
    // first. Polling the budget timer here registers its wakeup.
    fn pending<T>(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, ClientError>> {
        match self
            .outage
            .as_mut()
            .and_then(|outage| outage.poll_expired(cx))
        {
            Some(error) => Poll::Ready(Err(self.end_with_connect(error))),
            None => Poll::Pending,
        }
    }

    // Applies a received frame. Empty frames, such as the opening checkpoint,
    // and frames whose entries all fall outside the key prefix still move the
    // cursor without being delivered.
    fn receive(&mut self, frame: SubscribeResponse) -> Result<Option<StoreBatch>, ClientError> {
        self.outage = None;
        let sequence_number = frame.sequence_number;

        // A server that lags behind the cursor can resend batches already delivered.
        if !self.cursor.accepts(sequence_number) {
            return Ok(None);
        }
        self.failures = 0;
        self.cursor = Cursor::after(sequence_number);
        if frame.entries.is_empty() {
            return Ok(None);
        }

        let batch = decode_batch(self.key_prefix.as_ref(), frame)?;
        if let Some(observed) = &self.observed_sequence {
            observed.observe(batch.sequence_number);
        }
        Ok(Some(batch))
    }

    // Schedules a reconnect after `failure`, or ends the subscription when it
    // cannot resume.
    fn recover(&mut self, failure: ConnectError) -> Result<(), ClientError> {
        let resumable =
            self.config.enabled && is_resumable(&failure) && matches!(self.cursor, Cursor::Next(_));
        if !resumable {
            return Err(self.end_with_connect(failure));
        }
        self.reconnect(Some(failure));
        Ok(())
    }

    // Backs off before reopening. A clean end of the stream passes no failure,
    // because it is not an error to report if the outage budget runs out.
    fn reconnect(&mut self, failure: Option<ConnectError>) {
        let outage = self
            .outage
            .get_or_insert_with(|| Outage::start(self.config.outage_budget));
        if failure.is_some() {
            outage.last_error = failure;
        }
        self.failures = self.failures.saturating_add(1);
        let delay = self.config.backoff(self.failures);
        self.state = State::Backoff(Box::pin(tokio::time::sleep(delay)));
    }

    fn end_with_connect(&mut self, err: ConnectError) -> ClientError {
        let err = client_error_from_connect(err, self.credential);
        self.end(err)
    }

    fn end(&mut self, err: ClientError) -> ClientError {
        self.state = State::Ended;
        self.outage = None;
        err
    }
}

fn decode_batch(
    key_prefix: Option<&StoreKeyPrefix>,
    frame: SubscribeResponse,
) -> Result<StoreBatch, ClientError> {
    let mut entries = Vec::with_capacity(frame.entries.len());
    for entry in frame.entries {
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
        sequence_number: frame.sequence_number,
        entries,
    })
}
