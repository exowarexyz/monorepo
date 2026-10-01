use std::sync::Arc;

use bytes::Bytes;
use connectrpc::ConnectError;

use super::parser::{
    decode_entry_with_budget, field_size, Field, PutEntryCursor, PutParseError, UnknownBudget,
};
use super::zstd::{frame_decoder_memory_bytes, validate_window_header, ArenaDecoder};
use super::{
    ByteLease, DecodeBuffers, EntryRanges, PutChunk, PutEncoding, PutError, PutLimits, RequestLease,
};

const OUTPUT_QUANTUM: usize = 64 * 1024;

enum Codec {
    Identity,
    Header {
        bytes: [u8; 18],
        len: usize,
        validated: Option<(usize, usize)>,
    },
    Zstd(ArenaDecoder),
}

pub(super) struct WireBatch {
    pub(super) frames: std::collections::VecDeque<Bytes>,
    pub(super) _bytes: ByteLease,
}

// A detached job owns all allocations ahead of the guards that account for them.
pub struct DecodeState {
    codec: Codec,
    pending: Bytes,
    pending_frames: Option<WireBatch>,
    offset: usize,
    arena: Vec<u8>,
    ranges: Vec<EntryRanges>,
    parsed: usize,
    retry_at: usize,
    #[cfg(test)]
    parser_attempts: usize,
    total: usize,
    count: usize,
    budget: UnknownBudget,
    outer_budget: UnknownBudget,
    entry_error: Option<ConnectError>,
    inner_error: Option<ConnectError>,
    rejection: Option<PutError>,
    fatal: Option<ConnectError>,
    eof: bool,
    limits: PutLimits,
    buffers: DecodeBuffers,
    arena_bytes: Option<ByteLease>,
    range_bytes: Option<ByteLease>,
    codec_bytes: Option<ByteLease>,
    _transport: Arc<ByteLease>,
    request: Arc<RequestLease>,
}

pub(super) enum DecodeStep {
    /// Sizing alone does not authorize publication.
    Bound(usize),
    Batch(PutChunk),
    Wire,
    Eof,
}

// Executors return the owned output intact so only the input can restore it.
pub struct DecodeOutput {
    pub(super) result: Result<DecodeStep, PutError>,
    pub(super) state: DecodeState,
}

impl DecodeState {
    fn suppressed(&self) -> bool {
        self.rejection.is_some()
            || self.entry_error.is_some()
            || self.inner_error.is_some()
            || self.count > self.limits.ingest.max_entries
    }

    pub(super) fn belongs_to(&self, request: &Arc<RequestLease>) -> bool {
        Arc::ptr_eq(&self.request, request)
    }

    pub(super) fn new(
        encoding: PutEncoding,
        limits: PutLimits,
        transport: Arc<ByteLease>,
        request: Arc<RequestLease>,
    ) -> Self {
        Self {
            codec: match encoding {
                PutEncoding::Identity => Codec::Identity,
                PutEncoding::Zstd => Codec::Header {
                    bytes: [0; 18],
                    len: 0,
                    validated: None,
                },
            },
            pending: Bytes::new(),
            pending_frames: None,
            offset: 0,
            arena: Vec::new(),
            ranges: Vec::new(),
            parsed: 0,
            retry_at: 0,
            #[cfg(test)]
            parser_attempts: 0,
            total: 0,
            count: 0,
            budget: UnknownBudget::default(),
            outer_budget: UnknownBudget::default(),
            entry_error: None,
            inner_error: None,
            rejection: None,
            fatal: None,
            eof: false,
            limits,
            buffers: DecodeBuffers::default(),
            arena_bytes: None,
            range_bytes: None,
            codec_bytes: None,
            _transport: transport,
            request,
        }
    }

    pub(super) fn feed(&mut self, pending: Bytes, eof: bool) {
        assert!(self.pending.is_empty());
        assert!(self
            .pending_frames
            .as_ref()
            .is_none_or(|batch| batch.frames.is_empty()));
        self.pending_frames = None;
        self.pending = pending;
        self.offset = 0;
        self.eof = eof;
    }

    pub(super) fn queue_wire(&mut self, pending: Bytes, batch: Option<WireBatch>) {
        if let Some(batch) = batch {
            assert!(self.pending_frames.is_none());
            self.pending_frames = Some(batch);
        }
        self.pending_frames
            .as_mut()
            .unwrap()
            .frames
            .push_back(pending);
    }

    pub(super) fn finish_wire(&mut self) {
        self.eof = true;
    }

    pub(super) fn reject(&mut self, error: PutError) {
        if self.rejection.is_none() {
            self.rejection = Some(error);
        }
        self.ranges.clear();
    }

    pub fn run(mut self, buffers: DecodeBuffers) -> DecodeOutput {
        self.buffers = buffers;
        let result = if let Some(error) = &self.fatal {
            Err(error.clone().into())
        } else if self.buffers.inspect_header {
            self.header().and_then(|complete| {
                if complete {
                    Ok(DecodeStep::Bound(
                        self.message_bound()?.expect("validated zstd header"),
                    ))
                } else {
                    Ok(DecodeStep::Wire)
                }
            })
        } else {
            self.process()
        };
        if let Err(PutError::Connect(error)) = &result {
            self.fatal = Some(error.clone());
        }
        DecodeOutput {
            result,
            state: self,
        }
    }

    fn grow_arena(&mut self, capacity: usize) -> Result<(), PutError> {
        let lease = self.request.reserve_bytes(capacity)?;
        let mut arena = Vec::with_capacity(capacity);
        arena.extend_from_slice(&self.arena);
        self.arena = arena;
        self.arena_bytes = Some(lease);
        Ok(())
    }

    fn allocate(&mut self) -> Result<(), PutError> {
        if self.buffers.byte_capacity == 0 || self.buffers.entry_capacity == 0 {
            return Err(ConnectError::internal("decode buffer capacities must be positive").into());
        }
        if self.arena.capacity() == 0 {
            self.grow_arena(
                self.buffers
                    .byte_capacity
                    .min(self.limits.message_bytes)
                    .max(1),
            )?;
        }
        if self.ranges.capacity() == 0 && !self.suppressed() {
            let capacity = self
                .buffers
                .entry_capacity
                .min(self.limits.ingest.max_entries)
                .max(1);
            let bytes = capacity
                .checked_mul(std::mem::size_of::<EntryRanges>())
                .ok_or_else(|| ConnectError::resource_exhausted("entry buffer size overflow"))?;
            let lease = match self.request.reserve_bytes(bytes) {
                Ok(lease) => lease,
                Err(error) => {
                    self.reject(error.into());
                    return Ok(());
                }
            };
            self.ranges = Vec::with_capacity(capacity);
            self.range_bytes = Some(lease);
        }
        Ok(())
    }

    fn header(&mut self) -> Result<bool, PutError> {
        let Codec::Header {
            bytes,
            len,
            validated,
        } = &mut self.codec
        else {
            return Ok(true);
        };
        if validated.is_some() {
            return Ok(true);
        }
        let mut required = 5;
        loop {
            if *len >= 5 {
                if bytes[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
                    return Err(ConnectError::invalid_argument(
                        "zstd decompression failed: expected a standard frame",
                    )
                    .into());
                }
                let descriptor = bytes[4];
                if descriptor & 0x08 != 0 {
                    return Err(ConnectError::invalid_argument(
                        "zstd decompression failed: reserved frame header bit",
                    )
                    .into());
                }
                let single = descriptor & 0x20 != 0;
                let dictionary = [0, 1, 2, 4][usize::from(descriptor & 3)];
                let size = match descriptor >> 6 {
                    0 => usize::from(single),
                    1 => 2,
                    2 => 4,
                    _ => 8,
                };
                if size == 0 {
                    return Err(ConnectError::invalid_argument(
                        "zstd decompression failed: frame content size is required",
                    )
                    .into());
                }
                required = 5 + usize::from(!single) + dictionary + size;
            }
            if *len >= required {
                break;
            }
            if self.offset == self.pending.len() {
                self.pending = self
                    .pending_frames
                    .as_mut()
                    .and_then(|batch| batch.frames.pop_front())
                    .unwrap_or_default();
                self.offset = 0;
                if !self.pending.is_empty() {
                    continue;
                }
                if self.eof {
                    return Err(ConnectError::invalid_argument(
                        "zstd decompression failed: incomplete frame",
                    )
                    .into());
                }
                return Ok(false);
            }
            let count = (required - *len).min(self.pending.len() - self.offset);
            bytes[*len..*len + count]
                .copy_from_slice(&self.pending[self.offset..self.offset + count]);
            *len += count;
            self.offset += count;
        }
        validate_window_header(&bytes[..*len])?;
        let pledged = zstd::zstd_safe::get_frame_content_size(&bytes[..*len])
            .map_err(|_| {
                ConnectError::invalid_argument("zstd decompression failed: invalid frame header")
            })?
            .ok_or_else(|| {
                ConnectError::invalid_argument(
                    "zstd decompression failed: frame content size is required",
                )
            })?;
        let pledged = usize::try_from(pledged).map_err(|_| {
            ConnectError::resource_exhausted("zstd frame content size exceeds platform bound")
        })?;
        if pledged > self.limits.message_bytes {
            return Err(
                ConnectError::resource_exhausted("decoded request exceeds message limit").into(),
            );
        }
        let memory =
            usize::try_from(frame_decoder_memory_bytes(&bytes[..*len])?).map_err(|_| {
                ConnectError::resource_exhausted("zstd decoder memory exceeds platform bound")
            })?;
        *validated = Some((pledged, memory));
        Ok(true)
    }

    fn start_decoder(&mut self) -> Result<(), PutError> {
        let Codec::Header {
            bytes,
            len,
            validated: Some((pledged, memory)),
        } = &self.codec
        else {
            return Ok(());
        };
        let lease = self.request.reserve_bytes(*memory)?;
        let mut decoder = ArenaDecoder::new(*pledged)?;
        let mut consumed = 0;
        while consumed < *len {
            let step = decoder.step(&bytes[consumed..*len], &mut self.arena, OUTPUT_QUANTUM)?;
            consumed += step.consumed;
            if step.consumed == 0 && step.produced == 0 {
                return Err(ConnectError::invalid_argument(
                    "zstd decompression failed: invalid frame header",
                )
                .into());
            }
        }
        self.codec = Codec::Zstd(decoder);
        self.codec_bytes = Some(lease);
        Ok(())
    }

    pub(super) fn message_bound(&self) -> Result<Option<usize>, PutError> {
        if let Some(error) = &self.fatal {
            return Err(error.clone().into());
        }
        Ok(match &self.codec {
            Codec::Header { validated, .. } => validated.map(|(pledged, _)| pledged),
            Codec::Zstd(decoder) => Some(decoder.limit()),
            Codec::Identity => None,
        })
    }

    fn parse(&mut self, decoded_bound: usize) -> Result<(), PutError> {
        let data = &mut *self;
        let remaining = &data.arena[data.parsed..];
        if remaining.is_empty()
            || (remaining.len() < data.retry_at && !(data.eof && data.pending.is_empty()))
        {
            return Ok(());
        }
        #[cfg(test)]
        {
            data.parser_attempts += 1;
        }
        let mut cursor = PutEntryCursor::new(remaining);
        while data.suppressed() || data.ranges.len() < data.ranges.capacity() {
            let unknown_before = data.outer_budget.remaining();
            let field = match cursor.next(&mut data.outer_budget) {
                Ok(Some(field)) => field,
                Ok(None) => {
                    data.retry_at = 0;
                    break;
                }
                Err(PutParseError::Incomplete) => {
                    // Complete prefixes never participate in the next retry window.
                    let remaining = cursor.remaining();
                    data.retry_at = field_size(remaining)
                        .unwrap_or_else(|| remaining.len().saturating_mul(2))
                        .min(decoded_bound);
                    break;
                }
                Err(error) => return Err(ConnectError::from(error).into()),
            };
            data.retry_at = 0;
            let Field::Entry(entry) = field else {
                if data.inner_error.is_none() {
                    if let Err(error) = data
                        .budget
                        .charge_many(unknown_before - data.outer_budget.remaining())
                    {
                        data.inner_error = Some(ConnectError::from(error));
                        data.ranges.clear();
                    }
                }
                if data.arena.capacity() > data.buffers.byte_capacity {
                    break;
                }
                continue;
            };

            // Counting continues after rejection so finalization can preserve error precedence.
            let index = data.count;
            data.count += 1;
            if data.count > data.limits.ingest.max_entries {
                data.ranges.clear();
                continue;
            }

            if data.inner_error.is_some() {
                continue;
            }
            let (key, value) = match decode_entry_with_budget(entry, &mut data.budget) {
                Ok(entry) => entry,
                Err(error) => {
                    data.inner_error = Some(ConnectError::from(error));
                    data.ranges.clear();
                    continue;
                }
            };
            if data.entry_error.is_none() {
                data.entry_error =
                    crate::validate::validate_put_entry(index, key, value, data.limits.ingest)
                        .err();
            }
            if data.entry_error.is_none() && data.rejection.is_none() {
                let base = data.arena.as_ptr() as usize;
                let key_start = key.as_ptr() as usize - base;
                let value_start = value.as_ptr() as usize - base;
                data.ranges.push(EntryRanges {
                    key: key_start..key_start + key.len(),
                    value: value_start..value_start + value.len(),
                });
            } else {
                data.ranges.clear();
            }
        }
        data.parsed += cursor.consumed();
        Ok(())
    }

    fn compact(&mut self) {
        self.arena.copy_within(self.parsed.., 0);
        self.arena.truncate(self.arena.len() - self.parsed);
        self.parsed = 0;
    }

    fn batch(&mut self) -> Result<Option<DecodeStep>, PutError> {
        let suffix = self.arena.len() - self.parsed;
        let capacity = suffix
            .max(self.buffers.byte_capacity.min(self.limits.message_bytes))
            .max(1);
        let next_lease = match self.request.reserve_bytes(capacity) {
            Ok(lease) => lease,
            Err(error) => {
                self.reject(error.into());
                self.compact();
                return Ok(None);
            }
        };
        let mut next = Vec::with_capacity(capacity);
        next.extend_from_slice(&self.arena[self.parsed..]);
        let arena = std::mem::replace(&mut self.arena, next);
        let lease = self.arena_bytes.replace(next_lease);
        let range_bytes = std::mem::take(&mut self.range_bytes);
        let ranges = std::mem::take(&mut self.ranges);
        self.parsed = 0;
        let backing_capacity = arena.capacity();
        let data = Bytes::from_owner(super::buffer::ChunkBacking {
            data: arena,
            _bytes: lease,
            _request: self.request.clone(),
        });
        Ok(Some(DecodeStep::Batch(PutChunk {
            data,
            ranges,
            _range_bytes: range_bytes,
            request: self.request.clone(),
            backing_capacity,
        })))
    }

    fn process(&mut self) -> Result<DecodeStep, PutError> {
        self.allocate()?;
        if !self.header()? {
            return Ok(DecodeStep::Wire);
        }
        self.start_decoder()?;
        let decoded_bound = self
            .message_bound()?
            .unwrap_or(self.limits.wire_bytes)
            .min(self.limits.message_bytes);
        loop {
            self.parse(decoded_bound)?;
            if !self.ranges.is_empty()
                && (self.ranges.len() == self.ranges.capacity()
                    || self.parsed >= self.buffers.byte_capacity / 2
                    || self.pending.is_empty()
                    || field_size(&self.arena[self.parsed..])
                        .is_some_and(|size| size > self.buffers.byte_capacity))
            {
                if let Some(batch) = self.batch()? {
                    return Ok(batch);
                }
            }
            if self.ranges.is_empty() && self.parsed != 0 {
                self.compact();
                let capacity = self.arena.len().max(
                    self.buffers
                        .byte_capacity
                        .min(self.limits.message_bytes)
                        .max(1),
                );
                if self.arena.capacity() > capacity {
                    self.grow_arena(capacity)?;
                }

                // A large unknown field can leave a complete next field in the suffix.
                continue;
            }
            let field_capacity = field_size(&self.arena[self.parsed..])
                .filter(|size| *size > self.buffers.byte_capacity)
                .map(|size| size.min(decoded_bound));
            if let Some(capacity) = field_capacity {
                if capacity > self.arena.capacity() {
                    self.grow_arena(capacity)?;
                }
            }
            if self.arena.len() == self.arena.capacity() {
                if self.pending.is_empty() && matches!(self.codec, Codec::Identity) {
                    return Ok(if self.eof {
                        DecodeStep::Eof
                    } else {
                        DecodeStep::Wire
                    });
                }
                if !self.ranges.is_empty() {
                    if let Some(batch) = self.batch()? {
                        return Ok(batch);
                    }
                    continue;
                }
                let current = self.arena.capacity();
                let capacity = if self.retry_at > current {
                    self.retry_at
                } else {
                    current.saturating_mul(2)
                }
                .min(decoded_bound);
                if capacity <= self.arena.capacity() {
                    if matches!(self.codec, Codec::Identity)
                        && self.total >= self.limits.message_bytes
                        && !self.pending.is_empty()
                    {
                        return Err(ConnectError::resource_exhausted(
                            "decoded request exceeds message limit",
                        )
                        .into());
                    }
                    return Err(ConnectError::invalid_argument(
                        "failed to decode proto request: unexpected end of buffer",
                    )
                    .into());
                }
                self.grow_arena(capacity)?;
            }
            let previous = self.arena.len();
            let output_budget = field_capacity.map_or(OUTPUT_QUANTUM, |size| {
                size.saturating_sub(previous).min(OUTPUT_QUANTUM)
            });
            let consumed = match &mut self.codec {
                Codec::Identity => {
                    let count = (self.pending.len() - self.offset)
                        .min(self.arena.capacity() - previous)
                        .min(output_budget);
                    if count > self.limits.message_bytes.saturating_sub(self.total) {
                        return Err(ConnectError::resource_exhausted(
                            "decoded request exceeds message limit",
                        )
                        .into());
                    }
                    self.arena
                        .extend_from_slice(&self.pending[self.offset..self.offset + count]);
                    count
                }
                Codec::Zstd(decoder) => {
                    decoder
                        .step(&self.pending[self.offset..], &mut self.arena, output_budget)?
                        .consumed
                }
                Codec::Header { .. } => unreachable!(),
            };
            self.total += self.arena.len() - previous;
            self.offset += consumed;
            let advanced = self.offset == self.pending.len();
            if advanced {
                self.pending = self
                    .pending_frames
                    .as_mut()
                    .and_then(|batch| batch.frames.pop_front())
                    .unwrap_or_default();
                self.offset = 0;
            }
            if consumed == 0 && self.arena.len() == previous {
                if advanced && !self.pending.is_empty() {
                    continue;
                }
                if !self.ranges.is_empty() {
                    if let Some(batch) = self.batch()? {
                        return Ok(batch);
                    }
                }
                return Ok(if self.eof {
                    DecodeStep::Eof
                } else {
                    DecodeStep::Wire
                });
            }
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), PutError> {
        if let Some(error) = &self.fatal {
            return Err(error.clone().into());
        }
        if !self.eof || !self.pending.is_empty() {
            return Err(ConnectError::internal("ingest finalization before HTTP EOF").into());
        }
        if let Codec::Zstd(decoder) = &self.codec {
            decoder.finish()?;
        }
        if matches!(self.codec, Codec::Header { .. }) {
            return Err(ConnectError::invalid_argument(
                "zstd decompression failed: incomplete frame",
            )
            .into());
        }
        if self.parsed != self.arena.len() {
            return Err(ConnectError::from(PutParseError::Incomplete).into());
        }
        crate::validate::validate_put_count(self.count, self.limits.ingest)?;
        if let Some(error) = &self.inner_error {
            return Err(error.clone().into());
        }
        if let Some(error) = &self.entry_error {
            return Err(error.clone().into());
        }
        if let Some(error) = &self.rejection {
            return Err(error.clone());
        }
        Ok(())
    }

    pub(super) fn needs_wire(&self) -> bool {
        matches!(self.codec, Codec::Identity)
            && self.fatal.is_none()
            && !self.eof
            && self.pending.is_empty()
            && self
                .pending_frames
                .as_ref()
                .is_none_or(|batch| batch.frames.is_empty())
            && self.ranges.is_empty()
            && self.parsed == self.arena.len()
    }

    pub(super) fn total(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http_body_util::Full;
    use tokio::time::Instant;

    use super::*;
    use crate::ingest::{box_body, BudgetConfig, IngestBudget, PutInput, PutMetadata};

    fn field(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        buffa::encoding::encode_varint(bytes.len() as u64, &mut output);
        output.extend_from_slice(bytes);
        output
    }

    fn entry(key: &[u8], value: &[u8]) -> Vec<u8> {
        field(10, &[field(10, key), field(18, value)].concat())
    }

    fn state(encoding: PutEncoding, message_bytes: usize) -> (DecodeState, Arc<IngestBudget>) {
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 256 * 1024 * 1024,
        });
        let admission = budget.try_admit(0).unwrap();
        let state = DecodeState::new(
            encoding,
            PutLimits {
                message_bytes,
                ..PutLimits::default()
            },
            admission.transport.clone(),
            admission.request.clone(),
        );
        (state, budget)
    }

    #[test]
    fn header_inspection_leaves_decoder_and_preparation_unallocated() {
        let payload = entry(b"key", &[7; 1024]);
        let wire = zstd::bulk::compress(&payload, 1).unwrap();
        let (mut state, budget) = state(PutEncoding::Zstd, 4096);
        state.feed(Bytes::from(wire), false);
        let output = state.run(DecodeBuffers::header());
        assert!(matches!(output.result.unwrap(), DecodeStep::Bound(size) if size == payload.len()));
        let mut state = output.state;
        assert_eq!(state.arena.capacity(), 0);
        assert_eq!(state.ranges.capacity(), 0);
        assert_eq!(state.total, 0);
        assert_eq!(state.count, 0);
        assert_eq!(state.parser_attempts, 0);
        assert!(state.codec_bytes.is_none());
        assert!(matches!(
            state.codec,
            Codec::Header {
                validated: Some(_),
                ..
            }
        ));
        assert_eq!(budget.usage(), (1, 0));
        assert!(state.finish().is_err());
        let position = (state.pending.as_ptr(), state.offset);
        let output = state.run(DecodeBuffers::header());
        assert!(matches!(output.result.unwrap(), DecodeStep::Bound(size) if size == payload.len()));
        assert_eq!(
            position,
            (output.state.pending.as_ptr(), output.state.offset)
        );
        drop(output.state);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn chunk_backing_retains_full_capacity_after_input_drop() {
        let wire = [field(26, b"discarded prefix"), entry(b"key", b"value")].concat();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire.clone()))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        let chunk = input
            .next_batch(DecodeBuffers::new(64, 8))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chunk.backing_capacity(), 64);
        let value = chunk.data.slice(chunk.ranges()[0].value.clone());
        assert_eq!(value.as_ref(), b"value");
        assert!(chunk.ranges()[0].value.start > 16);
        assert!(chunk.data.len() < chunk.backing_capacity());
        input.finish().await.unwrap();
        drop(input);
        assert_eq!(
            budget.usage(),
            (1, 64 + 8 * std::mem::size_of::<EntryRanges>())
        );
        drop(chunk);
        assert_eq!(budget.usage(), (1, 64));
        drop(value);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn arena_replacement_requires_admission_for_both_live_allocations() {
        struct Inspect {
            budget: Arc<IngestBudget>,
            allocations: Arc<std::sync::Mutex<Vec<(usize, usize)>>>,
        }
        impl crate::ingest::DecodeExecutor for Inspect {
            fn execute(
                &self,
                state: DecodeState,
                buffers: DecodeBuffers,
            ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
                let output = state.run(buffers);
                self.allocations
                    .lock()
                    .unwrap()
                    .push((output.state.arena.capacity(), self.budget.usage().1));
                Box::pin(async move { Ok(output) })
            }
        }
        let wire = entry(b"key", &[7; 257]);
        let reserved = 64 + 8 * std::mem::size_of::<EntryRanges>();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 2 * wire.len() + reserved + wire.len() - 1,
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire.clone()))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        let allocations = Arc::new(std::sync::Mutex::new(Vec::new()));
        input.set_executor(Arc::new(Inspect {
            budget: budget.clone(),
            allocations: allocations.clone(),
        }));
        assert_eq!(
            input
                .next_batch(DecodeBuffers::new(64, 8))
                .await
                .err()
                .unwrap()
                .into_connect()
                .code,
            connectrpc::ErrorCode::ResourceExhausted
        );
        {
            let snapshots = allocations.lock().unwrap();
            assert_eq!(snapshots.as_slice(), &[(64, 2 * wire.len() + reserved)]);
        }
        assert!(input.finish().await.is_err());
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn grown_buffer_slice_keeps_only_its_backing_charge_after_chunk_drop() {
        let wire = entry(b"key", &[7; 257]);
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 1024 * 1024,
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire.clone()))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        let chunk = input
            .next_batch(DecodeBuffers::new(64, 8))
            .await
            .unwrap()
            .unwrap();
        let value = chunk.data.slice(chunk.ranges()[0].value.clone());
        assert_eq!(chunk.backing_capacity(), wire.len());
        input.finish().await.unwrap();
        drop(input);
        assert_eq!(
            budget.usage(),
            (1, 8 * std::mem::size_of::<EntryRanges>() + wire.len())
        );
        drop(chunk);
        assert_eq!(budget.usage(), (1, wire.len()));
        assert_eq!(value.as_ref(), &[7; 257]);
        drop(value);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[test]
    fn group_retry_attempts_stay_bounded_across_fragments() {
        let mut wire = vec![19];
        for _ in 0..6000 {
            wire.extend_from_slice(&[24, 0]);
        }
        wire.extend(field(26, &vec![9; 512 * 1024]));
        wire.push(20);
        wire.extend(entry(b"key", b"value"));
        let (mut state, budget) = state(PutEncoding::Identity, wire.len() + 64 * 1024);
        let mut entries = 0;
        for fragment in wire.chunks(1024) {
            state.feed(Bytes::copy_from_slice(fragment), false);
            loop {
                let output = state.run(DecodeBuffers::new(8192, 16));
                state = output.state;
                match output.result.unwrap() {
                    DecodeStep::Batch(chunk) => entries += chunk.ranges().len(),
                    DecodeStep::Wire => break,
                    DecodeStep::Eof | DecodeStep::Bound(_) => panic!("body still open"),
                }
            }
        }
        state.feed(Bytes::new(), true);
        loop {
            let output = state.run(DecodeBuffers::new(8192, 16));
            state = output.state;
            match output.result.unwrap() {
                DecodeStep::Batch(chunk) => entries += chunk.ranges().len(),
                DecodeStep::Eof => break,
                DecodeStep::Wire | DecodeStep::Bound(_) => panic!("body closed"),
            }
        }
        state.finish().unwrap();
        assert_eq!(entries, 1);
        assert!(
            state.parser_attempts <= 32,
            "{} attempts",
            state.parser_attempts
        );
        drop(state);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[test]
    fn eof_forces_group_parse_before_retry_target() {
        for truncated in [false, true] {
            let mut wire = entry(b"key", b"value");
            wire.push(19);
            wire.extend(field(26, &vec![9; 20_000]));
            if !truncated {
                wire.push(20);
            }
            let (mut state, _) = state(PutEncoding::Identity, 65536);
            for fragment in wire.chunks(1024) {
                state.feed(Bytes::copy_from_slice(fragment), false);
                loop {
                    let output = state.run(DecodeBuffers::new(8192, 16));
                    state = output.state;
                    match output.result.unwrap() {
                        DecodeStep::Batch(_) => {}
                        DecodeStep::Wire => break,
                        DecodeStep::Eof | DecodeStep::Bound(_) => panic!("body still open"),
                    }
                }
            }
            assert!(state.arena.len() < state.retry_at);
            let attempts = state.parser_attempts;
            state.feed(Bytes::new(), true);
            let output = state.run(DecodeBuffers::new(8192, 16));
            assert!(matches!(output.result.unwrap(), DecodeStep::Eof));
            state = output.state;
            assert_eq!(state.parser_attempts, attempts + 1);
            assert_eq!(state.finish().is_err(), truncated);
        }
    }

    #[test]
    fn large_value_uses_exact_field_backing_and_shares_its_destination() {
        let value = vec![7; 32 * 1024 * 1024];
        let wire = entry(b"blob", &value);
        for encoding in [PutEncoding::Identity, PutEncoding::Zstd] {
            let input = match encoding {
                PutEncoding::Identity => wire.clone(),
                PutEncoding::Zstd => zstd::bulk::compress(&wire, 1).unwrap(),
            };
            let (mut state, budget) = state(encoding, wire.len() + 1024);
            state.feed(Bytes::copy_from_slice(&input[..128]), false);
            let output = state.run(DecodeBuffers::new(64 * 1024, 16));
            assert!(matches!(output.result.unwrap(), DecodeStep::Wire));
            state = output.state;
            assert_eq!(state.arena.capacity(), wire.len());
            let expected = state.arena.as_ptr().wrapping_add(wire.len() - value.len());
            state.feed(Bytes::copy_from_slice(&input[128..]), true);
            let output = state.run(DecodeBuffers::new(64 * 1024, 16));
            let DecodeStep::Batch(chunk) = output.result.unwrap() else {
                panic!("expected large value");
            };
            assert_eq!(chunk.backing_capacity(), wire.len());
            let kept = chunk.data.slice(chunk.ranges()[0].value.clone());
            assert_eq!(kept.as_ptr(), expected);
            assert_eq!(kept.as_ref(), value);
            drop(chunk);
            drop(output.state);
            assert_eq!(budget.usage().0, 1);
            assert_eq!(budget.usage().1, wire.len());
            drop(kept);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[test]
    fn large_unknown_field_does_not_pin_its_backing_in_the_next_chunk() {
        let unknown = field(26, &vec![9; 2 * 1024 * 1024]);
        let suffix = entry(b"key", b"value");
        let wire = [unknown.clone(), suffix].concat();
        let (mut state, _) = state(PutEncoding::Identity, wire.len() + 64);
        state.feed(Bytes::from(wire), true);
        let output = state.run(DecodeBuffers::new(8192, 16));
        let DecodeStep::Batch(chunk) = output.result.unwrap() else {
            panic!("expected inline entry");
        };
        assert_eq!(chunk.backing_capacity(), 8192);
        assert_eq!(
            chunk.entries().collect::<Vec<_>>(),
            vec![(b"key".as_slice(), b"value".as_slice())]
        );
    }
}
