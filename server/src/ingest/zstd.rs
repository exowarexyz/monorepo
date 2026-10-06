use zstd::stream::raw::{InBuffer, OutBuffer, WriteBuf};
use zstd::zstd_safe::{get_frame_content_size, DCtx};

pub(super) const WINDOW_LOG_MAX: u32 = 27;

// A small protobuf payload with a 256 MiB window exercises streaming-limit parity.
#[cfg(test)]
pub(super) const OVERSIZED_WINDOW_FRAME: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, 0x40, 0x90, 0x00, 0x03, 0x7d, 0x00, 0x00, 0x40, 0x0a, 0x06, 0x0a, 0x01,
    0x61, 0x12, 0x01, 0x62, 0x01, 0x00, 0xf5, 0x57, 0x15, 0x2e,
];

pub(super) struct ArenaDecoder {
    context: DCtx<'static>,
    total: usize,
    limit: usize,
    started: bool,
    finished: bool,
}

#[derive(Debug)]
pub(super) struct ArenaStep {
    pub(super) consumed: usize,
    pub(super) produced: usize,
}

impl ArenaDecoder {
    pub(super) fn new(limit: usize) -> Result<Self, connectrpc::ConnectError> {
        let mut context = DCtx::try_create().ok_or_else(|| {
            connectrpc::ConnectError::resource_exhausted("unable to allocate zstd decoder")
        })?;
        context.init().map_err(zstd_error)?;
        context
            .set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(WINDOW_LOG_MAX))
            .map_err(zstd_error)?;
        Ok(Self {
            context,
            total: 0,
            limit,
            started: false,
            finished: false,
        })
    }

    #[cfg(test)]
    fn context_size(&self) -> usize {
        self.context.sizeof()
    }

    pub(super) fn finish(&self) -> Result<(), connectrpc::ConnectError> {
        if !self.finished {
            return Err(connectrpc::ConnectError::invalid_argument(
                "zstd decompression failed: incomplete frame",
            ));
        }
        self.validate_size()
    }

    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    pub(super) fn step(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        budget: usize,
    ) -> Result<ArenaStep, connectrpc::ConnectError> {
        if self.finished {
            if input.is_empty() {
                return Ok(ArenaStep {
                    consumed: 0,
                    produced: 0,
                });
            }
            return Err(connectrpc::ConnectError::invalid_argument(
                "zstd decompression failed: trailing input after frame",
            ));
        }

        let mut source = InBuffer::around(input);
        let remaining = self.limit - self.total;
        let (result, produced) = if remaining == 0 {
            // A single probe byte distinguishes an exact limit from overflowing output.
            let mut probe = [0u8; 1];
            let mut destination = OutBuffer::around(&mut probe[..]);
            let result = self
                .context
                .decompress_stream(&mut destination, &mut source);
            (result, destination.pos())
        } else {
            let previous = output.len();
            let limit = previous + budget.min(remaining).min(output.capacity() - previous);
            let mut target = CappedOutput { output, limit };
            let mut destination = OutBuffer::around_pos(&mut target, previous);
            let result = self
                .context
                .decompress_stream(&mut destination, &mut source);
            (result, destination.pos() - previous)
        };
        let hint = result.map_err(zstd_error)?;
        if produced > remaining {
            return Err(connectrpc::ConnectError::invalid_argument(format!(
                "zstd decompression failed: frame content size pledged {} bytes but decoded more",
                self.limit
            )));
        }
        self.total += produced;
        if source.pos() != 0 || produced != 0 {
            self.started = true;
        }
        if hint == 0 && self.started {
            self.finished = true;
            self.validate_size()?;
        }
        Ok(ArenaStep {
            consumed: source.pos(),
            produced,
        })
    }

    fn validate_size(&self) -> Result<(), connectrpc::ConnectError> {
        if self.total == self.limit {
            return Ok(());
        }
        Err(connectrpc::ConnectError::invalid_argument(format!(
            "zstd decompression failed: frame content size pledged {} bytes but decoded {} bytes",
            self.limit, self.total
        )))
    }
}

fn zstd_error(code: usize) -> connectrpc::ConnectError {
    connectrpc::ConnectError::invalid_argument(format!(
        "zstd decompression failed: {}",
        zstd::zstd_safe::get_error_name(code)
    ))
}

pub(super) fn frame_decoder_memory_bytes(header: &[u8]) -> Result<u64, connectrpc::ConnectError> {
    let mut frame = std::mem::MaybeUninit::uninit();

    // SAFETY: The native parser receives a writable header and the complete input slice.
    let result = unsafe {
        zstd::zstd_safe::zstd_sys::ZSTD_getFrameHeader(
            frame.as_mut_ptr(),
            header.as_ptr().cast(),
            header.len(),
        )
    };
    if unsafe { zstd::zstd_safe::zstd_sys::ZSTD_isError(result) } != 0 {
        return Err(zstd_error(result));
    }
    if result != 0 {
        return Err(connectrpc::ConnectError::invalid_argument(
            "zstd decompression failed: incomplete frame header",
        ));
    }

    // SAFETY: A zero result initializes the entire native header.
    let frame = unsafe { frame.assume_init() };
    if frame.dictID != 0 {
        return Err(connectrpc::ConnectError::invalid_argument(
            "zstd decompression failed: dictionaries are not supported",
        ));
    }

    // Match zstd's cold streaming allocation. The pledge caps output storage,
    // while the advertised window still determines the input block size.
    let output = unsafe {
        zstd::zstd_safe::zstd_sys::ZSTD_decodingBufferSize_min(
            frame.windowSize.max(1024),
            frame.frameContentSize,
        )
    };
    if unsafe { zstd::zstd_safe::zstd_sys::ZSTD_isError(output) } != 0 {
        return Err(zstd_error(output));
    }
    let context = unsafe { zstd::zstd_safe::zstd_sys::ZSTD_estimateDCtxSize() };
    context
        .checked_add(frame.blockSizeMax.max(4) as usize)
        .and_then(|bytes| bytes.checked_add(output))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| {
            connectrpc::ConnectError::resource_exhausted("zstd decoder memory estimate overflow")
        })
}

pub(super) fn validate_window_header(input: &[u8]) -> Result<(), connectrpc::ConnectError> {
    if !input.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Ok(());
    }
    let Some(descriptor) = input.get(4) else {
        return Ok(());
    };
    // Leave malformed headers to the decoder's existing diagnostics.
    if descriptor & 0x08 != 0 {
        return Ok(());
    }
    let oversized = if descriptor & 0x20 == 0 {
        input.get(5).is_some_and(|window| *window > 0x88)
    } else {
        get_frame_content_size(input)
            .ok()
            .flatten()
            .is_some_and(|size| size > 1 << 27)
    };
    if oversized {
        return Err(connectrpc::ConnectError::invalid_argument(
            "zstd decompression failed: Frame requires too much memory for decoding",
        ));
    }
    Ok(())
}

struct CappedOutput<'a> {
    output: &'a mut Vec<u8>,
    limit: usize,
}

// SAFETY: The reported capacity never exceeds the allocation. The initialized slice and
// pointer share that allocation, which remains exclusively borrowed throughout each run.
unsafe impl WriteBuf for CappedOutput<'_> {
    fn as_slice(&self) -> &[u8] {
        self.output.as_slice()
    }

    fn capacity(&self) -> usize {
        self.limit
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.output.as_mut_ptr()
    }

    unsafe fn filled_until(&mut self, n: usize) {
        assert!(n <= self.limit && self.limit <= self.output.capacity());

        // SAFETY: WriteBuf's caller guarantees initialization through n, within our cap.
        unsafe { self.output.set_len(n) };
    }
}

#[cfg(test)]
mod arena_tests {
    use std::io::Write;

    use super::*;

    fn decode_with(
        decoder: &mut ArenaDecoder,
        input: &[u8],
        budget: usize,
    ) -> Result<Vec<u8>, connectrpc::ConnectError> {
        let mut consumed = 0;
        let mut result = Vec::new();
        loop {
            let mut output = Vec::with_capacity(budget);
            let step = decoder.step(&input[consumed..], &mut output, budget)?;
            consumed += step.consumed;
            result.extend_from_slice(&output);
            if step.consumed == 0 && step.produced == 0 {
                assert_eq!(consumed, input.len());
                decoder.finish()?;
                return Ok(result);
            }
        }
    }

    fn decode(
        input: &[u8],
        cap: usize,
        budget: usize,
    ) -> Result<Vec<u8>, connectrpc::ConnectError> {
        let mut decoder = ArenaDecoder::new(cap)?;
        decode_with(&mut decoder, input, budget)
    }

    fn checksummed_frame(payload: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder
            .set_pledged_src_size(Some(payload.len() as u64))
            .unwrap();
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn windowed_frame(payload: &[u8], descriptor: u8) -> Vec<u8> {
        let mut wire = checksummed_frame(payload);
        assert_ne!(wire[4] & 0x20, 0);
        wire[4] &= !0x20;
        wire.insert(5, descriptor);
        assert_eq!(
            get_frame_content_size(&wire).unwrap(),
            Some(payload.len() as u64)
        );
        wire
    }

    fn decode_fragmented_with(
        decoder: &mut ArenaDecoder,
        input: &[u8],
        fragment: usize,
        budget: usize,
    ) -> Result<(Vec<u8>, usize), connectrpc::ConnectError> {
        let mut consumed = 0;
        let mut available = fragment.min(input.len());
        let mut result = Vec::new();
        let mut max_context_size = decoder.context_size();
        loop {
            let mut output = Vec::with_capacity(budget);
            let step = decoder.step(&input[consumed..available], &mut output, budget)?;
            consumed += step.consumed;
            result.extend_from_slice(&output);
            max_context_size = max_context_size.max(decoder.context_size());
            if step.consumed == 0 && step.produced == 0 {
                if available < input.len() {
                    available = (available + fragment).min(input.len());
                    continue;
                }
                decoder.finish()?;
                return Ok((result, max_context_size));
            }
            if consumed == available && available < input.len() {
                available = (available + fragment).min(input.len());
            }
        }
    }

    #[test]
    fn frame_estimate_covers_native_context_across_geometries_and_fragmentation() {
        let patterned = (0..4096)
            .map(|index| (index * 31) as u8)
            .collect::<Vec<_>>();
        let window_payload = (0..256).map(|index| index as u8).collect::<Vec<_>>();
        let cases = [
            (checksummed_frame(&[]), Vec::new(), 1),
            (checksummed_frame(&patterned), patterned, 3),
            (
                windowed_frame(&window_payload, 0x00),
                window_payload.clone(),
                2,
            ),
            (
                windowed_frame(&window_payload, 0x50),
                window_payload.clone(),
                5,
            ),
            (
                windowed_frame(&window_payload, 0x70),
                window_payload.clone(),
                7,
            ),
            (windowed_frame(&window_payload, 0x88), window_payload, 11),
        ];

        for (wire, payload, fragment) in cases {
            let header = &wire[..wire.len().min(18)];
            let native_estimate = unsafe {
                zstd::zstd_safe::zstd_sys::ZSTD_estimateDStreamSize_fromFrame(
                    header.as_ptr().cast(),
                    header.len(),
                )
            };
            assert_eq!(
                unsafe { zstd::zstd_safe::zstd_sys::ZSTD_isError(native_estimate) },
                0
            );
            let accounted = frame_decoder_memory_bytes(header).unwrap();
            assert!(accounted <= native_estimate as u64);
            if payload.len() <= 4096 {
                assert!(accounted < 1024 * 1024);
            }

            let mut decoder = ArenaDecoder::new(payload.len()).unwrap();
            let (decoded, max_context_size) =
                decode_fragmented_with(&mut decoder, &wire, fragment, 113).unwrap();
            assert_eq!(decoded, payload);
            assert!(max_context_size as u64 <= accounted);
            drop(decoder);
        }
    }

    #[test]
    fn frame_estimate_rejects_dictionary_memory() {
        let mut wire = checksummed_frame(b"dictionary frame");
        assert_eq!(wire[4] & 0x03, 0);
        wire[4] |= 0x01;
        wire.insert(5, 7);
        assert!(zstd::zstd_safe::get_dict_id_from_frame(&wire).is_some());
        let error = frame_decoder_memory_bytes(&wire).unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(
            error.message.as_deref(),
            Some("zstd decompression failed: dictionaries are not supported")
        );
    }

    #[test]
    fn arena_cap_allows_exact_limit_and_rejects_overflow() {
        let wire = zstd::bulk::compress(b"firstsecond", 1).unwrap();
        assert_eq!(decode(&wire, 11, 2).unwrap(), b"firstsecond");
        let error = decode(&wire, 10, 2).unwrap_err();
        assert!(error.to_string().contains("zstd decompression failed"));
        assert!(decode(&wire, 0, 2).is_err());
        assert!(decode(&zstd::bulk::compress(b"", 1).unwrap(), 0, 2)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn arena_preserves_default_streaming_window_limit() {
        let error = decode(OVERSIZED_WINDOW_FRAME, 1024, 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("Frame requires too much memory for decoding"));
    }

    #[test]
    fn arena_rejects_additional_frames() {
        let wire = zstd::bulk::compress(b"first", 1).unwrap();
        let mut decoder = ArenaDecoder::new(5).unwrap();
        assert_eq!(decode_with(&mut decoder, &wire, 8).unwrap(), b"first");
        let context_size = decoder.context_size();
        let mut output = Vec::with_capacity(8);
        let error = decoder
            .step(OVERSIZED_WINDOW_FRAME, &mut output, 8)
            .unwrap_err();
        assert!(error.to_string().contains("trailing input after frame"));
        assert_eq!(decoder.context_size(), context_size);
        assert!(output.is_empty());
    }

    #[test]
    fn arena_caps_writes_for_incorrect_pledges() {
        for pledged in [6, 8] {
            let mut wire = checksummed_frame(b"payload");
            assert_eq!(wire[4] & 0x20, 0x20);
            wire[5] = pledged;
            let mut decoder = ArenaDecoder::new(pledged as usize).unwrap();
            let mut consumed = 0;
            let mut output = Vec::with_capacity(16);
            let error = loop {
                match decoder.step(&wire[consumed..], &mut output, 16) {
                    Ok(step) => {
                        consumed += step.consumed;
                        assert!(step.consumed != 0 || step.produced != 0);
                    }
                    Err(error) => break error,
                }
            };
            assert!(error.to_string().contains("zstd decompression failed"));
            assert!(output.len() <= pledged as usize);
        }
    }

    #[test]
    fn arena_finishes_checksum_after_exact_output_and_rejects_later_input() {
        let payload = b"checksum pending";
        let wire = checksummed_frame(payload);
        let checksum = wire.len() - 4;
        let mut decoder = ArenaDecoder::new(payload.len()).unwrap();
        let mut output = Vec::with_capacity(payload.len());
        let mut consumed = 0;
        while consumed < checksum {
            let step = decoder
                .step(&wire[consumed..checksum], &mut output, payload.len())
                .unwrap();
            consumed += step.consumed;
            assert!(step.consumed != 0 || step.produced != 0);
        }
        assert_eq!(output, payload);
        assert!(!decoder.finished);

        let step = decoder.step(&wire[checksum..], &mut output, 0).unwrap();
        assert_eq!(step.consumed, 4);
        assert_eq!(step.produced, 0);
        decoder.finish().unwrap();

        let error = decoder.step(&[0], &mut output, 0).unwrap_err();
        assert!(error.to_string().contains("trailing input after frame"));
    }

    #[test]
    fn arena_rejects_corrupt_checksum_and_incomplete_frame() {
        let payload = b"checked frame";
        let valid = checksummed_frame(payload);
        let mut malformed = valid.clone();
        *malformed.last_mut().unwrap() ^= 1;
        let error = decode(&malformed, payload.len(), 8).unwrap_err();
        assert!(error.to_string().to_ascii_lowercase().contains("checksum"));
        let error = decode(&valid[..valid.len() - 1], payload.len(), 8).unwrap_err();
        assert!(error.to_string().contains("incomplete frame"));
    }
}
