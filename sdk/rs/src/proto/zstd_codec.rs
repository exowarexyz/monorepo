//! The "zstd" codec that
//! [`connect_compression_registry`](super::connect_compression_registry) registers.

use std::io::Read;
use std::sync::Mutex;

use bytes::Bytes;
use connectrpc::compression::{CompressionProvider, ZstdProvider};
use connectrpc::ConnectError;
use zstd::bulk::Decompressor;
use zstd::zstd_safe::{find_frame_compressed_size, get_frame_content_size};

/// Most idle decompressors kept for reuse, the same cap connectrpc puts on its compressor pool.
const MAX_IDLE_DECOMPRESSORS: usize = 64;

/// Compresses with connectrpc's [`ZstdProvider`] and decompresses into an exactly sized buffer.
///
/// connectrpc's own decompression copies the input through a 128 KiB `BufReader`, starts its
/// output at four times the compressed size and grows it by doubling. The returned `Bytes` keeps
/// that whole capacity, and every value the response decoder slices out of it keeps it alive.
/// For an incompressible 32 MiB blob, that is a 128 MiB allocation.
///
/// A zstd encoder that knows its input size up front, like connectrpc's, writes that size into
/// the frame header. When the input is exactly one frame with that size, this codec checks the
/// size against the limit, reserves exactly that much and decompresses in one call with a
/// pooled decompressor. Any other input (no size in the header, several frames, or bytes that
/// aren't a valid frame) takes the streaming path connectrpc uses, without the `BufReader`.
pub(crate) struct ZstdCodec {
    compressor: ZstdProvider,
    decompressors: Mutex<Vec<Decompressor<'static>>>,
}

impl ZstdCodec {
    pub(crate) fn new(compressor: ZstdProvider) -> Self {
        Self {
            compressor,
            decompressors: Mutex::new(Vec::new()),
        }
    }

    /// Decompresses a single frame whose header says it holds `size` bytes.
    ///
    /// The output never takes more than the `size` bytes reserved up front. A frame that holds
    /// more than it claims fails when the buffer is full, and one that holds less fails zstd's
    /// own check of the claimed size.
    fn decompress_sized(&self, data: &[u8], size: usize) -> Result<Bytes, ConnectError> {
        let mut output = Vec::new();
        output.try_reserve_exact(size).map_err(|_| {
            ConnectError::resource_exhausted(format!(
                "cannot allocate {size} bytes to decompress zstd"
            ))
        })?;
        let idle = self
            .decompressors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop();
        let mut decompressor = match idle {
            Some(decompressor) => decompressor,
            None => Decompressor::new().map_err(|e| {
                ConnectError::internal(format!("failed to create zstd decompressor: {e}"))
            })?,
        };
        // Each call starts a new frame, so a decompressor that failed is still reusable.
        let result = decompressor.decompress_to_buffer(data, &mut output);
        let mut idle = self.decompressors.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < MAX_IDLE_DECOMPRESSORS {
            idle.push(decompressor);
        }
        drop(idle);
        result.map_err(malformed)?;
        Ok(Bytes::from(output))
    }
}

/// The streaming decoder and limit check of connectrpc's `ZstdProvider`, reading the input in
/// place instead of through a `BufReader`. The output is shrunk to its length before it is
/// returned.
fn decompress_streaming(data: &[u8], max_size: usize) -> Result<Bytes, ConnectError> {
    let decoder = zstd::stream::read::Decoder::with_buffer(data).map_err(malformed)?;
    let mut output = Vec::with_capacity(
        data.len()
            .saturating_mul(4)
            .max(256)
            .min(max_size.saturating_add(1)),
    );
    decoder
        .take((max_size as u64).saturating_add(1))
        .read_to_end(&mut output)
        .map_err(malformed)?;
    if output.len() > max_size {
        return Err(exceeds_limit(max_size));
    }
    output.shrink_to_fit();
    Ok(Bytes::from(output))
}

fn malformed(error: std::io::Error) -> ConnectError {
    ConnectError::invalid_argument(format!("zstd decompression failed: {error}"))
}

fn exceeds_limit(max_size: usize) -> ConnectError {
    ConnectError::resource_exhausted(format!("decompressed size exceeds limit {max_size}"))
}

impl CompressionProvider for ZstdCodec {
    fn name(&self) -> &'static str {
        self.compressor.name()
    }

    fn compress(&self, data: &[u8]) -> Result<Bytes, ConnectError> {
        self.compressor.compress(data)
    }

    fn decompressor<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<Box<dyn std::io::Read + 'a>, ConnectError> {
        self.compressor.decompressor(data)
    }

    fn decompress_with_limit(&self, data: &[u8], max_size: usize) -> Result<Bytes, ConnectError> {
        let single_frame = find_frame_compressed_size(data).is_ok_and(|len| len == data.len());
        let content_size = if single_frame {
            get_frame_content_size(data).ok().flatten()
        } else {
            None
        };
        match content_size {
            None => decompress_streaming(data, max_size),
            Some(size) => match usize::try_from(size) {
                Ok(size) if size <= max_size => self.decompress_sized(data, size),
                _ => Err(exceeds_limit(max_size)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connectrpc::ErrorCode;

    const LIMIT: usize = 64 * 1024 * 1024;

    fn codec() -> ZstdCodec {
        ZstdCodec::new(ZstdProvider::default())
    }

    /// Deterministic bytes zstd can't compress.
    fn random(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// Bytes zstd compresses well, but not to a trivial frame.
    fn compressible(len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) % 1_000 / 100) as u8)
            .collect()
    }

    /// Size of the allocation behind `bytes`, which must be its only handle.
    fn capacity(bytes: Bytes) -> usize {
        bytes.try_into_mut().unwrap().capacity()
    }

    fn error_code(result: Result<Bytes, ConnectError>) -> ErrorCode {
        result.unwrap_err().code
    }

    /// Rewrites the content size in a frame header whose size field is 4 or 8 bytes long.
    fn with_content_size(frame: &[u8], size: u64) -> Vec<u8> {
        let descriptor = frame[4];
        let single_segment = descriptor & 0x20 != 0;
        let dictionary_id_len = [0, 1, 2, 4][usize::from(descriptor & 0x03)];
        let start = 5 + usize::from(!single_segment) + dictionary_id_len;
        let mut frame = frame.to_vec();
        match descriptor >> 6 {
            2 => {
                frame[start..start + 4].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes())
            }
            3 => frame[start..start + 8].copy_from_slice(&size.to_le_bytes()),
            flag => panic!("content size field flag {flag} is not 4 or 8 bytes"),
        }
        assert_eq!(get_frame_content_size(&frame).unwrap(), Some(size));
        frame
    }

    #[test]
    fn registry_returns_zstd_responses_without_spare_capacity() {
        let registry = super::super::connect_compression_registry();
        assert_eq!(registry.accept_encoding_header(), "gzip, zstd");
        for payload in [random(1024 * 1024), compressible(1024 * 1024)] {
            let compressed = registry.compress("zstd", &payload).unwrap();
            let decompressed = registry
                .decompress_with_limit("zstd", compressed, LIMIT)
                .unwrap();
            assert_eq!(decompressed, payload);
            assert_eq!(capacity(decompressed), payload.len());
        }
    }

    #[test]
    fn round_trips_like_connectrpc() {
        let stock = ZstdProvider::default();
        let codec = codec();
        for payload in [
            Vec::new(),
            b"hello".to_vec(),
            compressible(100_000),
            random(100_000),
            compressible(3 * 1024 * 1024),
        ] {
            let compressed = codec.compress(&payload).unwrap();
            assert_eq!(compressed, stock.compress(&payload).unwrap());
            assert_eq!(
                get_frame_content_size(&compressed).unwrap(),
                Some(payload.len() as u64)
            );
            let decompressed = codec.decompress_with_limit(&compressed, LIMIT).unwrap();
            assert_eq!(decompressed, payload);
            assert_eq!(
                decompressed,
                stock.decompress_with_limit(&compressed, LIMIT).unwrap()
            );
            if !payload.is_empty() {
                assert_eq!(capacity(decompressed), payload.len());
            }
        }
    }

    #[test]
    fn rejects_content_size_over_limit() {
        let payload = compressible(100_000);
        let compressed = codec().compress(&payload).unwrap();
        assert_eq!(
            codec()
                .decompress_with_limit(&compressed, payload.len())
                .unwrap(),
            payload
        );
        let error = codec()
            .decompress_with_limit(&compressed, payload.len() - 1)
            .unwrap_err();
        let stock = ZstdProvider::default()
            .decompress_with_limit(&compressed, payload.len() - 1)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert_eq!(error.code, stock.code);
        assert_eq!(error.message, stock.message);
    }

    #[test]
    fn rejects_frames_whose_content_size_lies() {
        let payload = compressible(100_000);
        let frame = codec().compress(&payload).unwrap();

        // Holds more than it claims, and more than the limit. Decoding stops when the claimed
        // 50,000 bytes are full.
        let short = with_content_size(&frame, 50_000);
        assert_eq!(
            error_code(codec().decompress_with_limit(&short, 60_000)),
            ErrorCode::InvalidArgument
        );
        // Holds less than it claims.
        let long = with_content_size(&frame, 150_000);
        assert_eq!(
            error_code(codec().decompress_with_limit(&long, LIMIT)),
            ErrorCode::InvalidArgument
        );
        // Claims more than the limit. Rejected from the header, before reserving anything.
        let huge = with_content_size(&frame, 1 << 31);
        assert_eq!(
            error_code(codec().decompress_with_limit(&huge, LIMIT)),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn a_failed_frame_leaves_its_decompressor_reusable() {
        let codec = codec();
        let payload = compressible(100_000);
        let frame = codec.compress(&payload).unwrap();
        let short = with_content_size(&frame, 50_000);
        for _ in 0..3 {
            assert!(codec.decompress_with_limit(&short, LIMIT).is_err());
            assert_eq!(codec.decompress_with_limit(&frame, LIMIT).unwrap(), payload);
        }
        assert_eq!(codec.decompressors.lock().unwrap().len(), 1);
    }

    #[test]
    fn frames_without_content_size_stream_into_an_exact_buffer() {
        let payload = compressible(1024 * 1024);
        let mut compressor = zstd::bulk::Compressor::new(3).unwrap();
        compressor.include_contentsize(false).unwrap();
        let frame = compressor.compress(&payload).unwrap();
        assert_eq!(get_frame_content_size(&frame).unwrap(), None);

        let decompressed = codec().decompress_with_limit(&frame, LIMIT).unwrap();
        assert_eq!(decompressed, payload);
        assert_eq!(capacity(decompressed), payload.len());
        assert_eq!(
            codec()
                .decompress_with_limit(&frame, payload.len())
                .unwrap(),
            payload
        );
        assert_eq!(
            error_code(codec().decompress_with_limit(&frame, payload.len() - 1)),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn several_frames_decode_like_connectrpc() {
        let first = compressible(100_000);
        let second = random(50_000);
        let skippable = [0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 1, 2, 3, 4];
        let mut input = codec().compress(&first).unwrap().to_vec();
        input.extend_from_slice(&skippable);
        input.extend_from_slice(&codec().compress(&second).unwrap());
        let expected = [first, second].concat();

        let stock = ZstdProvider::default();
        let decompressed = codec().decompress_with_limit(&input, LIMIT).unwrap();
        assert_eq!(decompressed, expected);
        assert_eq!(
            decompressed,
            stock.decompress_with_limit(&input, LIMIT).unwrap()
        );
        assert_eq!(capacity(decompressed), expected.len());
        for limit in [expected.len() - 1, 100_000] {
            assert_eq!(
                error_code(codec().decompress_with_limit(&input, limit)),
                ErrorCode::ResourceExhausted
            );
        }
    }

    #[test]
    fn malformed_input_fails_like_connectrpc() {
        let frame = codec().compress(&compressible(100_000)).unwrap();
        let truncated = &frame[..frame.len() - 3];
        let trailing = [&frame[..], &[0xaa; 8]].concat();
        let stock = ZstdProvider::default();
        for input in [&b"not zstd"[..], truncated, &trailing] {
            let error = codec().decompress_with_limit(input, LIMIT).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert_eq!(
                error.code,
                stock.decompress_with_limit(input, LIMIT).unwrap_err().code
            );
        }
    }
}
