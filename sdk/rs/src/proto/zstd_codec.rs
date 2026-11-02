//! The "zstd" codec that
//! [`connect_compression_registry`](super::connect_compression_registry) registers.

use bytes::Bytes;
use connectrpc::compression::{CompressionProvider, ZstdProvider};
use connectrpc::ConnectError;
use zstd::zstd_safe::{
    decompress, find_frame_compressed_size, get_error_name, get_frame_content_size,
};

/// connectrpc's [`ZstdProvider`], except that a frame whose header records a size within the
/// limit decompresses into a buffer of exactly that size.
///
/// connectrpc's own decompression copies the input through a 128 KiB `BufReader`, starts its
/// output at four times the compressed size and grows it by doubling. The returned `Bytes` keeps
/// that whole capacity, and every value the response decoder slices out of it keeps it alive.
/// For an incompressible 32 MiB blob, that is a 128 MiB allocation.
///
/// A zstd encoder that knows its input size up front, like connectrpc's, writes that size into
/// the frame header. When the input is exactly one such frame and the size fits the limit, this
/// codec reserves exactly that much and decompresses in one call. Everything else goes to
/// connectrpc, so it gets connectrpc's result and error.
#[derive(Default)]
pub(crate) struct ZstdCodec(ZstdProvider);

impl ZstdCodec {
    pub(crate) fn with_level(level: i32) -> Self {
        Self(ZstdProvider::with_level(level))
    }
}

impl CompressionProvider for ZstdCodec {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn compress(&self, data: &[u8]) -> Result<Bytes, ConnectError> {
        self.0.compress(data)
    }

    fn decompressor<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<Box<dyn std::io::Read + 'a>, ConnectError> {
        self.0.decompressor(data)
    }

    fn decompress_with_limit(&self, data: &[u8], max_size: usize) -> Result<Bytes, ConnectError> {
        match lone_frame_size(data) {
            Some(size) if size <= max_size => decompress_exact(data, size),
            // This includes a header that claims more than the limit, which connectrpc decodes
            // only as far as the limit (or refuses earlier, if the frame's window is too large).
            _ => self.0.decompress_with_limit(data, max_size),
        }
    }
}

/// The most bytes a zstd block decompresses to.
const MAX_BLOCK_SIZE: usize = 128 * 1024;

/// The content size `data` records, if `data` is exactly one frame, its header records a size,
/// and the frame could hold that much.
///
/// Every block takes at least 3 bytes and holds at most [`MAX_BLOCK_SIZE`], so a header that
/// claims more than that bound is lying. Leaving such a frame to connectrpc keeps a small body
/// from making this codec reserve a large buffer.
fn lone_frame_size(data: &[u8]) -> Option<usize> {
    let size = usize::try_from(get_frame_content_size(data).ok().flatten()?).ok()?;
    let possible = data.len().div_ceil(3).saturating_mul(MAX_BLOCK_SIZE);
    let lone = || find_frame_compressed_size(data).is_ok_and(|len| len == data.len());
    (size <= possible && lone()).then_some(size)
}

/// Decompresses a lone frame into a buffer of exactly the `size` its header records.
///
/// A frame that holds more than it claims fails when the buffer is full, and one that holds less
/// fails zstd's own check of the claimed size. connectrpc's streaming decoder skips that second
/// check when the frame ends in an empty block, so it returns such a frame's short content where
/// this fails it. One-shot decoding writes straight into the output, so unlike the streaming
/// decoder it needs no window buffer and isn't held to its 128 MiB window limit.
fn decompress_exact(data: &[u8], size: usize) -> Result<Bytes, ConnectError> {
    let mut output = Vec::new();
    output.try_reserve_exact(size).map_err(|_| {
        ConnectError::resource_exhausted(format!("cannot allocate {size} bytes to decompress zstd"))
    })?;
    decompress(&mut output, data).map_err(|code| {
        // Worded like connectrpc's error for a frame it can't decode.
        ConnectError::invalid_argument(format!(
            "zstd decompression failed: {}",
            get_error_name(code)
        ))
    })?;
    Ok(Bytes::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use connectrpc::ErrorCode;

    const LIMIT: usize = 64 * 1024 * 1024;

    /// A one-frame payload of 1,024 bytes whose header asks for a 256 MiB window, more than
    /// connectrpc's streaming decoder allows. The server's Put decoder rejects it too.
    const OVERSIZED_WINDOW_FRAME: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x40, 0x90, 0x00, 0x03, 0x7d, 0x00, 0x00, 0x40, 0x0a, 0x06, 0x0a,
        0x01, 0x61, 0x12, 0x01, 0x62, 0x01, 0x00, 0xf5, 0x57, 0x15, 0x2e,
    ];

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

    /// Decodes `input` with the codec and with connectrpc's provider, checks that both give the
    /// same bytes or the same error code and message, and returns the codec's result.
    fn decode_like_connectrpc(input: &[u8], limit: usize) -> Result<Bytes, ConnectError> {
        let ours = ZstdCodec::default().decompress_with_limit(input, limit);
        let stock = ZstdProvider::default().decompress_with_limit(input, limit);
        match (&ours, &stock) {
            (Ok(ours), Ok(stock)) => assert_eq!(ours, stock),
            (Err(ours), Err(stock)) => {
                assert_eq!(ours.code, stock.code);
                assert_eq!(ours.message, stock.message);
            }
            _ => panic!("codec returned {ours:?}, connectrpc returned {stock:?}"),
        }
        ours
    }

    /// A 16-byte single-segment frame that claims `size` bytes and holds an empty last block.
    fn empty_frame_claiming(size: u64) -> Vec<u8> {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xe0];
        frame.extend_from_slice(&size.to_le_bytes());
        frame.extend_from_slice(&[0x01, 0x00, 0x00]);
        frame
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
        let codec = ZstdCodec::default();
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
            let decompressed = decode_like_connectrpc(&compressed, LIMIT).unwrap();
            assert_eq!(decompressed, payload);
            if !payload.is_empty() {
                assert_eq!(capacity(decompressed), payload.len());
            }
        }
    }

    #[test]
    fn content_size_over_limit_fails_like_connectrpc() {
        let payload = compressible(100_000);
        let compressed = ZstdCodec::default().compress(&payload).unwrap();
        assert_eq!(
            decode_like_connectrpc(&compressed, payload.len()).unwrap(),
            payload
        );
        assert_eq!(
            error_code(decode_like_connectrpc(&compressed, payload.len() - 1)),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn lying_content_sizes_fail_like_connectrpc() {
        let frame = ZstdCodec::default()
            .compress(&compressible(100_000))
            .unwrap();

        // Holds more than it claims, and more than the limit. Decoding stops when the claimed
        // 50,000 bytes are full.
        let short = with_content_size(&frame, 50_000);
        assert!(lone_frame_size(&short).is_some());
        assert_eq!(
            error_code(decode_like_connectrpc(&short, 60_000)),
            ErrorCode::InvalidArgument
        );
        // Holds less than it claims.
        let long = with_content_size(&frame, 150_000);
        assert!(lone_frame_size(&long).is_some());
        assert_eq!(
            error_code(decode_like_connectrpc(&long, LIMIT)),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn rejects_some_lies_connectrpc_misses() {
        use std::io::Write;

        // zstd's streaming encoder ends a flushed frame with an empty block. connectrpc's
        // streaming decoder doesn't check the claimed size after an empty last block, so it
        // returns the 100,000 bytes this frame holds instead of the 150,000 it claims.
        let payload = compressible(100_000);
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        encoder
            .set_pledged_src_size(Some(payload.len() as u64))
            .unwrap();
        encoder.include_contentsize(true).unwrap();
        encoder.write_all(&payload).unwrap();
        encoder.flush().unwrap();
        let frame = encoder.finish().unwrap();
        assert_eq!(decode_like_connectrpc(&frame, LIMIT).unwrap(), payload);
        let long = with_content_size(&frame, 150_000);
        assert_eq!(
            ZstdProvider::default()
                .decompress_with_limit(&long, LIMIT)
                .unwrap(),
            payload
        );
        let error = ZstdCodec::default()
            .decompress_with_limit(&long, LIMIT)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(
            error.message.as_deref(),
            Some("zstd decompression failed: Data corruption detected")
        );

        // A frame that claims 0 bytes but holds 5 fails with the same code as in connectrpc,
        // and a different message.
        let mut hello = ZstdCodec::default().compress(b"hello").unwrap().to_vec();
        assert_eq!(hello[4], 0x20, "single segment, 1-byte content size");
        hello[5] = 0;
        assert!(lone_frame_size(&hello).is_some());
        let ours = ZstdCodec::default()
            .decompress_with_limit(&hello, LIMIT)
            .unwrap_err();
        let stock = ZstdProvider::default()
            .decompress_with_limit(&hello, LIMIT)
            .unwrap_err();
        assert_eq!(ours.code, ErrorCode::InvalidArgument);
        assert_eq!(ours.code, stock.code);
        assert_eq!(
            ours.message.as_deref(),
            Some("zstd decompression failed: Destination buffer is too small")
        );
        assert_eq!(
            stock.message.as_deref(),
            Some("zstd decompression failed: Data corruption detected")
        );
    }

    #[test]
    fn claims_a_frame_could_not_hold_go_to_connectrpc() {
        // 16 bytes hold at most 6 blocks of 128 KiB.
        let possible = 6 * MAX_BLOCK_SIZE as u64;
        assert!(lone_frame_size(&empty_frame_claiming(possible)).is_some());
        assert!(lone_frame_size(&empty_frame_claiming(possible + 1)).is_none());

        // Without the bound, these would reserve 100 MiB and 200 MiB before failing.
        // connectrpc returns nothing for the first (its window fits) and refuses the window of
        // the second.
        let limit = 256 * 1024 * 1024;
        assert!(
            decode_like_connectrpc(&empty_frame_claiming(100 << 20), limit)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            decode_like_connectrpc(&empty_frame_claiming(200 << 20), limit)
                .unwrap_err()
                .message
                .as_deref(),
            Some("zstd decompression failed: Frame requires too much memory for decoding")
        );
    }

    #[test]
    fn claims_over_the_limit_fail_like_connectrpc() {
        // Claims 2 GiB. connectrpc refuses its window before decoding anything.
        let frame = ZstdCodec::default()
            .compress(&compressible(100_000))
            .unwrap();
        let huge = with_content_size(&frame, 1 << 31);
        assert_eq!(
            error_code(decode_like_connectrpc(&huge, LIMIT)),
            ErrorCode::InvalidArgument
        );

        // An empty frame that claims 256 MiB + 1 bytes. kv-mk1's ingest tests expect this exact
        // error from the registry at the request limit.
        let pledge = empty_frame_claiming((256 << 20) + 1);
        let error =
            decode_like_connectrpc(&pledge, crate::limits::MAX_REQUEST_MESSAGE_BYTES).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(
            error.message.as_deref(),
            Some("zstd decompression failed: Frame requires too much memory for decoding")
        );
    }

    #[test]
    fn decodes_windows_the_streaming_decoder_refuses() {
        let stock = ZstdProvider::default()
            .decompress_with_limit(OVERSIZED_WINDOW_FRAME, LIMIT)
            .unwrap_err();
        assert_eq!(
            stock.message.as_deref(),
            Some("zstd decompression failed: Frame requires too much memory for decoding")
        );
        let decompressed = ZstdCodec::default()
            .decompress_with_limit(OVERSIZED_WINDOW_FRAME, LIMIT)
            .unwrap();
        assert_eq!(decompressed.len(), 1024);
        // Over the limit, the frame goes to connectrpc and gets its window error.
        assert_eq!(
            decode_like_connectrpc(OVERSIZED_WINDOW_FRAME, 1023)
                .unwrap_err()
                .message,
            stock.message
        );
    }

    #[test]
    fn frames_without_content_size_decode_like_connectrpc() {
        let payload = compressible(1024 * 1024);
        let mut compressor = zstd::bulk::Compressor::new(3).unwrap();
        compressor.include_contentsize(false).unwrap();
        let frame = compressor.compress(&payload).unwrap();
        assert_eq!(get_frame_content_size(&frame).unwrap(), None);

        assert_eq!(decode_like_connectrpc(&frame, LIMIT).unwrap(), payload);
        assert_eq!(
            decode_like_connectrpc(&frame, payload.len()).unwrap(),
            payload
        );
        assert_eq!(
            error_code(decode_like_connectrpc(&frame, payload.len() - 1)),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn several_frames_decode_like_connectrpc() {
        let codec = ZstdCodec::default();
        let first = compressible(100_000);
        let second = random(50_000);
        let skippable = [0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 1, 2, 3, 4];
        let mut input = codec.compress(&first).unwrap().to_vec();
        input.extend_from_slice(&skippable);
        input.extend_from_slice(&codec.compress(&second).unwrap());
        let expected = [first, second].concat();

        assert_eq!(decode_like_connectrpc(&input, LIMIT).unwrap(), expected);
        for limit in [expected.len() - 1, 100_000] {
            assert_eq!(
                error_code(decode_like_connectrpc(&input, limit)),
                ErrorCode::ResourceExhausted
            );
        }
        // A lone skippable frame records a content size of zero and decodes to nothing.
        assert!(decode_like_connectrpc(&skippable, LIMIT)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn malformed_input_fails_like_connectrpc() {
        let frame = ZstdCodec::default()
            .compress(&compressible(100_000))
            .unwrap();

        // Input that isn't one whole frame goes to connectrpc.
        let truncated = &frame[..frame.len() - 3];
        let trailing = [&frame[..], &[0xaa; 8]].concat();
        for input in [&b"not zstd"[..], truncated, &trailing] {
            assert!(lone_frame_size(input).is_none());
            assert_eq!(
                error_code(decode_like_connectrpc(input, LIMIT)),
                ErrorCode::InvalidArgument
            );
        }

        // A whole frame with a size is decoded here, and fails the way connectrpc fails it.
        let mut corrupt = frame.to_vec();
        let middle = corrupt.len() / 2;
        corrupt[middle] ^= 0xff;
        let mut compressor = zstd::bulk::Compressor::new(3).unwrap();
        compressor.include_checksum(true).unwrap();
        let mut bad_checksum = compressor.compress(&compressible(10_000)).unwrap();
        *bad_checksum.last_mut().unwrap() ^= 1;
        // One raw byte, compressed with dictionary 1.
        let dictionary = [
            0x28, 0xb5, 0x2f, 0xfd, 0x21, 0x01, 0x01, 0x09, 0x00, 0x00, b'x',
        ];
        for (input, message) in [
            (&corrupt[..], "Data corruption detected"),
            (&bad_checksum, "Restored data doesn't match checksum"),
            (&dictionary, "Dictionary mismatch"),
        ] {
            assert!(lone_frame_size(input).is_some());
            assert_eq!(
                decode_like_connectrpc(input, LIMIT).unwrap_err().message,
                Some(format!("zstd decompression failed: {message}"))
            );
        }
    }
}
