use std::{convert::Infallible, sync::Arc, time::Duration};

use buffa::{
    encoding::{Tag, WireType},
    MessageView as _,
};
use bytes::Bytes;
use connectrpc::ConnectError;
use exoware_sdk::log::ingest::v1::PutRequestView;
use http_body::Frame;
use http_body_util::StreamBody;
use tokio::time::Instant;

use super::{
    box_body, BudgetConfig, DecodeBuffers, DecodeExecutor, DecodeOutput, DecodeState, IngestBudget,
    PutEncoding, PutError, PutInput, PutLimits, PutMetadata,
};
use crate::validate::IngestLimits;

// Running the production decoder inline keeps the short corpus independent of thread scheduling.
struct InlineExecutor;

impl DecodeExecutor for InlineExecutor {
    fn execute(
        &self,
        state: DecodeState,
        buffers: DecodeBuffers,
    ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
        Box::pin(async move { Ok(state.run(buffers)) })
    }
}

fn bytes_field(number: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    Tag::new(number, WireType::LengthDelimited).encode(&mut wire);
    buffa::encoding::encode_varint(payload.len() as u64, &mut wire);
    wire.extend_from_slice(payload);
    wire
}

fn entry(key: &[u8], value: &[u8]) -> Vec<u8> {
    bytes_field(1, &[bytes_field(1, key), bytes_field(2, value)].concat())
}

async fn parse(wire: &[u8], limits: IngestLimits) -> Result<Vec<(Bytes, Bytes)>, ConnectError> {
    parse_fragmented(wire, limits, wire.len().max(1)).await
}

async fn parse_fragmented(
    wire: &[u8],
    limits: IngestLimits,
    split: usize,
) -> Result<Vec<(Bytes, Bytes)>, ConnectError> {
    let frames = wire
        .chunks(split)
        .map(|bytes| Ok::<_, Infallible>(Frame::data(Bytes::copy_from_slice(bytes))))
        .collect::<Vec<_>>();
    let budget = IngestBudget::new(BudgetConfig {
        max_requests: 1,
        max_bytes: 64 * 1024 * 1024,
    });
    let admission = budget.try_admit(wire.len()).unwrap();
    let mut input = PutInput::new(
        box_body(StreamBody::new(futures::stream::iter(frames))),
        PutMetadata {
            encoding: PutEncoding::Identity,
            content_length: Some(wire.len()),
        },
        PutLimits {
            ingest: limits,
            ..PutLimits::default()
        },
        Instant::now() + Duration::from_secs(30),
        admission,
    );
    input.set_executor(Arc::new(InlineExecutor));
    let mut entries = Vec::new();
    while let Some(chunk) = input
        .next_batch(DecodeBuffers::new(4096, 2))
        .await
        .map_err(PutError::into_connect)?
    {
        entries.extend(chunk.ranges().iter().map(|range| {
            (
                chunk.data.slice(range.key.clone()),
                chunk.data.slice(range.value.clone()),
            )
        }));
    }
    input.finish().await.map_err(PutError::into_connect)?;
    assert!(input.is_finished());
    drop(input);
    Ok(entries)
}

async fn assert_matches_generated(wire: &[u8], limits: IngestLimits) {
    let expected = PutRequestView::decode_view(wire)
        .map_err(|error| {
            ConnectError::invalid_argument(format!("failed to decode proto request: {error}"))
        })
        .and_then(|view| {
            crate::validate::validate_put_request(&view, limits)?;
            Ok(view
                .kvs
                .iter()
                .map(|entry| {
                    (
                        Bytes::copy_from_slice(entry.key),
                        Bytes::copy_from_slice(entry.value),
                    )
                })
                .collect::<Vec<_>>())
        });
    for split in [
        wire.len().max(1),
        if wire.len() <= 256 { 1 } else { wire.len() },
    ] {
        let actual = parse_fragmented(wire, limits, split.max(1)).await;
        match (&actual, &expected) {
            (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
            (Err(actual), Err(expected)) => {
                assert_eq!(
                    exoware_sdk::decode_connect_error(actual).unwrap(),
                    exoware_sdk::decode_connect_error(expected).unwrap(),
                    "wire length {}, split {}",
                    wire.len(),
                    split,
                );
            }
            (actual, expected) => panic!("parser {actual:?}, generated {expected:?}"),
        }
    }
}

#[tokio::test]
async fn entries_preserve_order_duplicates_and_omissions() {
    let repeated = [
        bytes_field(1, b"first"),
        bytes_field(2, b"old"),
        bytes_field(1, b"last"),
        bytes_field(2, b"new"),
    ]
    .concat();
    let wire = Bytes::from(
        [
            bytes_field(1, &repeated),
            bytes_field(1, &[]),
            entry(b"last", b"again"),
            bytes_field(1, &bytes_field(2, b"value only")),
            bytes_field(1, &bytes_field(1, b"key only")),
        ]
        .concat(),
    );
    assert_matches_generated(&wire, IngestLimits::default()).await;
    let parsed = parse(&wire, IngestLimits::default()).await.unwrap();
    assert_eq!(parsed.len(), 5);
    assert_eq!(
        parsed[0],
        (Bytes::from_static(b"last"), Bytes::from_static(b"new"))
    );
    assert_eq!(parsed[1], (Bytes::new(), Bytes::new()));
}

#[tokio::test]
async fn duplicate_fields_validate_only_the_last_value() {
    let limits = IngestLimits {
        max_entries: 1,
        max_value_len: 3,
    };
    let oversized = [bytes_field(1, &[b'k'; 255]), bytes_field(2, b"long")].concat();
    let valid = [bytes_field(1, b"key"), bytes_field(2, b"val")].concat();
    for inner in [
        [oversized.clone(), valid.clone()].concat(),
        [valid, oversized].concat(),
    ] {
        assert_matches_generated(&bytes_field(1, &inner), limits).await;
    }
}

#[tokio::test]
async fn unknown_wire_types_are_accepted_at_request_and_entry_levels() {
    let unknown = [
        vec![0x18, 0xff, 0x01],
        vec![0x21, 0, 1, 2, 3, 4, 5, 6, 7],
        bytes_field(5, &[0, 0xff, 0x80]),
        vec![0x35, 0, 1, 2, 3],
        vec![0x3b, 0x08, 0, 0x3c],
    ]
    .concat();
    let inner = [
        bytes_field(1, b"key"),
        unknown.clone(),
        bytes_field(2, b"value"),
    ]
    .concat();
    let wire = [unknown, bytes_field(1, &inner)].concat();
    assert_matches_generated(&wire, IngestLimits::default()).await;
}

#[tokio::test]
async fn malformed_wire_matches_generated_decoder() {
    let mut cases = vec![
        vec![],
        vec![0],
        vec![0x0e],
        vec![0x08, 0],
        vec![0x0c],
        vec![0x14],
        vec![0x13, 0x1c],
        vec![0x13],
        vec![0x80],
        vec![0x0a, 0x80],
        vec![0x0a, 2, 0x0a],
        vec![0x0a, 2, 0x0a, 4],
        bytes_field(1, &[0x08, 0]),
        bytes_field(1, &[0x13, 0x1c]),
        bytes_field(1, &[0x1b, 0x24]),
        bytes_field(1, &[0x1b]),
        bytes_field(1, &[0x1a, 10, 0]),
        vec![0xff; 10],
        vec![0x80, 0x80, 0x80, 0x80, 0x10],
    ];
    for field in [0x0a, 0x10, 0x1a] {
        for tail in [vec![0x80; 10], [vec![0xff; 9], vec![2]].concat()] {
            cases.push([vec![field], tail.clone()].concat());
            cases.push(bytes_field(1, &[vec![field], tail].concat()));
        }
    }
    for unknown in [vec![0x11, 0], vec![0x1d, 0], vec![0x1a, 4, 0]] {
        cases.push(unknown.clone());
        cases.push(bytes_field(1, &unknown));
    }
    for wire in cases {
        assert_matches_generated(&wire, IngestLimits::default()).await;
    }
}

#[tokio::test]
async fn truncated_fields_match_generated_errors_at_each_boundary() {
    for wire in [
        vec![0x0a],
        vec![0x0a, 3, 0x0a, 1],
        vec![0x13, 0x18, 0],
        bytes_field(1, &[0x0a]),
        bytes_field(1, &[0x0a, 3, 0]),
        bytes_field(1, &[0x1b, 0x20, 0]),
    ] {
        assert_matches_generated(&wire, IngestLimits::default()).await;
        assert!(parse(&wire, IngestLimits::default()).await.is_err());
    }
}

fn groups(depth: usize) -> Vec<u8> {
    [vec![0x1b; depth], vec![0x1c; depth]].concat()
}

#[tokio::test]
async fn entry_depth_consumes_one_recursion_level() {
    for depth in [98, 99, 100, 101] {
        for (wire, valid) in [
            ([groups(depth), entry(b"a", b"b")].concat(), depth <= 100),
            (bytes_field(1, &groups(depth)), depth < 100),
        ] {
            assert_matches_generated(&wire, IngestLimits::default()).await;
            assert_eq!(parse(&wire, IngestLimits::default()).await.is_ok(), valid);
        }
    }
}

#[tokio::test]
async fn unknown_allowance_is_shared_across_all_levels() {
    let mut wire = [0x10, 0].repeat(250_000);
    wire.extend(bytes_field(1, &[0x18, 0].repeat(250_000)));
    let group = [vec![0x1b], [0x20, 0].repeat(499_999), vec![0x1c]].concat();
    wire.extend(bytes_field(1, &group));
    assert_matches_generated(&wire, IngestLimits::default()).await;
    assert!(parse(&wire, IngestLimits::default()).await.is_ok());
    wire.extend_from_slice(&[0x10, 0]);
    assert_matches_generated(&wire, IngestLimits::default()).await;
    let error = parse(&wire, IngestLimits::default()).await.unwrap_err();
    assert_eq!(
        error.message.as_deref(),
        Some("failed to decode proto request: unknown field limit exceeded")
    );

    let top = [0x10, 0].repeat(buffa::DEFAULT_UNKNOWN_FIELD_LIMIT + 1);
    assert_eq!(
        parse(&top, IngestLimits::default())
            .await
            .unwrap_err()
            .message,
        error.message
    );
}

#[tokio::test]
async fn unknown_length_delimited_payload_is_opaque_and_uses_one_slot() {
    let mut wire = [0x10, 0].repeat(buffa::DEFAULT_UNKNOWN_FIELD_LIMIT - 1);
    wire.extend(bytes_field(3, &vec![0xff; 1_000_001]));
    wire.extend(entry(b"a", b"b"));
    assert_matches_generated(&wire, IngestLimits::default()).await;
    assert!(parse(&wire, IngestLimits::default()).await.is_ok());
    wire.extend_from_slice(&[0x10, 0]);
    assert_matches_generated(&wire, IngestLimits::default()).await;
    assert!(parse(&wire, IngestLimits::default()).await.is_err());
}

#[tokio::test]
async fn validation_matches_generated_details_and_retains_first_failure() {
    let limits = IngestLimits {
        max_entries: 2,
        max_value_len: 3,
    };
    let bad_key = entry(&[b'k'; 255], b"x");
    let bad_value = entry(b"k", b"long");
    for wire in [
        vec![],
        entry(&[b'k'; 254], b"abc"),
        bad_key.clone(),
        bad_value.clone(),
        [bad_key.clone(), bad_value.clone()].concat(),
        [bad_value.clone(), bad_key.clone()].concat(),
        [bad_key.clone(), entry(b"a", b"b"), bad_value.clone()].concat(),
    ] {
        assert_matches_generated(&wire, limits).await;
    }
    for tail in [vec![0], vec![0x80], bytes_field(1, &[0x0a])] {
        let wire = [bad_key.clone(), tail].concat();
        assert_matches_generated(&wire, limits).await;
        assert!(parse(&wire, limits).await.unwrap_err().details.is_empty());
    }
}

#[tokio::test]
async fn short_wire_corpus_matches_generated_decoder() {
    let limits = IngestLimits {
        max_entries: 4,
        max_value_len: 8,
    };
    for first in 0..=u8::MAX {
        assert_matches_generated(&[first], limits).await;
        for second in [0, 1, 0x0a, 0x10, 0x13, 0x14, 0x7f, 0x80, 0xff] {
            assert_matches_generated(&[first, second], limits).await;
            assert_matches_generated(&bytes_field(1, &[first, second]), limits).await;
        }
    }
}

#[tokio::test]
async fn entry_count_precedes_inner_decode_and_value_validation() {
    let limits = IngestLimits {
        max_entries: 1,
        max_value_len: 1,
    };
    let expected = crate::validate::validate_put_count(3, limits).unwrap_err();
    for wire in [
        [
            bytes_field(1, &[0x0a]),
            bytes_field(1, &[0x0a]),
            entry(b"c", b"d"),
        ]
        .concat(),
        [
            entry(b"a", b"long"),
            bytes_field(1, &[0x0a]),
            entry(b"c", b"d"),
        ]
        .concat(),
    ] {
        for split in [1, wire.len()] {
            let actual = parse_fragmented(&wire, limits, split).await.unwrap_err();
            assert_eq!(
                exoware_sdk::decode_connect_error(&actual).unwrap(),
                exoware_sdk::decode_connect_error(&expected).unwrap()
            );
        }
        let malformed_outer = [wire, vec![0x80]].concat();
        let actual = parse(&malformed_outer, limits).await.unwrap_err();
        assert_eq!(
            actual.message.as_deref(),
            Some("failed to decode proto request: unexpected end of buffer")
        );
        assert!(actual.details.is_empty());
    }
}

#[tokio::test]
async fn malformed_outer_field_precedes_malformed_inner_field() {
    let wire = [0x0a, 1, 0x0a, 0];
    for split in [1, wire.len()] {
        let error = parse_fragmented(&wire, IngestLimits::default(), split)
            .await
            .unwrap_err();
        assert_eq!(
            error.message.as_deref(),
            Some("failed to decode proto request: invalid field number")
        );
        assert!(error.details.is_empty());
    }
}

#[tokio::test]
async fn declared_field_length_beyond_the_decoded_bound_does_not_reserve_the_message_limit() {
    // Field 1 declares a 268,435,455 byte payload inside a ten byte body.
    let wire = [0x0a, 0xff, 0xff, 0xff, 0x7f, 1, 2, 3, 4, 5];
    for encoding in [PutEncoding::Identity, PutEncoding::Zstd] {
        let body = match encoding {
            PutEncoding::Identity => wire.to_vec(),
            PutEncoding::Zstd => ::zstd::bulk::compress(&wire, 1).unwrap(),
        };
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 64 * 1024 * 1024,
        });
        let admission = budget.try_admit(body.len()).unwrap();
        let mut input = PutInput::new(
            box_body(http_body_util::Full::new(Bytes::from(body.clone()))),
            PutMetadata {
                encoding,
                content_length: Some(body.len()),
            },
            PutLimits::default(),
            Instant::now() + Duration::from_secs(30),
            admission,
        );
        input.set_executor(Arc::new(InlineExecutor));
        let mut peak = 0;
        let result = loop {
            match input.next_batch(DecodeBuffers::default()).await {
                Ok(Some(_)) => peak = peak.max(budget.usage().1),
                Ok(None) => break input.finish().await,
                Err(error) => break Err(error),
            }
        };
        peak = peak.max(budget.usage().1);
        let error = result.unwrap_err().into_connect();
        assert_eq!(
            error.code,
            connectrpc::ErrorCode::InvalidArgument,
            "{encoding:?}: {error:?}"
        );
        assert_eq!(
            error.message.as_deref(),
            Some("failed to decode proto request: unexpected end of buffer"),
            "{encoding:?}"
        );
        // The zstd workspace reservation is bounded by the frame header, not by the field length.
        assert!(
            peak < 16 * 1024 * 1024,
            "{encoding:?}: peak reservation {peak} bytes for a {} byte body",
            body.len()
        );
    }
}
