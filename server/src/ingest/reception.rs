use std::mem::size_of;

use bytes::Bytes;
use connectrpc::ConnectError;

use super::input::FRAME_WORK_BUDGET;
use super::zstd::WINDOW_LOG_MAX;
use super::{DecodeBuffers, EntryRanges, PutLimits};

// Allow room for request controls and allocation owners beyond their payload charges.
const PROTOCOL_WORKSPACE_BYTES: usize = 1024 * 1024;

/// Conservative memory allowance for one Put reception and one returned chunk.
/// Pass the enforced limits and the largest buffer capacities used by the backend.
/// Add backend preparation and older retained chunk storage separately. This includes
/// decoder storage, but excludes listener and storage-engine memory.
pub fn maximum_reception_bytes(
    limits: PutLimits,
    buffers: &DecodeBuffers,
) -> Result<usize, ConnectError> {
    let payload = payload_bytes(limits, buffers)?;
    let decoder = maximum_decoder_bytes()?;
    add(payload, decoder)
}

fn payload_bytes(limits: PutLimits, buffers: &DecodeBuffers) -> Result<usize, ConnectError> {
    if buffers.byte_capacity == 0 || buffers.entry_capacity == 0 {
        return Err(ConnectError::internal(
            "decode buffer capacities must be positive",
        ));
    }

    // Transport admission remains held while exact copies reach the decoder.
    let wire = mul(limits.wire_bytes, 2)?;

    // Large fields can outgrow the requested byte capacity to the message limit.
    // Cover a returned chunk, the current arena, and replacement allocation overlap.
    let arenas = mul(limits.message_bytes.max(1), 3)?;

    // Returning a chunk transfers its range allocation. The next decode allocates another.
    let entries = buffers.entry_capacity.min(limits.ingest.max_entries).max(1);
    let ranges = mul(mul(entries, size_of::<EntryRanges>())?, 2)?;
    let frames = mul(FRAME_WORK_BUDGET - 1, size_of::<Bytes>())?;
    add(
        add(wire, arenas)?,
        add(add(ranges, frames)?, PROTOCOL_WORKSPACE_BYTES)?,
    )
}

fn maximum_decoder_bytes() -> Result<usize, ConnectError> {
    let window = 1usize.checked_shl(WINDOW_LOG_MAX).ok_or_else(overflow)?;

    // Accepted frames can request the maximum window even with a tiny size pledge.
    let estimate = unsafe { zstd::zstd_safe::zstd_sys::ZSTD_estimateDStreamSize(window) };
    if unsafe { zstd::zstd_safe::zstd_sys::ZSTD_isError(estimate) } != 0 {
        return Err(ConnectError::internal(format!(
            "cannot estimate Put zstd workspace. {}",
            zstd::zstd_safe::get_error_name(estimate)
        )));
    }

    Ok(estimate)
}

fn add(left: usize, right: usize) -> Result<usize, ConnectError> {
    left.checked_add(right).ok_or_else(overflow)
}

fn mul(left: usize, right: usize) -> Result<usize, ConnectError> {
    left.checked_mul(right).ok_or_else(overflow)
}

fn overflow() -> ConnectError {
    ConnectError::resource_exhausted("Put reception memory estimate overflow")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use buffa::Message as _;
    use exoware_sdk::{common::Entry, ingest::PutRequest};
    use http_body_util::Full;
    use tokio::time::Instant;

    use super::*;
    use crate::ingest::{box_body, BudgetConfig, IngestBudget, PutEncoding, PutInput, PutMetadata};

    #[tokio::test]
    async fn allowance_admits_growth_and_overlapping_chunks() {
        let request = PutRequest {
            kvs: (0..802)
                .map(|index| Entry {
                    key: b"key".to_vec(),
                    value: if index == 0 {
                        Bytes::from(vec![7; 2 * 1024 * 1024])
                    } else {
                        Bytes::from_static(b"small")
                    },
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let payload = request.encode_to_vec();
        for encoding in [PutEncoding::Identity, PutEncoding::Zstd] {
            let wire = match encoding {
                PutEncoding::Identity => payload.clone(),
                PutEncoding::Zstd => zstd::bulk::compress(&payload, 1).unwrap(),
            };
            for buffers in [
                DecodeBuffers::new(128, 4),
                DecodeBuffers::new(payload.len() + 64, 4096),
            ] {
                let limits = PutLimits {
                    wire_bytes: wire.len(),
                    message_bytes: payload.len() + 19,
                    ..PutLimits::default()
                };

                // Identity cannot borrow unused native allowance to hide a payload undercount.
                let allowance = match encoding {
                    PutEncoding::Identity => payload_bytes(limits, &buffers).unwrap(),
                    PutEncoding::Zstd => {
                        let frame = super::super::zstd::frame_decoder_memory_bytes(
                            &wire[..wire.len().min(18)],
                        )
                        .unwrap();
                        assert!(frame as usize <= maximum_decoder_bytes().unwrap());
                        maximum_reception_bytes(limits, &buffers).unwrap()
                    }
                };
                let budget = IngestBudget::new(BudgetConfig {
                    max_requests: 1,
                    max_bytes: allowance,
                });
                let mut input = PutInput::new(
                    box_body(Full::new(Bytes::from(wire.clone()))),
                    PutMetadata {
                        encoding,
                        content_length: Some(wire.len()),
                    },
                    limits,
                    Instant::now() + Duration::from_secs(10),
                    budget.try_admit(wire.len()).unwrap(),
                );
                let (mut previous, mut count, mut peak) = (None, 0, 0);
                while let Some(chunk) = input.next_batch(buffers).await.unwrap() {
                    peak = peak.max(budget.usage().1);
                    count += chunk.ranges().len();
                    previous = Some(chunk);
                }
                assert_eq!(count, request.kvs.len());
                assert!(peak > wire.len() + 2 * 1024 * 1024);
                input.finish().await.unwrap();
                drop(input);
                assert_eq!(budget.usage().0, 1);
                drop(previous);
                assert_eq!(budget.usage(), (0, 0));
            }
        }
    }

    #[test]
    fn invalid_capacities_and_overflow_return_errors() {
        let limits = PutLimits::default();
        for buffers in [DecodeBuffers::new(0, 1), DecodeBuffers::new(1, 0)] {
            assert!(maximum_reception_bytes(limits, &buffers).is_err());
        }
        for limits in [
            PutLimits {
                wire_bytes: usize::MAX,
                ..limits
            },
            PutLimits {
                message_bytes: usize::MAX,
                ..limits
            },
            PutLimits {
                ingest: crate::IngestLimits {
                    max_entries: usize::MAX,
                    ..limits.ingest
                },
                ..limits
            },
        ] {
            let error =
                maximum_reception_bytes(limits, &DecodeBuffers::new(1, usize::MAX)).unwrap_err();
            assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
        }
    }
}
