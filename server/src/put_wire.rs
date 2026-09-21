use buffa::encoding::{check_wire_type, skip_field_depth, Tag, WireType};
use buffa::DecodeError;
use bytes::Bytes;
use connectrpc::ConnectError;
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::Deserialize;

use crate::validate::{validate_put_entry, IngestLimits};

/// Distinguishes input that can be resumed from invalid Put data.
#[derive(Debug, thiserror::Error)]
pub enum PutParseError {
    /// More input may complete the current top-level field.
    #[error("failed to decode proto request: unexpected end of buffer")]
    Incomplete,
    /// Additional input cannot repair the wire structure.
    #[error("{0}")]
    Malformed(String),
}

impl From<DecodeError> for PutParseError {
    fn from(error: DecodeError) -> Self {
        Self::Malformed(format!("failed to decode proto request: {error}"))
    }
}

impl From<PutParseError> for ConnectError {
    fn from(error: PutParseError) -> Self {
        match error {
            PutParseError::Incomplete => {
                Self::invalid_argument("failed to decode proto request: unexpected end of buffer")
            }
            PutParseError::Malformed(message) => Self::invalid_argument(message),
        }
    }
}

/// Share one budget across top-level fields and decoded entries in a Put request.
pub struct UnknownBudget {
    remaining: usize,
}

impl Default for UnknownBudget {
    fn default() -> Self {
        Self {
            remaining: buffa::DEFAULT_UNKNOWN_FIELD_LIMIT,
        }
    }
}

impl UnknownBudget {
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    fn charge(&mut self) -> Result<(), DecodeError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(DecodeError::UnknownFieldLimitExceeded)?;
        Ok(())
    }
}

fn skip_unknown(
    tag: Tag,
    before_tag: &[u8],
    remaining: &mut &[u8],
    depth: u32,
    budget: &mut UnknownBudget,
) -> Result<(), DecodeError> {
    // Match the generated view's structural checks before charging a complete record.
    skip_field_depth(tag, remaining, depth)?;
    let mut record = &before_tag[..before_tag.len() - remaining.len()];
    while !record.is_empty() {
        let tag = Tag::decode(&mut record)?;
        if tag.wire_type() == WireType::EndGroup {
            continue;
        }
        budget.charge()?;
        if tag.wire_type() != WireType::StartGroup {
            skip_field_depth(tag, &mut record, depth)?;
        }
    }
    Ok(())
}

/// A complete top-level Put field returned without copying its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field<'a> {
    /// Entry payload without its enclosing tag and length.
    Entry(&'a [u8]),
    /// An unknown field that has been skipped and charged to the shared budget.
    Unknown,
}

/// Borrows buffered Put bytes while retaining incomplete fields for the next input buffer.
/// After consuming complete fields at body EOF, reject a non-empty [`Self::remaining`] or
/// final [`PutParseError::Incomplete`] with `ConnectError::from(PutParseError::Incomplete)`
/// to preserve the legacy unexpected end of buffer error.
pub struct PutEntryCursor<'a> {
    remaining: &'a [u8],
    original_len: usize,
}

impl<'a> PutEntryCursor<'a> {
    pub fn new(wire: &'a [u8]) -> Self {
        Self {
            remaining: wire,
            original_len: wire.len(),
        }
    }

    /// Bytes consumed since [`Self::new`]. Subtract an entry's length for its payload offset.
    pub fn consumed(&self) -> usize {
        self.original_len - self.remaining.len()
    }

    /// Preserve this unconsumed suffix when constructing a cursor over more input.
    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    /// Leaves both input and budget untouched on error so incomplete fields can be retried.
    /// `Ok(None)` means the current buffer is exhausted, not that the request has ended.
    pub fn next(&mut self, budget: &mut UnknownBudget) -> Result<Option<Field<'a>>, PutParseError> {
        if self.remaining.is_empty() {
            return Ok(None);
        }

        // Commit only complete fields so a later caller can retry the same cursor.
        let mut remaining = self.remaining;
        let mut next_budget = UnknownBudget {
            remaining: budget.remaining,
        };
        let decoded = (|| {
            let tag = Tag::decode(&mut remaining)?;
            if tag.field_number() == 1 {
                check_wire_type(tag, WireType::LengthDelimited)?;
                return buffa::types::borrow_bytes(&mut remaining).map(Field::Entry);
            }
            skip_unknown(
                tag,
                self.remaining,
                &mut remaining,
                buffa::RECURSION_LIMIT,
                &mut next_budget,
            )?;
            Ok(Field::Unknown)
        })();
        let field = decoded.map_err(|error| match error {
            DecodeError::UnexpectedEof => PutParseError::Incomplete,
            error => error.into(),
        })?;
        self.remaining = remaining;
        *budget = next_budget;
        Ok(Some(field))
    }
}

pub(crate) fn count_put_entries(wire: &[u8]) -> Result<usize, ConnectError> {
    let mut cursor = PutEntryCursor::new(wire);
    let mut budget = UnknownBudget::default();
    let mut count = 0;
    while let Some(field) = cursor.next(&mut budget)? {
        if matches!(field, Field::Entry(_)) {
            count += 1;
        }
    }
    Ok(count)
}

/// Decode a complete entry while charging unknown fields to its request's shared budget.
/// Fields that overrun the declared entry boundary are malformed, not incomplete.
pub fn decode_entry_with_budget<'a>(
    mut remaining: &'a [u8],
    budget: &mut UnknownBudget,
) -> Result<(&'a [u8], &'a [u8]), PutParseError> {
    let mut key = &remaining[..0];
    let mut value = key;
    while !remaining.is_empty() {
        let before_tag = remaining;
        let tag = Tag::decode(&mut remaining)?;
        match tag.field_number() {
            1 => {
                check_wire_type(tag, WireType::LengthDelimited)?;
                key = buffa::types::borrow_bytes(&mut remaining)?;
            }
            2 => {
                check_wire_type(tag, WireType::LengthDelimited)?;
                value = buffa::types::borrow_bytes(&mut remaining)?;
            }
            _ => skip_unknown(
                tag,
                before_tag,
                &mut remaining,
                buffa::RECURSION_LIMIT - 1,
                budget,
            )?,
        }
    }
    Ok((key, value))
}

pub(crate) fn parse_put_entries(
    wire: &Bytes,
    limits: IngestLimits,
    validated_count: usize,
) -> Result<Vec<(Bytes, Bytes)>, ConnectError> {
    // The dispatcher validates this count against the same immutable buffer before admission.
    let mut entries = Vec::with_capacity(validated_count);
    let mut validation = None;
    let mut cursor = PutEntryCursor::new(wire);
    let mut budget = UnknownBudget::default();
    let mut count = 0;
    while let Some(field) = cursor.next(&mut budget)? {
        let Field::Entry(entry) = field else {
            continue;
        };
        let index = count;
        count += 1;
        let (key, value) = decode_entry_with_budget(entry, &mut budget)?;

        // Finish decoding after validation fails so malformed wire retains precedence.
        if validation.is_none() {
            match validate_put_entry(index, key, value, limits) {
                Ok(()) => entries.push((wire.slice_ref(key), wire.slice_ref(value))),
                Err(error) => validation = Some(error),
            }
        }
    }
    if let Some(error) = validation {
        return Err(error);
    }
    Ok(entries)
}

pub(crate) fn count_put_entries_json(wire: &[u8]) -> Result<usize, ConnectError> {
    // Error reporting must not materialize entries before admission either.
    serde_json::from_slice::<RequestShape>(wire)
        .map(|shape| shape.kvs.0)
        .map_err(|error| ConnectError::invalid_argument(format!("failed to decode JSON: {error}")))
}

// Matching the generated struct derive preserves map and sequence JSON forms.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RequestShape {
    kvs: EntryCount,
}

#[derive(Default)]
struct EntryCount(usize);

impl<'de> Deserialize<'de> for EntryCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_option(CountVisitor)
    }
}

struct CountVisitor;

impl<'de> Visitor<'de> for CountVisitor {
    type Value = EntryCount;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an array of entries or null")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(EntryCount(0))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut count = 0;
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            count += 1;
        }
        Ok(EntryCount(count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::MessageView as _;
    use exoware_sdk::log::ingest::v1::{PutRequest, PutRequestView};

    use crate::validate::validate_put_count;

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

    fn parse(wire: &[u8], limits: IngestLimits) -> Result<Vec<(Bytes, Bytes)>, ConnectError> {
        // Compare malformed decoding even when admission would reject the outer structure first.
        let count = match count_put_entries(wire) {
            Ok(count) => {
                validate_put_count(count, limits)?;
                count
            }
            Err(_) => 0,
        };
        parse_put_entries(&Bytes::copy_from_slice(wire), limits, count)
    }

    fn assert_matches_generated(wire: &[u8], limits: IngestLimits) {
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
        let actual = parse(wire, limits);
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
            (Err(actual), Err(expected)) => {
                assert_eq!(
                    exoware_sdk::decode_connect_error(&actual).unwrap(),
                    exoware_sdk::decode_connect_error(&expected).unwrap(),
                    "wire length {}",
                    wire.len()
                );
            }
            (actual, expected) => panic!("parser {actual:?}, generated {expected:?}"),
        }
    }

    #[test]
    fn entries_preserve_order_duplicates_omissions_and_shared_storage() {
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
        assert_matches_generated(&wire, IngestLimits::default());
        assert_eq!(count_put_entries(&wire).unwrap(), 5);
        let parsed = parse_put_entries(&wire, IngestLimits::default(), 5).unwrap();
        assert_eq!(
            parsed[0],
            (Bytes::from_static(b"last"), Bytes::from_static(b"new"))
        );
        assert_eq!(parsed[1], (Bytes::new(), Bytes::new()));
        let begin = wire.as_ptr() as usize;
        let end = begin + wire.len();
        for (key, value) in parsed {
            for bytes in [key, value] {
                if !bytes.is_empty() {
                    let pointer = bytes.as_ptr() as usize;
                    assert!((begin..end).contains(&pointer));
                    assert!(pointer + bytes.len() <= end);
                }
            }
        }
    }

    #[test]
    fn duplicate_fields_validate_only_the_last_value() {
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
            assert_matches_generated(&bytes_field(1, &inner), limits);
        }
    }

    #[test]
    fn unknown_wire_types_are_accepted_at_request_and_entry_levels() {
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
        assert_eq!(count_put_entries(&wire).unwrap(), 1);
        assert_matches_generated(&wire, IngestLimits::default());
    }

    #[test]
    fn malformed_wire_matches_generated_decoder() {
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
            vec![0x0a, 1, 0x0a, 0],
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
            assert_matches_generated(&wire, IngestLimits::default());
        }
    }

    #[test]
    fn truncated_fields_match_generated_errors_at_each_boundary() {
        for wire in [vec![0x0a], vec![0x0a, 3, 0x0a, 1], vec![0x13, 0x18, 0]] {
            assert_matches_generated(&wire, IngestLimits::default());
            assert!(parse(&wire, IngestLimits::default()).is_err());
        }
        for entry in [vec![0x0a], vec![0x0a, 3, 0], vec![0x1b, 0x20, 0]] {
            let wire = bytes_field(1, &entry);
            assert_eq!(count_put_entries(&wire).unwrap(), 1);
            assert_matches_generated(&wire, IngestLimits::default());
            assert!(parse(&wire, IngestLimits::default()).is_err());
        }
    }

    fn groups(depth: usize) -> Vec<u8> {
        [vec![0x1b; depth], vec![0x1c; depth]].concat()
    }

    #[test]
    fn entry_depth_consumes_one_recursion_level() {
        for depth in [98, 99, 100, 101] {
            let top = [groups(depth), entry(b"a", b"b")].concat();
            let nested = bytes_field(1, &groups(depth));
            assert_matches_generated(&top, IngestLimits::default());
            assert_matches_generated(&nested, IngestLimits::default());
            assert_eq!(parse(&top, IngestLimits::default()).is_ok(), depth <= 100);
            assert_eq!(parse(&nested, IngestLimits::default()).is_ok(), depth < 100);
        }
    }

    #[test]
    fn unknown_allowance_is_shared_across_all_levels() {
        let mut wire = [0x10, 0].repeat(250_000);
        wire.extend(bytes_field(1, &[0x18, 0].repeat(250_000)));
        let group = [vec![0x1b], [0x20, 0].repeat(499_999), vec![0x1c]].concat();
        wire.extend(bytes_field(1, &group));
        assert_matches_generated(&wire, IngestLimits::default());
        assert!(parse(&wire, IngestLimits::default()).is_ok());
        wire.extend_from_slice(&[0x10, 0]);
        assert_eq!(count_put_entries(&wire).unwrap(), 2);
        assert_matches_generated(&wire, IngestLimits::default());
        let error = parse(&wire, IngestLimits::default()).unwrap_err();
        assert_eq!(
            error.message.as_deref(),
            Some("failed to decode proto request: unknown field limit exceeded")
        );

        let top = [0x10, 0].repeat(buffa::DEFAULT_UNKNOWN_FIELD_LIMIT + 1);
        assert_eq!(count_put_entries(&top).unwrap_err().message, error.message);
    }

    #[test]
    fn unknown_length_delimited_payload_is_opaque_and_uses_one_slot() {
        let wire =
            Bytes::from([bytes_field(3, &vec![0xff; 1_000_001]), entry(b"a", b"b")].concat());
        let mut budget = UnknownBudget { remaining: 1 };
        let mut cursor = PutEntryCursor::new(&wire);
        assert!(matches!(cursor.next(&mut budget), Ok(Some(Field::Unknown))));
        assert_eq!(budget.remaining, 0);
        assert!(matches!(
            cursor.next(&mut budget),
            Ok(Some(Field::Entry(_)))
        ));
        assert_matches_generated(&wire, IngestLimits::default());
    }

    #[test]
    fn validation_matches_generated_details_and_retains_first_failure() {
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
            assert_matches_generated(&wire, limits);
        }
        for tail in [vec![0], vec![0x80], bytes_field(1, &[0x0a])] {
            let wire = [bad_key.clone(), tail].concat();
            assert_matches_generated(&wire, limits);
            assert!(parse(&wire, limits).unwrap_err().details.is_empty());
        }
    }

    #[test]
    fn short_wire_corpus_matches_generated_decoder() {
        let limits = IngestLimits {
            max_entries: 4,
            max_value_len: 8,
        };
        for first in 0..=u8::MAX {
            assert_matches_generated(&[first], limits);
            for second in [0, 1, 0x0a, 0x10, 0x13, 0x14, 0x7f, 0x80, 0xff] {
                assert_matches_generated(&[first, second], limits);
                assert_matches_generated(&bytes_field(1, &[first, second]), limits);
            }
        }
    }

    #[test]
    fn json_count_preserves_generated_map_and_sequence_layouts() {
        for wire in [
            br#"{"kvs":[{}, {"key":null,"value":"YQ"}]}"#.as_slice(),
            br#"[[["", "YQ=="], []]]"#,
            br#"{"ignored":{"kvs":[1,2,3]},"kvs":[{}]}"#,
            br#"{"kvs":null}"#,
            br#"[null]"#,
            br#"{}"#,
            br#"[]"#,
        ] {
            let generated: PutRequest = serde_json::from_slice(wire).unwrap();
            assert_eq!(count_put_entries_json(wire).unwrap(), generated.kvs.len());
        }
    }

    #[test]
    fn json_duplicate_kvs_and_malformed_shapes_are_rejected() {
        for wire in [
            br#"{"kvs":[],"kvs":[]}"#.as_slice(),
            br#"{"kvs":null,"kvs":[]}"#,
            br#"{"kvs":[}"#,
            br#"{"kvs":42}"#,
            br#"[[],[]]"#,
            br#"{} false"#,
        ] {
            let expected = connectrpc::codec::decode_json::<PutRequest>(wire).unwrap_err();
            let error = count_put_entries_json(wire).unwrap_err();
            assert_eq!(error.code, expected.code);
            assert!(error
                .message
                .unwrap()
                .starts_with("failed to decode JSON: "));
        }
    }
}
