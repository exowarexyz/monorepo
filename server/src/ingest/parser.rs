use buffa::encoding::{check_wire_type, skip_field_depth, Tag, WireType};
use buffa::DecodeError;
use connectrpc::ConnectError;

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

    pub(super) fn charge_many(&mut self, count: usize) -> Result<(), PutParseError> {
        self.remaining = self
            .remaining
            .checked_sub(count)
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
    // Match buffa's register_unknown_record accounting after validating the complete record.
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

// Hints schedule retries and destination sizes. The cursor still validates the wire.
pub(super) fn field_size(mut bytes: &[u8]) -> Option<usize> {
    let original = bytes.len();
    let tag = Tag::decode(&mut bytes).ok()?;
    if tag.wire_type() != WireType::LengthDelimited {
        return None;
    }
    let len = usize::try_from(buffa::encoding::decode_varint(&mut bytes).ok()?).ok()?;
    len.checked_add(original - bytes.len())
}
