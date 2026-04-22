//! Validated filter for `store.stream.v1.Subscribe`.
//!
//! The filter is a list of `MatchKey`s with OR semantics: a row is delivered
//! if any match_key's (reserved_bits, prefix) selects its family AND its
//! payload_regex matches the key's payload bytes. The list is capped at 16 to
//! keep server-side regex compile cost predictable.

use anyhow::ensure;

use crate::keys::KeyCodec;
use crate::match_key::MatchKey;

pub const MAX_MATCH_KEYS_PER_FILTER: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFilter {
    pub match_keys: Vec<MatchKey>,
}

/// Shape-only validation: bounds, family validity, non-empty regex string.
/// Does NOT compile the regex — the server compiles once per subscribe.
pub fn validate_filter(filter: &StreamFilter) -> anyhow::Result<()> {
    ensure!(
        !filter.match_keys.is_empty(),
        "stream filter must contain at least one match_key"
    );
    ensure!(
        filter.match_keys.len() <= MAX_MATCH_KEYS_PER_FILTER,
        "stream filter capped at {MAX_MATCH_KEYS_PER_FILTER} match_keys"
    );
    for mk in &filter.match_keys {
        // Panics on invalid (reserved_bits, prefix); translate to Err.
        std::panic::catch_unwind(|| KeyCodec::new(mk.reserved_bits, mk.prefix)).map_err(|_| {
            anyhow::anyhow!(
                "invalid (reserved_bits={}, prefix={}) — see KeyCodec::new",
                mk.reserved_bits,
                mk.prefix
            )
        })?;
        ensure!(
            !mk.payload_regex.trim().is_empty(),
            "match_key payload_regex must not be empty"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv_codec::Utf8;

    fn mk(prefix: u16) -> MatchKey {
        MatchKey {
            reserved_bits: 4,
            prefix,
            payload_regex: Utf8::from("(?s).*"),
        }
    }

    #[test]
    fn accepts_one_match_key() {
        let f = StreamFilter {
            match_keys: vec![mk(1)],
        };
        validate_filter(&f).unwrap();
    }

    #[test]
    fn rejects_empty() {
        let f = StreamFilter { match_keys: vec![] };
        assert!(validate_filter(&f).is_err());
    }

    #[test]
    fn rejects_too_many() {
        let f = StreamFilter {
            match_keys: (0..(MAX_MATCH_KEYS_PER_FILTER as u16 + 1))
                .map(mk)
                .collect(),
        };
        assert!(validate_filter(&f).is_err());
    }

    #[test]
    fn rejects_empty_regex() {
        let f = StreamFilter {
            match_keys: vec![MatchKey {
                reserved_bits: 4,
                prefix: 1,
                payload_regex: Utf8::from(""),
            }],
        };
        assert!(validate_filter(&f).is_err());
    }
}
