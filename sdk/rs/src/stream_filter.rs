//! Validated filter for `store.stream.v1.Subscribe`.
//!
//! The filter is a list of `MatchKey`s with OR semantics: a row is delivered
//! if any match_key's (reserved_bits, prefix) selects its family AND its
//! payload_regex matches the key's payload bytes. The list is capped at 16 to
//! keep server-side regex compile cost predictable. When `value_filters` is
//! non-empty, rows that pass the key filter must also satisfy any one
//! `BytesFilter` in the value list (OR within the value list; AND between key
//! and value filters).

use std::collections::BTreeSet;

use anyhow::ensure;
use regex::bytes::Regex;

use crate::keys::KeyCodec;
use crate::match_key::MatchKey;

pub const MAX_MATCH_KEYS_PER_FILTER: usize = 16;
pub const MAX_VALUE_FILTERS_PER_FILTER: usize = 16;

/// Matches a row's raw value bytes by exact match, prefix, or regex. Wire
/// shape mirrors `store.common.v1.BytesFilter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BytesFilter {
    Exact(Vec<u8>),
    Prefix(Vec<u8>),
    Regex(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFilter {
    pub match_keys: Vec<MatchKey>,
    pub value_filters: Vec<BytesFilter>,
}

/// A compiled bundle of `BytesFilter`s ready to evaluate against a byte
/// slice. OR semantics: `matches` returns true when any contained filter
/// matches the input. An empty bundle matches nothing; callers should model
/// "no filter configured" as `Option::None` and skip the match.
#[derive(Clone, Debug)]
pub struct CompiledBytesFilters {
    exacts: BTreeSet<Vec<u8>>,
    prefixes: Vec<Vec<u8>>,
    regexes: Vec<Regex>,
}

impl CompiledBytesFilters {
    /// Compile filters from the domain `BytesFilter` representation. Returns
    /// `Ok(None)` when the input is empty (caller should skip matching).
    pub fn compile(filters: &[BytesFilter]) -> Result<Option<Self>, String> {
        if filters.is_empty() {
            return Ok(None);
        }
        let mut exacts = BTreeSet::<Vec<u8>>::new();
        let mut prefixes = Vec::new();
        let mut regexes = Vec::new();
        for filter in filters {
            match filter {
                BytesFilter::Exact(bytes) => {
                    exacts.insert(bytes.clone());
                }
                BytesFilter::Prefix(bytes) => prefixes.push(bytes.clone()),
                BytesFilter::Regex(pattern) => {
                    if pattern.trim().is_empty() {
                        return Err("regex filter must not be empty".to_string());
                    }
                    regexes.push(
                        Regex::new(pattern)
                            .map_err(|e| format!("invalid regex `{pattern}`: {e}"))?,
                    );
                }
            }
        }
        Ok(Some(Self {
            exacts,
            prefixes,
            regexes,
        }))
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.exacts.contains(bytes)
            || self.prefixes.iter().any(|p| bytes.starts_with(p))
            || self.regexes.iter().any(|r| r.is_match(bytes))
    }
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
    ensure!(
        filter.value_filters.len() <= MAX_VALUE_FILTERS_PER_FILTER,
        "stream filter capped at {MAX_VALUE_FILTERS_PER_FILTER} value_filters"
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
    for vf in &filter.value_filters {
        match vf {
            BytesFilter::Regex(r) => {
                ensure!(!r.trim().is_empty(), "value_filter regex must not be empty")
            }
            BytesFilter::Exact(_) | BytesFilter::Prefix(_) => {}
        }
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
            value_filters: vec![],
        };
        validate_filter(&f).unwrap();
    }

    #[test]
    fn rejects_empty() {
        let f = StreamFilter {
            match_keys: vec![],
            value_filters: vec![],
        };
        assert!(validate_filter(&f).is_err());
    }

    #[test]
    fn rejects_too_many() {
        let f = StreamFilter {
            match_keys: (0..(MAX_MATCH_KEYS_PER_FILTER as u16 + 1))
                .map(mk)
                .collect(),
            value_filters: vec![],
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
            value_filters: vec![],
        };
        assert!(validate_filter(&f).is_err());
    }
}
