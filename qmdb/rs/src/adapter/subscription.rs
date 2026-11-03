use crate::{
    adapter::codec::{
        decode_operation_location_key, decode_watermark_location, OPERATION_PREFIX,
        WATERMARK_PREFIX,
    },
    QmdbError,
};
use commonware_storage::merkle::{Family, Location};
use exoware_sdk::{
    keys::Key, kv_codec::Utf8, selector::Selector, stream_filter::StreamFilter,
    PrefixedStoreClient, StreamSubscription,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowFamily {
    Op,
    Watermark,
}

pub(crate) async fn open_store_subscription(
    client: &PrefixedStoreClient,
    filter: StreamFilter,
    since: Option<u64>,
) -> Result<StreamSubscription, QmdbError> {
    client
        .stream()
        .subscribe(filter, since)
        .await
        .map_err(|err| QmdbError::Stream(err.to_string()))
}

/// The family and location of a QMDB historical-log row, or `None` for any
/// other row.
pub(crate) fn classify_row<F: Family>(key: &Key) -> Option<(RowFamily, Location<F>)> {
    if OPERATION_PREFIX.matches(key) {
        return decode_operation_location_key::<F>(key)
            .ok()
            .map(|location| (RowFamily::Op, location));
    }
    if WATERMARK_PREFIX.matches(key) {
        return decode_watermark_location::<F>(key)
            .ok()
            .map(|location| (RowFamily::Watermark, location));
    }
    None
}

/// Select operation and publication rows from a QMDB historical log.
pub(crate) fn row_filter() -> StreamFilter {
    let payload_regex = Utf8::from("(?s-u)^.{8}$");
    StreamFilter {
        selectors: vec![
            Selector {
                prefix: OPERATION_PREFIX.as_bytes().clone(),
                payload_regex: payload_regex.clone(),
            },
            Selector {
                prefix: WATERMARK_PREFIX.as_bytes().clone(),
                payload_regex,
            },
        ],
        value_filters: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_row, row_filter, RowFamily};
    use crate::adapter::codec::{encode_operation_key, encode_watermark_key};
    use commonware_storage::merkle::{mmr, Location};
    use exoware_sdk::{keys::Key, selector::compile_payload_regex};

    const LOCATIONS: [u64; 4] = [0, 1, 0x0102_0304_0506_0708, u64::MAX];

    // The payload regexes re-state the codec's row layouts, and the server
    // drops any row a selector fails to match, so pin them together: every
    // operation and watermark key the codec can produce must match its
    // selector's regex in full and classify to the same family and location.
    #[test]
    fn test_backend_selectors_match_their_row_payloads() {
        let filter = row_filter();
        for location in LOCATIONS {
            let loc = Location::new(location);
            let rows: [(RowFamily, Key); 2] = [
                (RowFamily::Op, encode_operation_key(loc)),
                (RowFamily::Watermark, encode_watermark_key(loc)),
            ];
            for (family, key) in rows {
                let selector = filter
                    .selectors
                    .iter()
                    .find(|s| key.starts_with(&s.prefix))
                    .expect("row must carry a selector prefix");
                let regex = compile_payload_regex(&selector.payload_regex).expect("regex");
                let payload = &key[selector.prefix.len()..];
                let captures = regex.captures(payload).unwrap_or_else(|| {
                    panic!("regex must match {family:?} payload {payload:02X?}")
                });
                assert_eq!(captures.get(0).expect("full match").as_bytes(), payload);
                assert_eq!(classify_row::<mmr::Family>(&key), Some((family, loc)));
            }
        }
    }
}
