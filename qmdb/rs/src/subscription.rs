use std::sync::Arc;

use commonware_storage::merkle::{Family, Location};
use exoware_sdk::keys::Key;
use exoware_sdk::selector::Selector;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::{PrefixedStoreClient, StreamSubscription};

use crate::auth::{
    decode_auth_operation_location, decode_auth_presence_location, decode_auth_watermark_location,
    AuthenticatedBackendNamespace,
};
use crate::codec::{
    decode_operation_location_key, decode_presence_location, decode_watermark_location,
    OPERATION_PREFIX, PRESENCE_PREFIX, WATERMARK_PREFIX,
};
use crate::QmdbError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowFamily {
    Op,
    Presence,
    Watermark,
}

#[derive(Clone)]
pub(crate) struct RowClassifier<F: Family> {
    classify: Arc<dyn Fn(&Key, &[u8]) -> Option<(RowFamily, Location<F>)> + Send + Sync + 'static>,
}

impl<F: Family> RowClassifier<F> {
    fn new(
        classify: impl Fn(&Key, &[u8]) -> Option<(RowFamily, Location<F>)> + Send + Sync + 'static,
    ) -> Self {
        Self {
            classify: Arc::new(classify),
        }
    }

    pub(crate) fn classify(&self, key: &Key, value: &[u8]) -> Option<(RowFamily, Location<F>)> {
        (self.classify)(key, value)
    }
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

/// Build the classifier + stream filter selecting the Op / Presence /
/// Watermark rows of a QMDB backend's historical op log. Pass
/// `Some(namespace)` for the authenticated backends (immutable, keyless) and
/// `None` for the plain-store backends (ordered, unordered).
pub(crate) fn classify_and_filter<F: Family>(
    namespace: Option<AuthenticatedBackendNamespace>,
) -> (RowClassifier<F>, StreamFilter) {
    use exoware_sdk::keys::{Key as StoreKey, Prefix};
    use exoware_sdk::kv_codec::Utf8;

    struct RowRule<F: Family> {
        prefix: Prefix,
        family: RowFamily,
        decode: Arc<dyn Fn(&StoreKey) -> Option<Location<F>> + Send + Sync>,
    }

    // The family byte encodes row semantics and is shared across every backend
    // variant, so the Op / Presence / Watermark stream-filter prefixes are
    // identical for the merkleized and authenticated backends. Only the
    // per-namespace payload layout (payload_regex) and the namespace-aware row
    // decoders still differ, so those stay inside the match.
    let op_prefix = OPERATION_PREFIX.as_bytes().clone();
    let presence_prefix = PRESENCE_PREFIX.as_bytes().clone();
    let watermark_prefix = WATERMARK_PREFIX.as_bytes().clone();

    let (compiled, payload_regex) = match namespace {
        None => {
            let compiled: [RowRule<F>; 3] = [
                RowRule {
                    prefix: OPERATION_PREFIX,
                    family: RowFamily::Op,
                    decode: Arc::new(|key| decode_operation_location_key::<F>(key).ok()),
                },
                RowRule {
                    prefix: PRESENCE_PREFIX,
                    family: RowFamily::Presence,
                    decode: Arc::new(|key| decode_presence_location::<F>(key).ok()),
                },
                RowRule {
                    prefix: WATERMARK_PREFIX,
                    family: RowFamily::Watermark,
                    decode: Arc::new(|key| decode_watermark_location::<F>(key).ok()),
                },
            ];
            (compiled, "(?s-u)^.{8}$".to_string())
        }
        Some(ns) => {
            let compiled: [RowRule<F>; 3] = [
                RowRule {
                    prefix: OPERATION_PREFIX,
                    family: RowFamily::Op,
                    decode: Arc::new(move |key| decode_auth_operation_location::<F>(ns, key).ok()),
                },
                RowRule {
                    prefix: PRESENCE_PREFIX,
                    family: RowFamily::Presence,
                    decode: Arc::new(move |key| decode_auth_presence_location::<F>(ns, key).ok()),
                },
                RowRule {
                    prefix: WATERMARK_PREFIX,
                    family: RowFamily::Watermark,
                    decode: Arc::new(move |key| decode_auth_watermark_location::<F>(ns, key).ok()),
                },
            ];
            (compiled, format!(r"(?s-u)^\x{:02X}.{{8}}$", ns.tag()))
        }
    };

    let classify = RowClassifier::new(move |key: &StoreKey, _value: &[u8]| {
        for rule in &compiled {
            if rule.prefix.matches(key) {
                return (rule.decode)(key).map(|location| (rule.family, location));
            }
        }
        None
    });

    let filter = StreamFilter {
        selectors: vec![
            Selector {
                prefix: op_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
            Selector {
                prefix: presence_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
            Selector {
                prefix: watermark_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
        ],
        value_filters: vec![],
    };
    (classify, filter)
}

#[cfg(test)]
mod tests {
    use commonware_storage::merkle::{mmr, Location};
    use exoware_sdk::keys::Key;
    use exoware_sdk::selector::compile_payload_regex;

    use super::{classify_and_filter, RowFamily};
    use crate::auth::{
        encode_auth_operation_key, encode_auth_presence_key, encode_auth_watermark_key,
        AuthenticatedBackendNamespace,
    };
    use crate::codec::{encode_operation_key, encode_presence_key, encode_watermark_key};

    const LOCATIONS: [u64; 4] = [0, 1, 0x0102_0304_0506_0708, u64::MAX];

    // The payload regexes re-state the codec's row layouts, and the server
    // drops any row a selector fails to match, so pin them together: every
    // Op / Presence / Watermark key the codec can produce must match its
    // selector's regex in full and classify to the same family and location.
    fn assert_rows_match_filter(namespace: Option<AuthenticatedBackendNamespace>) {
        let (classifier, filter) = classify_and_filter::<mmr::Family>(namespace);
        for location in LOCATIONS {
            let loc = Location::new(location);
            let rows: [(RowFamily, Key); 3] = match namespace {
                None => [
                    (RowFamily::Op, encode_operation_key(loc)),
                    (RowFamily::Presence, encode_presence_key(loc)),
                    (RowFamily::Watermark, encode_watermark_key(loc)),
                ],
                Some(ns) => [
                    (RowFamily::Op, encode_auth_operation_key(ns, loc)),
                    (RowFamily::Presence, encode_auth_presence_key(ns, loc)),
                    (RowFamily::Watermark, encode_auth_watermark_key(ns, loc)),
                ],
            };
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
                assert_eq!(classifier.classify(&key, &[]), Some((family, loc)));
            }
        }
    }

    #[test]
    fn plain_backend_selectors_match_their_row_payloads() {
        assert_rows_match_filter(None);
    }

    #[test]
    fn authenticated_backend_selectors_match_their_row_payloads() {
        assert_rows_match_filter(Some(AuthenticatedBackendNamespace::Immutable));
        assert_rows_match_filter(Some(AuthenticatedBackendNamespace::Keyless));
    }

    // Plain payloads are a bare 8-byte location; authenticated payloads
    // prepend a namespace tag. Each selector shape must reject the others so a
    // subscription never claims rows from a differently-shaped backend.
    #[test]
    fn selectors_reject_payloads_of_the_other_shape() {
        let loc = Location::<mmr::Family>::new(7);
        let (_, plain) = classify_and_filter::<mmr::Family>(None);
        let (_, auth) =
            classify_and_filter::<mmr::Family>(Some(AuthenticatedBackendNamespace::Immutable));
        let plain_key = encode_operation_key(loc);
        let immutable_key =
            encode_auth_operation_key(AuthenticatedBackendNamespace::Immutable, loc);
        let keyless_key = encode_auth_operation_key(AuthenticatedBackendNamespace::Keyless, loc);
        let plain_regex = compile_payload_regex(&plain.selectors[0].payload_regex).expect("regex");
        let auth_regex = compile_payload_regex(&auth.selectors[0].payload_regex).expect("regex");
        assert!(plain_regex.is_match(&plain_key[1..]));
        assert!(!plain_regex.is_match(&immutable_key[1..]));
        assert!(auth_regex.is_match(&immutable_key[1..]));
        assert!(!auth_regex.is_match(&keyless_key[1..]));
        assert!(!auth_regex.is_match(&plain_key[1..]));
    }
}
