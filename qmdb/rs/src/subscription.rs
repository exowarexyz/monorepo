use std::sync::Arc;

use commonware_storage::merkle::{Family, Location};
use exoware_sdk::keys::Key;
use exoware_sdk::match_key::MatchKey;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::{StoreClient, StreamSubscription};

use crate::auth::{
    decode_auth_operation_location, decode_auth_presence_location, decode_auth_watermark_location,
    AuthenticatedBackendNamespace, AUTH_OPERATION_CODEC, AUTH_PRESENCE_CODEC, AUTH_WATERMARK_CODEC,
};
use crate::codec::{
    decode_operation_location_key, decode_presence_location, decode_watermark_location, OP_FAMILY,
    PRESENCE_FAMILY, RESERVED_BITS, WATERMARK_FAMILY,
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
    client: &StoreClient,
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
    use exoware_sdk::keys::{Key as StoreKey, KeyCodec};
    use exoware_sdk::kv_codec::Utf8;

    struct RowRule<F: Family> {
        codec: KeyCodec,
        family: RowFamily,
        decode: Arc<dyn Fn(&StoreKey) -> Option<Location<F>> + Send + Sync>,
    }

    let (compiled, op_prefix, presence_prefix, watermark_prefix, payload_regex) = match namespace {
        None => {
            let compiled: [RowRule<F>; 3] = [
                RowRule {
                    codec: KeyCodec::new(RESERVED_BITS, OP_FAMILY),
                    family: RowFamily::Op,
                    decode: Arc::new(|key| decode_operation_location_key::<F>(key).ok()),
                },
                RowRule {
                    codec: KeyCodec::new(RESERVED_BITS, PRESENCE_FAMILY),
                    family: RowFamily::Presence,
                    decode: Arc::new(|key| decode_presence_location::<F>(key).ok()),
                },
                RowRule {
                    codec: KeyCodec::new(RESERVED_BITS, WATERMARK_FAMILY),
                    family: RowFamily::Watermark,
                    decode: Arc::new(|key| decode_watermark_location::<F>(key).ok()),
                },
            ];
            (
                compiled,
                OP_FAMILY,
                PRESENCE_FAMILY,
                WATERMARK_FAMILY,
                "(?s-u)^.{8}$".to_string(),
            )
        }
        Some(ns) => {
            let compiled: [RowRule<F>; 3] = [
                RowRule {
                    codec: AUTH_OPERATION_CODEC,
                    family: RowFamily::Op,
                    decode: Arc::new(move |key| decode_auth_operation_location::<F>(ns, key).ok()),
                },
                RowRule {
                    codec: AUTH_PRESENCE_CODEC,
                    family: RowFamily::Presence,
                    decode: Arc::new(move |key| decode_auth_presence_location::<F>(ns, key).ok()),
                },
                RowRule {
                    codec: AUTH_WATERMARK_CODEC,
                    family: RowFamily::Watermark,
                    decode: Arc::new(move |key| decode_auth_watermark_location::<F>(ns, key).ok()),
                },
            ];
            (
                compiled,
                AUTH_OPERATION_CODEC.prefix(),
                AUTH_PRESENCE_CODEC.prefix(),
                AUTH_WATERMARK_CODEC.prefix(),
                format!(r"(?s-u)^\x{:02X}.{{8}}$", ns.tag()),
            )
        }
    };

    let classify = RowClassifier::new(move |key: &StoreKey, _value: &[u8]| {
        for rule in &compiled {
            if rule.codec.matches(key) {
                return (rule.decode)(key).map(|location| (rule.family, location));
            }
        }
        None
    });

    let filter = StreamFilter {
        match_keys: vec![
            MatchKey {
                reserved_bits: RESERVED_BITS,
                prefix: op_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
            MatchKey {
                reserved_bits: RESERVED_BITS,
                prefix: presence_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
            MatchKey {
                reserved_bits: RESERVED_BITS,
                prefix: watermark_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
        ],
        value_filters: vec![],
    };
    (classify, filter)
}
