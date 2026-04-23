use std::sync::Arc;

use commonware_storage::mmr::Location;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{StoreClient, StreamSubscription};

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
pub enum Family {
    Op,
    Presence,
    Watermark,
}

pub type Classify = Arc<dyn Fn(&Key, &[u8]) -> Option<(Family, Location)> + Send + Sync + 'static>;

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
pub(crate) fn classify_and_filter(
    namespace: Option<AuthenticatedBackendNamespace>,
) -> (Classify, StreamFilter) {
    use exoware_sdk_rs::keys::{Key as StoreKey, KeyCodec};
    use exoware_sdk_rs::kv_codec::Utf8;

    type DecodeLocation = Arc<dyn Fn(&StoreKey) -> Option<Location> + Send + Sync>;

    let (compiled, op_prefix, presence_prefix, watermark_prefix, payload_regex) = match namespace {
        None => {
            let compiled: [(KeyCodec, Family, DecodeLocation); 3] = [
                (
                    KeyCodec::new(RESERVED_BITS, OP_FAMILY),
                    Family::Op,
                    Arc::new(|key| decode_operation_location_key(key).ok()),
                ),
                (
                    KeyCodec::new(RESERVED_BITS, PRESENCE_FAMILY),
                    Family::Presence,
                    Arc::new(|key| decode_presence_location(key).ok()),
                ),
                (
                    KeyCodec::new(RESERVED_BITS, WATERMARK_FAMILY),
                    Family::Watermark,
                    Arc::new(|key| decode_watermark_location(key).ok()),
                ),
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
            let compiled: [(KeyCodec, Family, DecodeLocation); 3] = [
                (
                    AUTH_OPERATION_CODEC,
                    Family::Op,
                    Arc::new(move |key| decode_auth_operation_location(ns, key).ok()),
                ),
                (
                    AUTH_PRESENCE_CODEC,
                    Family::Presence,
                    Arc::new(move |key| decode_auth_presence_location(ns, key).ok()),
                ),
                (
                    AUTH_WATERMARK_CODEC,
                    Family::Watermark,
                    Arc::new(move |key| decode_auth_watermark_location(ns, key).ok()),
                ),
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

    let classify: Classify = Arc::new(move |key: &StoreKey, _value: &[u8]| {
        for (codec, family, decode) in &compiled {
            if codec.matches(key) {
                return decode(key).map(|location| (*family, location));
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
