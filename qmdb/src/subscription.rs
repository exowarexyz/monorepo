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
pub(crate) enum Family {
    Op,
    Presence,
    Watermark,
}

pub(crate) type Classify =
    Arc<dyn Fn(&Key, &[u8]) -> Option<(Family, Location)> + Send + Sync + 'static>;

fn build_filter(
    reserved_bits: u8,
    op_prefix: u16,
    presence_prefix: u16,
    watermark_prefix: u16,
    payload_regex: &str,
) -> StreamFilter {
    use exoware_sdk_rs::kv_codec::Utf8;

    StreamFilter {
        match_keys: vec![
            MatchKey {
                reserved_bits,
                prefix: op_prefix,
                payload_regex: Utf8::from(payload_regex),
            },
            MatchKey {
                reserved_bits,
                prefix: presence_prefix,
                payload_regex: Utf8::from(payload_regex),
            },
            MatchKey {
                reserved_bits,
                prefix: watermark_prefix,
                payload_regex: Utf8::from(payload_regex),
            },
        ],
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

fn historical_classify_and_filter() -> (Classify, StreamFilter) {
    use exoware_sdk_rs::keys::{Key as StoreKey, KeyCodec};

    type DecodeLocation = Arc<dyn Fn(&StoreKey) -> Option<Location> + Send + Sync>;

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

    let classify: Classify = Arc::new(move |key: &StoreKey, _value: &[u8]| {
        for (codec, family, decode) in &compiled {
            if codec.matches(key) {
                return decode(key).map(|location| (*family, location));
            }
        }
        None
    });

    let filter = build_filter(
        RESERVED_BITS,
        OP_FAMILY,
        PRESENCE_FAMILY,
        WATERMARK_FAMILY,
        "(?s-u)^.{8}$",
    );
    (classify, filter)
}

fn authenticated_classify_and_filter(
    namespace: AuthenticatedBackendNamespace,
) -> (Classify, StreamFilter) {
    use exoware_sdk_rs::keys::{Key as StoreKey, KeyCodec};

    type DecodeLocation = Arc<dyn Fn(&StoreKey) -> Option<Location> + Send + Sync>;

    let compiled: [(KeyCodec, Family, DecodeLocation); 3] = [
        (
            AUTH_OPERATION_CODEC,
            Family::Op,
            Arc::new(move |key| decode_auth_operation_location(namespace, key).ok()),
        ),
        (
            AUTH_PRESENCE_CODEC,
            Family::Presence,
            Arc::new(move |key| decode_auth_presence_location(namespace, key).ok()),
        ),
        (
            AUTH_WATERMARK_CODEC,
            Family::Watermark,
            Arc::new(move |key| decode_auth_watermark_location(namespace, key).ok()),
        ),
    ];

    let classify: Classify = Arc::new(move |key: &StoreKey, _value: &[u8]| {
        for (codec, family, decode) in &compiled {
            if codec.matches(key) {
                return decode(key).map(|location| (*family, location));
            }
        }
        None
    });

    let payload_regex = format!(r"(?s-u)^\x{:02X}.{{8}}$", namespace.tag());
    let filter = build_filter(
        RESERVED_BITS,
        AUTH_OPERATION_CODEC.prefix(),
        AUTH_PRESENCE_CODEC.prefix(),
        AUTH_WATERMARK_CODEC.prefix(),
        &payload_regex,
    );
    (classify, filter)
}

pub(crate) fn ordered_classify_and_filter() -> (Classify, StreamFilter) {
    historical_classify_and_filter()
}

pub(crate) fn unordered_classify_and_filter() -> (Classify, StreamFilter) {
    historical_classify_and_filter()
}

pub(crate) fn immutable_classify_and_filter() -> (Classify, StreamFilter) {
    authenticated_classify_and_filter(AuthenticatedBackendNamespace::Immutable)
}

pub(crate) fn keyless_classify_and_filter() -> (Classify, StreamFilter) {
    authenticated_classify_and_filter(AuthenticatedBackendNamespace::Keyless)
}
