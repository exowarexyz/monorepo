use exoware_sdk::keys::Key;

#[derive(Clone, Debug)]
pub struct Record {
    pub key: Key,
    pub value: Vec<u8>,
}

/// Borrows a record batch in the `(key, value)` shape the SDK put API expects.
pub(crate) fn record_refs(records: &[Record]) -> Vec<(&Key, &[u8])> {
    records
        .iter()
        .map(|record| (&record.key, record.value.as_slice()))
        .collect()
}
