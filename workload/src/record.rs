use exoware_sdk::keys::Key;

#[derive(Clone, Debug)]
pub struct Record {
    pub key: Key,
    pub value: Vec<u8>,
}
