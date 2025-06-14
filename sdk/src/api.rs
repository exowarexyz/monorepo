use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct GetResult {
    pub value: String, // base64 encoded
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResultItem {
    pub key: String,
    pub value: String, // base64 encoded
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResult {
    pub results: Vec<QueryResultItem>,
}
