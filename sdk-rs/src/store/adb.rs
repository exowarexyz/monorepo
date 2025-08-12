use crate::{Client as SdkClient, Error};
use base64::{engine::general_purpose, Engine};
use commonware_codec::FixedSize;
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::mmr::{hasher::Standard, verification::Proof};
use http::HeaderMap;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use url::Url;

type Sha256Digest = <Sha256 as Hasher>::Digest;

pub const PATH_SEGMENT: &str = "adb";

pub struct Client {
    client: SdkClient,
    base_url: Url,
}

/// The JSON response payload for a `get` adb operation. The payload provides both the value for the
/// requested key, and a proof that should verify against the database's root corresponding to the
/// provided MMR size.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetResultPayload {
    /// The requested key's value.
    #[serde_as(as = "Base64")]
    pub value: Vec<u8>,

    /// The position of the value in the MMR.
    pub position: u64,

    /// The raw proof data for the value that can be verified against the database's root at the
    /// state corresponding to the provided MMR size.
    #[serde_as(as = "Base64")]
    pub proof_data: Vec<u8>,
}

impl Client {
    pub fn new(client: SdkClient, parent_url: &str) -> Self {
        let mut base_url = Url::parse(parent_url).unwrap();
        base_url.path_segments_mut().unwrap().push(PATH_SEGMENT);

        Self { client, base_url }
    }

    pub async fn get_and_verify_proof(
        &self,
        root: [u8; 32],
        key: &[u8],
        mmr_size: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let res = self.get(key, mmr_size).await?;
        let Some(payload) = res else {
            return Ok(None);
        };

        if payload.proof_data.len() % <<Sha256 as Hasher>::Digest as FixedSize>::SIZE != 0 {
            return Err(Error::BadResponse);
        }

        let mut digests = Vec::with_capacity(
            payload.proof_data.len() / <<Sha256 as Hasher>::Digest as FixedSize>::SIZE,
        );
        // Convert bytes to digests
        for chunk in payload
            .proof_data
            .chunks(<<Sha256 as Hasher>::Digest as FixedSize>::SIZE)
        {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(chunk);
            digests.push(digest.into());
        }

        let proof: Proof<<Sha256 as Hasher>::Digest> = Proof {
            size: mmr_size,
            digests,
        };

        let mut hasher = Standard::<Sha256>::new();
        let root_digest: Sha256Digest = root.into();
        let _root = proof.verify_range_inclusion(
            &mut hasher,
            std::slice::from_ref(&payload.value),
            payload.position,
            &root_digest,
        );

        Ok(Some(payload.value))
    }

    /// Retrieves a value from the store by its key, along with a proof that should verify against
    /// the database's root corresponding to the provided MMR size.
    ///
    /// - Returns `Ok(None)` if the key does not exit.
    /// - Returns [Error::ServerBehind] if the server's state is not sufficiently up-to-date to
    ///   handle a query for the provided size.
    pub async fn get(&self, key: &[u8], mmr_size: u64) -> Result<Option<GetResultPayload>, Error> {
        let (url, headers) = self.get_request(key, mmr_size, HeaderMap::new());

        let res = self.client.get(url, headers).await?;

        Self::get_handle_response(res).await
    }

    fn get_request(
        &self,
        key: &[u8],
        mmr_size: u64,
        mut headers: HeaderMap,
    ) -> (String, HeaderMap) {
        let key_b64 = general_purpose::STANDARD.encode(key);
        let mut url = self.base_url.clone();
        url.query_pairs_mut()
            .append_pair("key", &key_b64)
            .append_pair("size", &mmr_size.to_string());

        self.client.add_auth_header(&mut headers);

        (url.to_string(), headers)
    }

    async fn get_handle_response(res: Response) -> Result<Option<GetResultPayload>, crate::Error> {
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(Some(res.json().await?))
    }

    pub async fn set_key(&self, key: &[u8], position: u64, value: Vec<u8>) -> Result<(), Error> {
        let (url, headers) = self.set_key_request(key, position, HeaderMap::new());

        let res = self.client.post(url, headers, value).await?;

        Self::set_key_handle_response(res).await
    }

    fn set_key_request(
        &self,
        key: &[u8],
        position: u64,
        mut headers: HeaderMap,
    ) -> (String, HeaderMap) {
        let key_b64 = general_purpose::STANDARD.encode(key);

        let mut url = self.base_url.clone();
        url.path_segments_mut().unwrap().push("set_key");
        url.query_pairs_mut()
            .append_pair("key", &key_b64)
            .append_pair("position", &position.to_string());

        self.client.add_auth_header(&mut headers);

        (url.to_string(), headers)
    }

    async fn set_key_handle_response(res: Response) -> Result<(), Error> {
        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(())
    }

    pub async fn set_node_digest(&self, position: u64, digest: [u8; 32]) -> Result<(), Error> {
        let (url, headers) = self.set_node_digest_request(position, HeaderMap::new());

        let res = self.client.post(url, headers, digest.to_vec()).await?;

        Self::set_node_digest_handle_response(res).await
    }

    fn set_node_digest_request(
        &self,
        position: u64,
        mut headers: HeaderMap,
    ) -> (String, HeaderMap) {
        let mut url = self.base_url.clone();
        url.path_segments_mut().unwrap().push("set_node_digest");
        url.query_pairs_mut()
            .append_pair("position", &position.to_string());

        self.client.add_auth_header(&mut headers);

        (url.to_string(), headers)
    }

    async fn set_node_digest_handle_response(res: Response) -> Result<(), Error> {
        if !res.status().is_success() {
            return Err(Error::Http(res.status()));
        }

        Ok(())
    }
}
