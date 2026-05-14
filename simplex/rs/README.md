# exoware-simplex

Store-backed upload helpers for Commonware Simplex artifacts.

The crate uses the Commonware Library revision pinned by the workspace
`Cargo.toml` and stores encoded artifacts in Exoware Store rows:

- block by digest
- notarized `{ proof, block }` by Simplex view
- finalized `{ proof, block }` by Simplex view
- finalized `{ proof, block }` by block height

```rust
use exoware_simplex::{Finalized, SimplexClient};

# async fn example<B, S, D>(
#   store_url: &str,
#   proof: commonware_consensus::simplex::types::Finalization<S, D>,
#   block: B,
# ) -> Result<(), Box<dyn std::error::Error>>
# where
#   B: commonware_consensus::Block<Digest = D>,
#   S: commonware_cryptography::certificate::Scheme,
#   D: commonware_cryptography::Digest,
# {
let client = SimplexClient::new(store_url);
let finalized = Finalized::new(proof, block)?;
let receipt = client.upload_finalized(&finalized).await?;
println!("stored at sequence {}", receipt.store_sequence_number);
# Ok(())
# }
```

Use `prepare_block`, `prepare_notarized`, and `prepare_finalized` when multiple
Simplex artifacts should be staged into a shared `StoreWriteBatch`.

Finalized records can be read back by view, by height, or as the latest
finalized height index. The `{ proof, block }` wrappers validate that the
certificate payload digest matches the paired block during construction and
decoding.
