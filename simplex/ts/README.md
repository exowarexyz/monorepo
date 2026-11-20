# @exowarexyz/simplex

Upload, read and subscribe to Commonware Simplex artifacts in Exoware Store.
The package shares the [Rust package's](../rs/README.md) key layout and provides
a browser WASM verifier for Commonware certificates.

## Upload artifacts

`SimplexWriter` accepts encoded bytes and the indexes under which to store them.
Headers and full `{ header, body }` blocks are indexed by digest, notarizations
and finalizations by epoch and view, and finalizations also by height. For a
certificate record, encode the Commonware certificate followed by its
application header, and supply the header's digest and bytes so the upload also
stores the header by digest. The writer trusts the supplied indexes and header,
so they must match the encoded artifact.

This function uploads a full block and its finalization in one Store Put:

```ts
import { StoreClient, StoreWriteBatch } from '@exowarexyz/sdk';
import {
  SimplexWriter,
  type BlockUpload,
  type FinalizedUpload,
} from '@exowarexyz/simplex';

async function uploadBlockAndFinalization(
  storeUrl: string,
  block: BlockUpload,
  finalized: FinalizedUpload,
) {
  const client = new StoreClient(storeUrl);
  const writer = new SimplexWriter(client.unprefixed());
  const batch = new StoreWriteBatch();
  writer.stageUpload(writer.prepareBlock(block), batch);
  writer.stageUpload(writer.prepareFinalized(finalized), batch);
  return batch.commit(client);
}
```

For a single artifact, use the corresponding `upload*` method. Both approaches
validate Store limits before sending and throw `RangeError` if they exceed
them. The `prepare*` methods also throw `RangeError` for an empty digest or
header. For a custom batch, use `validate` to check these limits or `split` to
divide the writes into separate atomic Puts. Splitting can separate an
artifact's rows. Readers and writers must use the same Store prefix.

## Read verified certificates

Certificate reads take a `SimplexCertificateVerifier` as their first argument,
pass each stored record to it, and return its verified result. For Commonware
certificates, use the bundled WASM verifier, which requires an
application-specific `verifyHeader` callback. The WASM verifier checks
certificate signatures against your trusted configuration and returns the signed
epoch, view and payload with the attached header. For round reads, it also
checks that the signed epoch and view match the requested index.

Your `verifyHeader` callback authenticates the attached header against the
signed payload and enforces any application-specific epoch or header rules.
For height or latest reads, it must also match the header's height to
`context.height`. The verifier runs it for every certificate before returning
a result:

```ts
import { StoreClient } from '@exowarexyz/sdk';
import { SimplexReader, type SimplexCertificateVerifierOptions } from '@exowarexyz/simplex';
import { loadWasmSimplexCertificateVerifier } from '@exowarexyz/simplex/wasm';

async function readLatest(storeUrl: string, options: SimplexCertificateVerifierOptions) {
  const verifier = await loadWasmSimplexCertificateVerifier(options);
  const store = new StoreClient(storeUrl).unprefixed();
  return new SimplexReader(store).latestFinalized(verifier);
}
```

Choose `scheme`, `payloadKind`, `identity`, `namespace` and `verificationMaterial`
from trusted application configuration for the expected network and epoch.
A certificate's reported epoch does not establish trust in its validator keys,
and the signing namespace is separate from the Store prefix. For
`verificationMaterial`, supply Commonware-encoded public key data: a
participant set for Ed25519, an identity-to-signing-key map for Secp256r1 or BLS
multisig, or a threshold public identity for threshold schemes.

For an application-specific certificate format, implement
`SimplexCertificateVerifier` with signature, epoch, view, height and header
checks against the supplied context. Certificate reads throw if verification
fails and return `null` if the record is missing.

### Build the WASM verifier

Building the bundled verifier from source requires Rust's
`wasm32-unknown-unknown` target, `wasm-pack`, and `wasm-bindgen-cli`. Generate the
WASM module from the repository root:

```bash
npm --prefix simplex/ts run build:wasm
```

## Raw reads and subscriptions

Use certificate methods ending in `Raw` for unverified bytes. You can also read
header bytes with `getHeaderRaw` or block bytes with `getBlockRaw`, which
`decodeSimplexBlockData` splits into a `{ header, body }` envelope. Neither
method authenticates its contents. Since certificate records contain no body,
fetch the block separately and check its body against the application's header
commitment. The `createWasmSimplexHeaderVerifier` and
`createWasmSimplexBlockVerifier` adapters wrap application-owned WASM checks.
These checks see only the payload, header and body, so they cannot compare the
header's height with `context.height`.

Reads through `new SimplexReader(store)` use a monotonic session with no initial
minimum, and clones share observed Store sequences. Use
`SimplexReader.withSession` to supply an existing SDK `ReadSession`, or
`withMinSequenceNumber` to require reads at or after an upload receipt's
sequence. A fixed session sets a minimum, not a historical snapshot.

[`SimplexSubscriptions`](./src/subscriptions.ts) streams Store updates.
`subscribeCertificates` takes a verifier and applies it as certificate reads do.
`subscribeCertificatesRaw`, `subscribeHeaders` and `subscribeBlocks` return
unverified artifacts.
