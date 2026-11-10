# @exowarexyz/simplex

Upload, read and subscribe to Commonware Simplex artifacts in Exoware Store.
The package shares the [Rust package's](../rs/README.md) key layout and provides
a browser WASM verifier for Commonware certificates.

## Upload artifacts

`SimplexWriter` accepts encoded bytes and the indices under which to store them.
Headers and full `{ header, body }` blocks are indexed by digest, notarizations
and finalizations by epoch and view, and finalizations also by height. For a
certificate record, encode the Commonware proof followed by its application
header. The writer trusts the supplied indices, so they must match the encoded
artifact.

This function publishes a full block and its finalization in one Store Put:

```ts
import { StoreClient, StoreWriteBatch } from '@exowarexyz/sdk';
import {
  SimplexWriter,
  type BlockUpload,
  type FinalizationUpload,
} from '@exowarexyz/simplex';

async function publish(
  storeUrl: string,
  block: BlockUpload,
  finalization: FinalizationUpload,
) {
  const client = new StoreClient(storeUrl);
  const writer = new SimplexWriter(client.unprefixed());
  const batch = new StoreWriteBatch();
  writer.stageUpload(writer.prepareBlock(block), batch);
  writer.stageUpload(writer.prepareFinalization(finalization), batch);
  return batch.commit(client);
}
```

For a single artifact, use the corresponding `upload*` method. Both approaches
validate Store limits before sending and throw `RangeError` if they exceed
them. For a custom batch, use `validate` to check these limits or `split` to
divide the writes into separate atomic Puts. Splitting can separate an
artifact's rows. Readers and writers must use the same Store prefix.

## Read verified certificates

Certificate reads pass stored records to a `SimplexCertificateVerifier` and
return its verified result. For Commonware certificates, use the bundled WASM
verifier with an application-specific `verifyHeader` callback. The WASM
verifier checks certificate signatures against your trusted configuration and
returns the signed epoch, view and payload with the attached header. For round
reads, it also checks that the signed epoch and view match the requested index.

Your `verifyHeader` callback authenticates the attached header against the
signed payload and enforces any application-specific epoch or header rules.
For height or latest reads, it must also match the header's height to
`context.height`. The following example requires this callback when creating
the verifier:

```ts
import { StoreClient } from '@exowarexyz/sdk';
import {
  SimplexReader,
  type SimplexHeaderVerifier,
  type SimplexVerifierOptions,
} from '@exowarexyz/simplex';
import { createWasmSimplexVerifier } from '@exowarexyz/simplex/wasm';

async function readLatest(
  storeUrl: string,
  options: SimplexVerifierOptions & { verifyHeader: SimplexHeaderVerifier },
) {
  const verifier = await createWasmSimplexVerifier(options);
  const store = new StoreClient(storeUrl).unprefixed();
  return new SimplexReader(store, { verifier }).latestFinalization();
}
```

The API permits omitting `verifyHeader`, but then a successful result certifies
the payload without authenticating the attached header or height index. The
example requires the callback to check them.

Choose `scheme`, `payload`, `identity`, `namespace` and `verificationMaterial`
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
header bytes with `getHeader` or decode a `{ header, body }` envelope with
`getBlock`. Neither method authenticates its contents. Since certificate records
contain no body, fetch the block separately and check its body against the
application's header commitment. The `createWasmSimplexHeaderVerifier` and
`createWasmSimplexBlockVerifier` adapters wrap application-owned WASM checks.

Reads through `new SimplexReader(store)` use a monotonic session with no initial
minimum, and clones share observed Store sequences. Use
`SimplexReader.withSession` to supply an existing SDK `ReadSession`, or
`withMinSequenceNumber` to require reads at or after a publication sequence. A
fixed session sets a minimum, not a historical snapshot.

[`SimplexSubscriptions`](./src/subscriptions.ts) streams Store updates.
`subscribeCertificates` uses the same verifier contract as certificate reads.
`subscribeCertificatesRaw`, `subscribeHeaders` and `subscribeBlocks` return
unverified artifacts.
