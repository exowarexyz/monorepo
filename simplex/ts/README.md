# @exowarexyz/simplex

Upload, read and subscribe to Commonware Simplex artifacts in Exoware Store.
The package shares the [Rust package's](../rs/README.md) key layout and provides
a browser WASM verifier for Commonware certificates.

## Upload artifacts

`SimplexWriter` accepts encoded bytes. Headers and full `{ header, body }`
blocks are indexed by digest, notarizations and finalizations by epoch and view,
and finalizations also by height. Supply a certificate record encoded as the
Commonware proof followed by its application header. The writer trusts the
supplied indices, so they must match the encoded artifact.

This function publishes a full block and its finalization in one Store Put:

```ts
import { Client, StoreWriteBatch } from '@exowarexyz/sdk';
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
  const store = new Client(storeUrl).store();
  const writer = new SimplexWriter(store);
  const batch = new StoreWriteBatch();
  writer.stageUpload(writer.prepareBlock(block), batch);
  writer.stageUpload(writer.prepareFinalization(finalization), batch);
  return batch.commit(store);
}
```

For a single artifact, use the corresponding `upload*` method. Uploads validate
Store limits before sending and throw `RangeError` if they exceed them. A custom
batch can use `validate` or `split`, but splitting creates separate atomic Puts
and can separate an artifact's rows. See the [SDK guide](../../sdk/ts/README.md)
for Store prefixes, limits and batching. Readers and writers must use the same
Store prefix.

## Read verified certificates

Certificate reads require a `SimplexCertificateVerifier` and return its result.
Use the bundled verifier for Commonware certificates. Source builds require
Rust's `wasm32-unknown-unknown` target, `wasm-pack`, and `wasm-bindgen-cli`. The
[TypeScript CI workflow](../../.github/workflows/typescript.yml) lists compatible
tool versions. Generate the WASM module from the repository root:

```bash
npm --prefix simplex/ts run build:wasm
```

Supply trusted verifier options and an application-specific `verifyHeader`
callback. The callback authenticates your header format as described below:

```ts
import { Client } from '@exowarexyz/sdk';
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
  const store = new Client(storeUrl).store();
  return new SimplexReader(store, { verifier }).latestFinalization();
}
```

Choose `scheme`, `payload`, `identity`, `namespace` and `verificationMaterial`
from trusted application configuration for the expected network and epoch.
The signing namespace is separate from the Store prefix. Verification material
is Commonware-encoded public key data: a participant set for Ed25519, an
identity-to-signing-key map for Secp256r1 or BLS multisig, or a threshold public
identity for threshold schemes. See [`SimplexVerifierOptions`](./src/verification.ts)
for supported schemes, payload types and identity types, and the
[WASM decoder](../rs/wasm/src/lib.rs) for the corresponding key encodings.

The WASM verifier checks certificate signatures and returns the signed epoch,
view and payload with the attached header. Round reads also require the signed
epoch and view to match the requested index. `verifyHeader` must authenticate
the header against that payload and, for height or latest reads, match the
header's height to `context.height`. It also enforces any application-specific
epoch or header rules. Select validator keys from trusted configuration, even
when a certificate reports its epoch.

`verifyHeader` is optional in the API. Without it, a successful result certifies
the payload but leaves the attached header and height index unauthenticated.
Applications with their own certificate format can implement
`SimplexCertificateVerifier`. They own signature, epoch, view, height and header
checks against the supplied context. Failed verification throws. A missing
record returns `null`.

## Raw reads and subscriptions

Use certificate methods ending in `Raw` for unverified bytes. `getHeader`
returns header bytes and `getBlock` decodes the `{ header, body }` envelope.
Neither authenticates its contents. Certificate records contain no body. Fetch
the block separately and check its body against the application's header
commitment. The `createWasmSimplexHeaderVerifier` and
`createWasmSimplexBlockVerifier` adapters wrap application-owned WASM checks.

`new SimplexReader(store)` starts a monotonic session with no initial minimum,
and clones share observed Store sequences. `SimplexReader.withSession` accepts
an SDK `ReadSession`. `withMinSequenceNumber` requires reads at or after a
publication sequence. A fixed session sets a minimum, not a historical snapshot.

[`SimplexSubscriptions`](./src/subscriptions.ts) streams Store updates.
`subscribeCertificates` uses the same verifier contract as certificate reads.
`subscribeCertificatesRaw`, `subscribeHeaders` and `subscribeBlocks` return
unverified artifacts. See the [reader](./src/reader.ts),
[writer](./src/writer.ts) and [verification types](./src/verification.ts) for
method signatures and result types.
