# @exowarexyz/simplex

TypeScript helpers for uploading Commonware Simplex artifacts into Exoware
Store. The package mirrors the Rust `exoware-simplex` key layout:

- block by digest
- notarized bytes by Simplex view
- finalized bytes by Simplex view
- finalized bytes by block height

The TypeScript client uploads raw encoded bytes. Certificate reads verify bytes
before returning when the client is constructed with a verifier. Use the `*Raw`
read methods when you explicitly want unverified bytes.

```ts
import { SimplexClient } from '@exowarexyz/simplex';

const simplex = new SimplexClient('http://localhost:10000');
await simplex.uploadFinalization({
  view: 42n,
  height: 42n,
  digest: '0x...',
  block: '0x...',
  finalized: '0x...',
});
```

Use `prepareBlock`, `prepareNotarization`, and `prepareFinalization` to stage
multiple Simplex rows into one `StoreWriteBatch`. Finalizations are stored by
view and by height so callers can fetch a specific view or the latest finalized
height index.

## Verification

Pass a `SimplexCertificateVerifier` to verify opaque certificate records before
`getNotarization`, `getFinalizationByView`, `getFinalizationByHeight`,
`latestFinalization`, or `subscribeCertificates` returns them:

```ts
import { SimplexClient, type SimplexCertificateVerifier } from '@exowarexyz/simplex';

const verifier: SimplexCertificateVerifier = {
  verifyNotarization: async (bytes, context) => verifyMyNotarization(bytes, context.view),
  verifyFinalization: async (bytes, context) => verifyMyFinalization(bytes, context.index),
};

const simplex = new SimplexClient('http://localhost:10000', { verifier });
const latest = await simplex.latestFinalization();
```

The generic `createWasmSimplexVerifier` adapter supports caller-owned WASM
modules that expose `verify_notarized` / `verify_finalized` functions and treat
certificates as opaque values.

For upstream Commonware Simplex certificate types, build the optional WASM
module and use `@exowarexyz/simplex/wasm`:

```bash
npm --prefix simplex/ts run build:wasm
```

```ts
import { createCommonwareWasmSimplexVerifier } from '@exowarexyz/simplex/wasm';
import { SimplexClient, hexToBytes } from '@exowarexyz/simplex';

const verifier = await createCommonwareWasmSimplexVerifier({
  scheme: 'bls12381-threshold-vrf-min-sig',
  namespace: new TextEncoder().encode('_MY_SIMPLEX_NAMESPACE'),
  verificationMaterial: hexToBytes('...'),
});

const simplex = new SimplexClient('http://localhost:10000', { verifier });
```

Supported Commonware schemes are `ed25519`, `secp256r1`,
`bls12381-multisig-min-pk`, `bls12381-multisig-min-sig`,
`bls12381-threshold-standard-min-pk`,
`bls12381-threshold-standard-min-sig`, `bls12381-threshold-vrf-min-pk`, and
`bls12381-threshold-vrf-min-sig`. Verification material is encoded Commonware
key material: an Ed25519 participant set, a Secp256r1/BLS multisig
identity-to-signing-key map, or a threshold identity depending on the scheme.
