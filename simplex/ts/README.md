# @exowarexyz/simplex

TypeScript helpers for consuming Exoware-backed Commonware Simplex streams.

`SimplexClient.subscribeCertifiedBlocks` reads certificate metadata from SQL,
fetches the referenced raw block bytes from KV, and calls your verifier before
yielding the frame.

```ts
import { SimplexClient, wasmCertifiedBlockVerifier } from '@exowarexyz/simplex';

const client = new SimplexClient('http://127.0.0.1:8083', {
  storeUrl: 'http://127.0.0.1:8080',
  verifier: wasmCertifiedBlockVerifier({
    identity: '0x...',
    namespace: 'simplex-demo-...',
  }),
});

for await (const block of client.subscribeCertifiedBlocks({ kind: 'finalized' })) {
  console.log(block.height, block.blockDigest, block.encodedBlock);
}
```

`identity` is the committee identity encoded as hex. The demo seed command in
the Rust package prints both the identity and namespace it generated.
