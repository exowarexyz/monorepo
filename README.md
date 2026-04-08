# exoware

[License: MIT](./LICENSE-MIT)
[License: Apache 2.0](./LICENSE-APACHE)
[Ask DeepWiki](https://deepwiki.com/exowarexyz/monorepo)

## Primitives

*Primitives are designed for production use. If you find an exploit, please refer to our [security policy](./SECURITY.md) before disclosing it publicly (an exploit may equip a malicious party to attack users of a primitive).*

- [sdk-rs](./sdk-rs/README.md): Rust store SDK (shared types, key/value codec, prune policy, protobuf bindings generated from [`proto/`](./proto/)).
- [sdk-ts](./sdk-ts/README.md): TypeScript SDK for the Exoware store API.
- [exoware-server](./server/Cargo.toml): Pluggable store server (`StoreEngine`).
- [simulator](./simulator/README.md): Local store API simulator (RocksDB).
- [exoware-qmdb](./qmdb/README.md): Commonware QMDB bridge.
- [exoware-sql](./sql/README.md): DataFusion SQL layer.

*The service schema source of truth lives under [`proto/`](./proto).*

## Examples

*Examples may include insecure code (i.e. deriving keypairs from an integer arguments) to make them easier to run. Examples are not intended to be used directly in production.*

- [alto](https://github.com/commonwarexyz/alto): A minimal (and wicked fast) blockchain built with the Commonware Library.
- [sandbox](./examples/sandbox): Explore the Exoware API.

## Licensing

This repository is dual-licensed under both the [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses. You may choose either license when employing this code.

## Contributing

We encourage external contributors to submit issues and pull requests to the Exoware Library. To learn more, please refer to our [contributing guidelines](./CONTRIBUTING.md).

## Support

If you have any questions about using the Exoware Library, we encourage you to post in [GitHub Discussions](https://github.com/exowarexyz/monorepo/discussions). We're happy to help!