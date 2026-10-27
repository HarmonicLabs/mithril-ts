# Changelog

## 0.1.0

First release, extracted from the Gerolamo and Gerolamino nodes.

- Certificate chains to genesis: STM concatenation proofs over BLS12-381, strict Ed25519 genesis signatures,
  certificate hashes, protocol message checks.
- Aggregator client with compiled-in genesis keys and injectable `fetch`; certificate caches (memory, OPFS).
- Cardano database Merkle root, snapshot hash and message match; CardanoStakeDistribution; CardanoTransactions
  proofs; ancillary manifests (strict Ed25519, which the code it replaces did not use).
- Certified start point from any source of immutable chunks and digests.
- ustar writer, in-memory reader and streaming reader.
- Node entry point (`@harmoniclabs/mithril-ts/node`): snapshot download and extraction (built-in zstd), digests of a
  chunk store, producing, certifying and serving cardano-database snapshots.
