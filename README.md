# @harmoniclabs/mithril-ts

Mithril in pure TypeScript. Verifies Mithril certificates and the artifacts they sign, and downloads, produces and
serves cardano-node snapshots, so a Cardano node or a browser can start from a certified point without the Rust
client.

- **Core** (`@harmoniclabs/mithril-ts`): browsers, Bun and Node. Runtime dependency: `@harmoniclabs/crypto` only.
- **Node tooling** (`@harmoniclabs/mithril-ts/node`): Bun and Node. Adds file and network I/O with runtime
  built-ins only (`node:fs`, `node:zlib` for zstd, `node:crypto`, `fetch`).

## Core

| Area | What | Main exports |
|---|---|---|
| Certificates | parse, hash, verify a chain to genesis: STM concatenation proofs over BLS12-381, strict Ed25519 genesis signatures | `parseCertificate`, `verifyCertificateChain`, `verifyChainCached`, `computeCertificateHash` |
| Aggregator | network config with compiled-in genesis keys, HTTP client with injectable `fetch`, certificate cache | `mithrilNetworkConfig`, `AggregatorClient`, `cachingRetriever`, `MemoryCertificateStore`, `OpfsCertificateStore` |
| Cardano database | Merkle root of the immutable file digests, message match, snapshot hash | `cardanoDatabaseMerkleRoot`, `certifiedDigests`, `cardanoDatabaseMessageMatches`, `cardanoDatabaseSnapshotHash`, `MkTree` |
| Stake distribution | CardanoStakeDistribution artifact, Merkle root, certificate check | `mithrilStake`, `stakeDistributionMerkleRoot`, `stakeMessageMatches` |
| Transactions | CardanoTransactions proofs (Merkle map of block ranges over an MMR) | `mithrilTxProof`, `verifyTransactionsProof`, `mmrRoot` |
| Ancillary files | ledger-state manifest: SHA-256 entries, Ed25519 signature (strict) | `parseAncillaryManifest`, `verifyAncillaryManifestSignature`, `ANCILLARY_VKEYS` |
| Certified start | from a snapshot to a certified chain point, with the immutable chunk from any source | `mithrilAnchor`, `loadDigests` |
| Formats | ustar writer and readers (streaming for multi-GB archives), cardano-node chunk index | `buildTar`, `readTar`, `TarStreamReader`, `lastBlockOfChunk` |

```ts
import { AggregatorClient, cachingRetriever, decodeGenesisVerificationKey, mithrilNetworkConfig, verifyCertificateChain } from "@harmoniclabs/mithril-ts";

const cfg = mithrilNetworkConfig("preview");
const client = new AggregatorClient(cfg.aggregator);
const retrieve = cachingRetriever(client);
const cert = await retrieve(await client.latestCertificateHash());
const chain = await verifyCertificateChain(cert, { genesisVkey: decodeGenesisVerificationKey(cfg.genesisVkey), retrieve });
console.log(`${chain.hops.length} certificates verified to genesis ${chain.genesisHash}`);
```

## Security notes

- Genesis and ancillary signatures use strict Ed25519 (canonical points and scalars, no small-order keys), as
  cardano-node and mithril-client do.
- BLS keys and signatures are decoded strictly (canonical coordinates, subgroup checks).
- Anything fetched (certificates, digests, artifacts) is trusted only after it reproduces what a verified certificate
  signs. A cache holds downloads, not verdicts: cached certificates are verified again on every walk.

## Tests

`bun test`. Fixtures are real preview and mainnet certificates and artifacts. `MITHRIL_CROSSCHECK=1` also runs every
certificate (plus about 100 tampered ones) through an independent implementation built on noble, when a Gerolamo
checkout sits next to this one.

## Origin

Extracted on 2026-10-26 from the Mithril code of the Gerolamo node and the Gerolamino browser node (HarmonicLabs),
which share it from now on.
