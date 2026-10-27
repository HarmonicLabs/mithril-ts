/**
 * @harmoniclabs/mithril-ts/node: file and network tooling for Node (>= 22.15) and Bun.
 *
 * Restoring a cardano-database v2 snapshot (download, unpack, verify against the certificate chain,
 * the certified digests and the signed ancillary manifest), computing the digests of a chunk store,
 * producing the aggregator's artifacts from one and serving them over HTTP. Everything here builds on
 * the browser-safe core ("@harmoniclabs/mithril-ts") and uses only runtime built-ins on top of it:
 * node:fs, node:crypto, node:stream and node:zlib (zstd). Network access goes through an injectable
 * `fetch`; no module keeps state between calls.
 */

export { ANCILLARY_MANIFEST_FILE, ancillaryImmutableDigests, verifyAncillaryDir, type AncillaryVerification } from "./ancillary";
export { findCertifiedTarget, produceCertifiedSnapshot, type CertifiedTarget, type FindCertifiedTargetOptions, type ProduceCertifiedOptions } from "./certify";
export {
    computeImmutableDigests,
    DigestCache,
    immutableStem,
    immutableTrio,
    lastCompletedImmutable,
    listImmutableFiles,
    type ComputeDigestsOptions,
    type ImmutableFileInfo,
} from "./digests";
export {
    ARCHIVES_DIR,
    downloadAncillary,
    downloadImmutableFile,
    downloadImmutableRange,
    downloadToFile,
    findAncillaryLedgerDir,
    findImmutableDir,
    hasCompleteImmutableTrio,
    type AncillaryDownloadOptions,
    type AncillaryDownloadResult,
    type DownloadFetch,
    type ImmutableDownloadOptions,
    type ImmutableDownloadResult,
    type ImmutableRangeOptions,
    type ImmutableRangeResult,
} from "./download";
export { extractTar, extractTarZst, extractTarZstBytes, extractTarZstFile, tarEntryPath, type ByteSource, type ExtractOptions } from "./extract";
export { isFile, sha256File, writeFileAtomic, zstdCompress, zstdDecompress, ZSTD_LEVEL } from "./files";
export { archivePresent, buildDigestsArchive, buildImmutableArchive, produceCardanoDatabaseSnapshot, type ProduceOptions, type ProduceResult } from "./produce";
export { restoreCardanoDatabase, type HttpFetch, type RestoreOptions, type RestoreProgress, type RestoreResult } from "./restore";
export { createMithrilArtifactHandler, MITHRIL_API_VERSION, snapshotMessage, type MithrilArtifactHandler, type MithrilArtifactServerOptions } from "./server";
export {
    ancillaryUrl,
    fetchGenesisVkey,
    getCardanoDatabaseSnapshot,
    immutableUrlTemplate,
    listCardanoDatabaseSnapshots,
    locationUri,
    resolveVerificationKey,
    selectSnapshot,
    type CardanoDatabaseSnapshotListItem,
    type CardanoDatabaseSnapshotMessage,
    type MithrilLocation,
} from "./snapshot";
export { ArtifactStore, DOWNLOAD_DIR, type StoredSnapshot } from "./store";
export { describeVerification, fetchDigestList, fetchVerifiedDigests, parseDigestList, verifyImmutableFiles, type DigestsFetch, type ImmutableVerification, type VerifiedDigests } from "./verifyDownload";
