/**
 * A verified cardano-database v2 restore, as `mithril-client cardano-db download` does it
 * (mithril-client `CardanoDatabaseClient` + `MithrilCertificateVerifier`), with the steps exposed:
 *
 *   1. list the aggregator's snapshots and pick one (a hash, or the newest);
 *   2. verify its certificate chain back to the genesis certificate (genesis key: compiled in per
 *      network, or given);
 *   3. download and unpack the immutable archives of the requested range (resuming: complete trios
 *      already on disk are kept), and optionally the ancillary archive, whose files are checked
 *      against its Ed25519-signed manifest;
 *   4. download the digests list, check that the certificate signed its Merkle root, and hash every
 *      immutable file on disk against it (trios that differ, e.g. left by an older snapshot in a
 *      reused directory, are downloaded again once).
 *
 * The result is a directory in cardano-node's layout (`immutable/`, plus `ledger/` with the
 * ancillary files) every byte of which is certified. What to do with it (start a node on it,
 * import the ledger state) is the caller's business.
 */

import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

import { AggregatorClient, cachingRetriever, mithrilNetworkConfig } from "../aggregator";
import { ANCILLARY_VKEYS } from "../ancillary";
import type { Certificate } from "../certificate";
import type { CertificateStore } from "../certStore";
import { decodeGenesisVerificationKey, verifyCertificateChain, type ChainHop, type ChainVerifyResult } from "../verifier";
import { ancillaryImmutableDigests, verifyAncillaryDir, type AncillaryVerification } from "./ancillary";
import { downloadAncillary, downloadImmutableFile, downloadImmutableRange, findAncillaryLedgerDir, findImmutableDir } from "./download";
import { getCardanoDatabaseSnapshot, immutableUrlTemplate, listCardanoDatabaseSnapshots, resolveVerificationKey, selectSnapshot, type CardanoDatabaseSnapshotMessage } from "./snapshot";
import { describeVerification, fetchVerifiedDigests, verifyImmutableFiles, type ImmutableVerification, type VerifiedDigests } from "./verifyDownload";

/** `fetch`, or anything with its shape for the calls made here (one function serves every request). */
export type HttpFetch = (url: string) => Promise<Response>;

export type RestoreProgress =
    | { phase: "certificate"; verified: number; hop: ChainHop }
    | { phase: "download"; done: number; total: number; immutableFileNumber: number }
    | { phase: "ancillary"; received: number; total: number | null }
    | { phase: "verify"; message: string };

export type RestoreOptions = {
    /** preview, preprod or mainnet: default aggregator, genesis key and ancillary key. */
    network?: string;
    /** Aggregator URL, or a client of your own. */
    aggregator?: string | AggregatorClient;
    fetch?: HttpFetch;
    /** Genesis verification key: the key, a file path or a URL (default: the network's compiled-in key). */
    genesisVkey?: string;
    /** Snapshot hash, or "latest" (default). */
    snapshot?: string;
    downloadDir: string;
    /** Immutable file numbers to download, inclusive (default 0..beacon). */
    from?: number;
    to?: number;
    /** Parallel immutable downloads (default 8). */
    concurrency?: number;
    /** Also download and verify the ancillary archive (ledger state and the last immutable trio). */
    includeAncillary?: boolean;
    /** Ancillary verification key: the key, a file path or a URL (default: `ANCILLARY_VKEYS[network]`). */
    ancillaryVkey?: string;
    /** Download nothing; verify the immutable files already in `downloadDir`. */
    skipDownload?: boolean;
    /** Certificate cache: read before downloading, written once the chain verified. */
    certificateStore?: CertificateStore;
    log?: (m: string) => void;
    onProgress?: (p: RestoreProgress) => void;
};

export type RestoreResult = {
    snapshot: CardanoDatabaseSnapshotMessage;
    certificate: Certificate;
    chain: ChainVerifyResult;
    immutableDir: string;
    /** Present with `includeAncillary` (or when `skipDownload` finds a verified ancillary set). */
    ancillary: { ledgerDir: string | null; verification: AncillaryVerification } | null;
    downloaded: number[];
    skipped: number[];
    /** Trios downloaded again because the copy on disk did not match the certified digests. */
    refetched: number[];
    digests: VerifiedDigests;
    verification: ImmutableVerification;
};

/** Restore (or, with `skipDownload`, re-verify) a certified cardano-database snapshot into `downloadDir`. */
export async function restoreCardanoDatabase(o: RestoreOptions): Promise<RestoreResult> {
    const log = o.log ?? (() => {});
    const network = o.network;
    const netCfg = () => {
        if (!network) throw new Error("restoreCardanoDatabase: pass `network`, or both `aggregator` and `genesisVkey`");
        return mithrilNetworkConfig(network);
    };
    const client = o.aggregator instanceof AggregatorClient ? o.aggregator : new AggregatorClient(o.aggregator ?? netCfg().aggregator, o.fetch);
    const genesisVkey = o.genesisVkey ? await resolveVerificationKey(o.genesisVkey, o.fetch) : netCfg().genesisVkey;
    const downloadDir = resolve(o.downloadDir);
    await mkdir(downloadDir, { recursive: true });

    // 1. The snapshot.
    const item = selectSnapshot(await listCardanoDatabaseSnapshots(client), o.snapshot ?? "latest");
    log(`snapshot ${item.hash}: epoch ${item.beacon.epoch}, immutable file ${item.beacon.immutable_file_number}`);

    // 2. Its certificate chain.
    const retrieve = cachingRetriever(client, o.certificateStore);
    const certificate = await retrieve(item.certificate_hash);
    if (certificate.hash !== item.certificate_hash) throw new Error(`certificate ${item.certificate_hash}: aggregator returned ${certificate.hash}`);
    let verified = 0;
    const chain = await verifyCertificateChain(certificate, {
        genesisVkey: decodeGenesisVerificationKey(genesisVkey),
        retrieve,
        onHop: (hop) => o.onProgress?.({ phase: "certificate", verified: ++verified, hop }),
    });
    await retrieve.persist();
    log(`certificate chain verified: ${chain.hops.length} certificate(s) to genesis ${chain.genesisHash} (${(chain.ms / 1000).toFixed(1)} s)`);
    const snapshot = await getCardanoDatabaseSnapshot(client, item.hash);
    if (snapshot.certificate_hash !== certificate.hash || snapshot.merkle_root !== item.merkle_root) throw new Error(`snapshot ${item.hash}: detail differs from the listed item`);

    // 3. Downloads.
    const beacon = snapshot.beacon.immutable_file_number;
    const from = Math.max(0, o.from ?? 0);
    const to = Math.min(beacon, o.to ?? beacon);
    if (from > to) throw new Error(`invalid immutable range ${from}..${to} (beacon ${beacon})`);
    let immutableDir: string;
    let downloaded: number[] = [];
    let skipped: number[] = [];
    let ancillaryLedgerDir: string | null = null;
    let ancillaryWanted = !!o.includeAncillary;
    if (o.skipDownload) {
        const found = await findImmutableDir(downloadDir);
        if (!found) throw new Error(`no immutable files under ${downloadDir}`);
        immutableDir = found;
        ancillaryLedgerDir = await findAncillaryLedgerDir(downloadDir);
        ancillaryWanted ||= ancillaryLedgerDir != null;
    } else {
        log(`downloading immutable files ${from}..${to} into ${downloadDir}`);
        const r = await downloadImmutableRange({
            snapshot,
            downloadDir,
            from,
            to,
            concurrency: o.concurrency ?? 8,
            fetch: o.fetch,
            onProgress: (done, total, n) => o.onProgress?.({ phase: "download", done, total, immutableFileNumber: n }),
        });
        immutableDir = r.immutableDir;
        downloaded = r.downloaded;
        skipped = r.skipped;
        if (o.includeAncillary) {
            const a = await downloadAncillary({ snapshot, downloadDir, fetch: o.fetch, log, onBytes: (received, total) => o.onProgress?.({ phase: "ancillary", received, total }) });
            ancillaryLedgerDir = a.ledgerDir;
        }
    }

    // The ancillary files, against their signed manifest; its immutable trio joins the certified digests.
    let ancillary: RestoreResult["ancillary"] = null;
    let extraDigests = new Map<string, string>();
    if (ancillaryWanted) {
        const key = o.ancillaryVkey ? await resolveVerificationKey(o.ancillaryVkey, o.fetch) : network ? ANCILLARY_VKEYS[network.toLowerCase()] : undefined;
        if (!key) throw new Error("no ancillary verification key (pass `ancillaryVkey`)");
        o.onProgress?.({ phase: "verify", message: "verifying the ancillary manifest" });
        const verification = await verifyAncillaryDir(downloadDir, key, log);
        if (!verification.ok) throw new Error(`ancillary verification failed: ${verification.errors.join("; ")}`);
        extraDigests = ancillaryImmutableDigests(verification.manifest!);
        ancillary = { ledgerDir: ancillaryLedgerDir, verification };
    }

    // 4. The immutable files, against the certified digests.
    o.onProgress?.({ phase: "verify", message: "verifying the immutable files against the certified digests" });
    const digests = await fetchVerifiedDigests(snapshot, certificate, { fetch: o.fetch, log });
    const range = o.skipDownload ? { from: 0, to: -1 } : { from, to };
    let verification = await verifyImmutableFiles(immutableDir, range, digests, extraDigests);
    const refetched = [...new Set(verification.tampered.map((n) => parseInt(n, 10)).filter((n) => n >= range.from && n <= range.to))].sort((a, b) => a - b);
    if (refetched.length) {
        log(`${refetched.length} trio(s) on disk differ from the certified digests (${refetched.slice(0, 5).join(", ")}); downloading them again`);
        const template = immutableUrlTemplate(snapshot);
        for (const n of refetched) await downloadImmutableFile({ template, number: n, downloadDir, skipIfPresent: false, fetch: o.fetch });
        verification = await verifyImmutableFiles(immutableDir, range, digests, extraDigests);
    }
    const problem = describeVerification(verification);
    if (problem) throw new Error(`immutable files do not match the certified snapshot: ${problem}${verification.nonVerifiable.length ? " (files left from another snapshot: use a fresh download directory)" : ""}`);
    log(`immutable files verified: ${verification.checked} file(s) match the certified digests (merkle root ${digests.merkleRoot})`);

    return { snapshot, certificate, chain, immutableDir, ancillary, downloaded, skipped, refetched, digests, verification };
}
