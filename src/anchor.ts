/**
 * A Mithril-certified starting point for Gerolamino:
 *   1. the aggregator's newest cardano-database snapshot (JSON over `fetch`);
 *   2. its certificate verified back to the genesis certificate signed with the network's genesis
 *      key (verifier.ts);
 *   3. the certificate certifies that snapshot: its signed entity is CardanoDatabase with the
 *      snapshot's epoch and immutable file number, and its signed message binds the snapshot's
 *      Merkle root;
 *   4. the aggregator's digests list reproduces that Merkle root (mkTree.ts);
 *   5. the last certified chunk (the beacon's immutable file) comes from the relay over the
 *      light-query protocol, and its three files hash (SHA-256) to their certified digests;
 *   6. that chunk's last block (slot, header hash) is the certified point to intersect at.
 * The relay and the aggregator only supply bytes; every trust decision rests on the genesis key.
 */

import { blake2b_256 } from "./hl";

import { AggregatorClient, cachingRetriever, fetchGenesisVkey, mithrilNetworkConfig, type FetchLike } from "./aggregator";
import { bytesEqual, bytesToHex } from "./bytes";
import { cardanoDatabaseMessageMatches, CertificateError } from "./certificate";
import { OpfsCertificateStore, type CertificateStore } from "./certStore";
import { lastBlockOfChunk } from "./chunkIndex";
import { sha256Async } from "./hash";
import { cardanoDatabaseMerkleRoot, certifiedDigests, type ImmutableFileDigest } from "./mkTree";
import { decodeGenesisVerificationKey, verifyCertificateChain } from "./verifier";
import { rememberVerified } from "./chainCache";

export type ChunkFiles = { chunk: Uint8Array; primary: Uint8Array; secondary: Uint8Array };

/** The light-query methods the anchor uses (the node's LightQueryClient satisfies it). */
export interface MithrilLightQuery {
    /** A complete immutable chunk (the three files) from the relay, or null when it does not have it. */
    chunk(chunkNo: number): Promise<ChunkFiles | null>;
    /** Mithril digests of the peer's immutable files from..to; null when it does not serve them (yet). */
    digests?(from: number, to: number): Promise<{ from: number; to: number; entries: ImmutableFileDigest[] } | null>;
}
export type LightQueryClient = MithrilLightQuery;

export interface MithrilAnchor {
    network: string;
    snapshotHash: string;
    certificateHash: string;
    epoch: number;
    immutableFileNumber: number;
    merkleRoot: string;
    chunkNo: number;
    /** Slot of the certified point (the last block of the chunk). */
    slot: number;
    /** Header hash (hex) of the certified point. */
    hash: string;
    blocksInChunk: number;
    /** Human summary of the chain walk, e.g. "walked 330 certificates to genesis d6b8be9f…". */
    certificatesWalked: string;
    genesisCertificateHash: string;
    chain: { certificates: number; cacheHits: number; downloads: number; walkMs: number; verifyMs: number };
    /** Where the immutable file digests came from (both are checked against the certified Merkle root). */
    digestsSource: "peer" | "aggregator";
    digestsMs: number;
}

export type MithrilAnchorOptions = {
    network: string;
    lq: MithrilLightQuery;
    log?: (l: string) => void;
    /** Aggregator base URL (default: the network's IOG aggregator). */
    aggregator?: string;
    /** Genesis verification key (JSON hex or bytes hex); "fetch" downloads the published file. Default: compiled in. */
    genesisVkey?: string | "fetch";
    /** Snapshot to anchor on (default: the newest one whose beacon chunk the relay has). */
    snapshotHash?: string;
    /** How many of the newest snapshots to try when the relay lacks a beacon chunk (default 5). */
    maxSnapshots?: number;
    /**
     * Certificate cache. Default: OPFS (`mithril-ts/certs/<network>`) where the runtime has
     * it, none elsewhere; null disables it.
     */
    store?: CertificateStore | null;
    fetch?: FetchLike;
    /**
     * Where to get the immutable file digests: the Gerolamo peer (fast; default) or the Mithril aggregator (direct,
     * 10 MB on preview, slow). Either way they must reproduce the certified Merkle root; a peer whose digests do not
     * (or that has none) falls back to the aggregator.
     */
    digestsFrom?: "peer" | "aggregator";
};

const hasOpfs = (): boolean => typeof (globalThis as { navigator?: { storage?: { getDirectory?: unknown } } }).navigator?.storage?.getDirectory === "function";

export async function mithrilAnchor(opts: MithrilAnchorOptions): Promise<MithrilAnchor> {
    const log = opts.log ?? (() => {});
    const cfg = mithrilNetworkConfig(opts.network);
    const client = new AggregatorClient(opts.aggregator ?? cfg.aggregator, opts.fetch);
    const store = opts.store === undefined ? (hasOpfs() ? OpfsCertificateStore.forNetwork(cfg.network) : undefined) : (opts.store ?? undefined);

    // Pick the snapshot: the newest whose beacon chunk the relay can serve. The chunk bytes are
    // only trusted after they match the certified digests below.
    log(`Mithril: listing snapshots at ${client.base}`);
    let hashes: string[];
    if (opts.snapshotHash) {
        hashes = [opts.snapshotHash];
    } else {
        const list = await client.listCardanoDatabase();
        if (!Array.isArray(list) || list.length === 0) throw new Error("Mithril: the aggregator lists no cardano-database snapshot");
        hashes = list.slice(0, Math.max(1, opts.maxSnapshots ?? 5)).map((s) => s.hash);
    }
    let detail: Awaited<ReturnType<AggregatorClient["cardanoDatabase"]>> | null = null;
    let files: ChunkFiles | null = null;
    for (const h of hashes) {
        const d = await client.cardanoDatabase(h);
        if (d.network !== cfg.network) throw new Error(`Mithril: snapshot is for ${d.network}, not ${cfg.network}`);
        log(`Mithril: snapshot ${d.hash.slice(0, 16)}… epoch ${d.beacon.epoch}, immutable file ${d.beacon.immutable_file_number}; asking the relay for that chunk`);
        files = await opts.lq.chunk(d.beacon.immutable_file_number);
        if (files) {
            detail = d;
            break;
        }
        log(`Mithril: the relay does not have complete chunk ${d.beacon.immutable_file_number}`);
    }
    if (!detail || !files) throw new Error("Mithril: the relay has none of the certified snapshots' last chunks (try later, or a relay further along)");
    const n = detail.beacon.immutable_file_number;

    // the digests download runs while the certificate chain is walked
    const merkleRoot = detail.merkle_root.toLowerCase();
    const digestsJob = loadDigests(client, opts, n, merkleRoot, log);
    digestsJob.catch(() => {});

    const vkeyText = opts.genesisVkey === "fetch" ? await fetchGenesisVkey(cfg.genesisVkeyUrl, opts.fetch) : (opts.genesisVkey ?? cfg.genesisVkey);
    const genesisVkey = decodeGenesisVerificationKey(vkeyText);

    const retrieve = cachingRetriever(client, store);
    const cert = await retrieve(detail.certificate_hash);
    if (cert.hash !== detail.certificate_hash) throw new CertificateError("CertificateRetrieve", `asked ${detail.certificate_hash}, got ${cert.hash}`);
    // The certificate must certify this snapshot (checked first, so a mismatch fails before the walk;
    // it counts only once the chain below has verified).
    const set = cert.signature.kind === "multi" ? cert.signature.signedEntityType : null;
    if (!set || set.type !== "CardanoDatabase" || set.epoch !== BigInt(detail.beacon.epoch) || set.immutableFileNumber !== BigInt(n)) {
        throw new Error(`Mithril: certificate ${cert.hash.slice(0, 16)}… does not certify cardano-database epoch ${detail.beacon.epoch} immutable file ${n}`);
    }
    if (!cardanoDatabaseMessageMatches(cert, detail.merkle_root)) throw new Error("Mithril: the certificate does not sign the snapshot's Merkle root");

    log(`Mithril: verifying the certificate chain from ${cert.hash.slice(0, 16)}… back to genesis`);
    const chain = await verifyCertificateChain(cert, {
        genesisVkey,
        retrieve,
        yieldEvery: 1,
        onHop: (h) => {
            if (h.kind === "genesis") log(`Mithril: genesis certificate ${h.hash.slice(0, 16)}… (epoch ${h.epoch}) verified`);
        },
    });
    if (!chain.genesisHash) throw new Error("Mithril: certificate chain did not reach genesis");
    rememberVerified(chain.hops.map((h) => h.hash));
    const walked = `walked ${chain.hops.length} certificates to genesis ${chain.genesisHash.slice(0, 16)}… in ${(chain.ms / 1000).toFixed(1)} s (${(chain.verifyMs / 1000).toFixed(1)} s verifying)`;
    log(`Mithril: certificate chain OK: ${walked}; ${retrieve.stats.hits} of ${retrieve.stats.hits + retrieve.stats.misses} certificates from the cache`);
    await retrieve.persist();

    const { digests, source: digestsSource, ms: digestsMs } = await digestsJob;
    log(`Mithril: ${certifiedDigests(digests, n).length} file digests from the ${digestsSource} reproduce the certified Merkle root (${(digestsMs / 1000).toFixed(1)} s)`);

    const name = n.toString().padStart(5, "0");
    const want = new Map(certifiedDigests(digests, n).filter((d) => d.immutable_file_name.startsWith(`${name}.`)).map((d) => [d.immutable_file_name, d.digest.toLowerCase()]));
    if (want.size !== 3) throw new Error(`Mithril: digests for ${name}.* are not in the certified list`);
    for (const [ext, bytes] of [["chunk", files.chunk], ["primary", files.primary], ["secondary", files.secondary]] as const) {
        const got = bytesToHex(await sha256Async(bytes));
        if (got !== want.get(`${name}.${ext}`)) throw new Error(`Mithril: ${name}.${ext} from the relay does not match its certified digest`);
    }

    const { entry, blocks } = lastBlockOfChunk(files.primary, files.secondary);
    // The header bytes are certified (the chunk digest); check the index's hash against them (Shelley and later).
    const hdrStart = entry.blockOffset + entry.headerOffset;
    const eraTag = files.chunk[entry.blockOffset + 1];
    if (!entry.isEbb && eraTag !== undefined && eraTag >= 2 && hdrStart + entry.headerSize <= files.chunk.length) {
        const h = blake2b_256(files.chunk.subarray(hdrStart, hdrStart + entry.headerSize));
        if (!bytesEqual(h, entry.headerHash)) throw new Error(`Mithril: chunk ${n}: last block's header does not hash to its index entry`);
    }
    const hash = bytesToHex(entry.headerHash);
    log(`Mithril: certified point = slot ${entry.slotOrEbb} hash ${hash.slice(0, 16)}… (last block of chunk ${n})`);
    return {
        network: detail.network,
        snapshotHash: detail.hash,
        certificateHash: cert.hash,
        epoch: detail.beacon.epoch,
        immutableFileNumber: n,
        merkleRoot: detail.merkle_root,
        chunkNo: n,
        slot: entry.slotOrEbb,
        hash,
        blocksInChunk: blocks,
        certificatesWalked: walked,
        genesisCertificateHash: chain.genesisHash,
        chain: { certificates: chain.hops.length, cacheHits: retrieve.stats.hits, downloads: retrieve.stats.misses, walkMs: chain.ms, verifyMs: chain.verifyMs },
        digestsSource,
        digestsMs,
    };
}

/** Digests of immutable files 0..n that reproduce `merkleRoot`: from the peer when it serves them, else the aggregator. */
export async function loadDigests(client: AggregatorClient, opts: MithrilAnchorOptions, n: number, merkleRoot: string, log: (l: string) => void): Promise<{ digests: ImmutableFileDigest[]; source: "peer" | "aggregator"; ms: number }> {
    const t0 = performance.now();
    if ((opts.digestsFrom ?? "peer") === "peer" && opts.lq.digests) {
        try {
            const all: ImmutableFileDigest[] = [];
            let from = 0, missing = false;
            while (from <= n) {
                const page = await opts.lq.digests(from, n);
                if (!page || page.to < from) { missing = true; break; }
                all.push(...page.entries);
                from = page.to + 1;
            }
            if (missing) log(`Mithril: the peer has no digests up to immutable file ${n} yet; asking the aggregator`);
            else {
                const root = cardanoDatabaseMerkleRoot(all, n);
                if (root === merkleRoot) return { digests: all, source: "peer", ms: performance.now() - t0 };
                log(`Mithril: the peer's digests give Merkle root ${root.slice(0, 16)}…, not the certified one; asking the aggregator`);
            }
        } catch (e) { log(`Mithril: digests from the peer failed (${(e as Error).message}); asking the aggregator`); }
    }
    log(`Mithril: downloading the digests from the aggregator`);
    const digests = await client.cardanoDatabaseDigests();
    const root = cardanoDatabaseMerkleRoot(digests, n);
    if (root !== merkleRoot) throw new Error(`Mithril: digests give Merkle root ${root}, the certificate signed ${merkleRoot}`);
    return { digests, source: "aggregator", ms: performance.now() - t0 };
}
