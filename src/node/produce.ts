/**
 * Produce cardano-database v2 artifacts from a directory of immutable files (a cardano-node
 * `db/immutable`, or any chunk store in that format), in the aggregator's layout
 * (mithril-aggregator `CardanoDatabaseArtifactBuilder`):
 *
 * - one `NNNNN.tar.zst` per immutable trio, holding `immutable/NNNNN.{chunk,primary,secondary}`
 *   (`ImmutableArchiver`);
 * - `<network>-e<epoch>-i<n>.digests.tar.zst` holding `<stem>.json`, the list of
 *   `{immutable_file_name, digest}` for every file numbered 0..=n (`DigestArtifactBuilder`);
 * - a snapshot record (hash, merkle root, beacon, sizes, certificate hash), written last.
 *
 * Producing is read-only on the source directory. "Certified" means: the computed Merkle root is
 * exactly what a real Mithril certificate signed for the same immutable file number. A producer that
 * is not a registered Mithril signer cannot sign a new root itself; an uncertified snapshot is kept
 * but the server does not list it by default (a client could not verify it).
 */

import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

import { cardanoDatabaseMessageMatches, type Certificate } from "../certificate";
import { stringifyJsonLossless } from "../json";
import { cardanoDatabaseMerkleRoot, cardanoDatabaseSnapshotHash, digestsFileStem, type ImmutableFileDigest } from "../mkTree";
import { buildTar, type TarEntry } from "../tar";
import { computeImmutableDigests, DigestCache, immutableStem, immutableTrio, listImmutableFiles } from "./digests";
import { isFile, writeFileAtomic, zstdCompress, ZSTD_LEVEL } from "./files";
import type { ArtifactStore, StoredSnapshot } from "./store";

/**
 * Build the `NNNNN.tar.zst` archive of one trio. When `digests` holds a file's digest, the bytes
 * archived must still hash to it (the file did not change since it was digested).
 * Deterministic: the same files give the same archive bytes.
 */
export async function buildImmutableArchive(immutableDir: string, n: number, digests: Map<string, string> = new Map(), level = ZSTD_LEVEL): Promise<{ archive: Uint8Array; uncompressed: number }> {
    const entries: TarEntry[] = [];
    let uncompressed = 0;
    for (const name of immutableTrio(n)) {
        const data = new Uint8Array(await readFile(join(immutableDir, name)));
        const want = digests.get(name);
        if (want !== undefined) {
            const got = createHash("sha256").update(data).digest("hex");
            if (got !== want) throw new Error(`${name} changed since it was digested (${got.slice(0, 12)} != ${want.slice(0, 12)})`);
        }
        entries.push({ name: `immutable/${name}`, data });
        uncompressed += data.length;
    }
    return { archive: zstdCompress(buildTar(entries), level), uncompressed };
}

/** The digests archive of a snapshot: `<stem>.json` in a tar, zstd-compressed. */
export function buildDigestsArchive(stem: string, digests: readonly ImmutableFileDigest[], level = ZSTD_LEVEL): { archive: Uint8Array; json: Uint8Array } {
    const json = new TextEncoder().encode(JSON.stringify(digests));
    return { archive: zstdCompress(buildTar([{ name: `${stem}.json`, data: json }]), level), json };
}

export type ProduceOptions = {
    immutableDir: string;
    store: ArtifactStore;
    network: string;
    beacon: { epoch: number; immutableFileNumber: number };
    /** The certificate that signs this snapshot (CardanoDatabase beacon). Its chain is stored too. */
    certificate?: Certificate;
    /** Certificates to store for serving (default: `certificate` alone). */
    certificateChain?: Certificate[];
    /** Archives to build (default: all of 0..beacon). Digests always cover 0..beacon. */
    archiveRange?: { from: number; to: number };
    cardanoNodeVersion?: string;
    createdAt?: string;
    compressionLevel?: number;
    /** Digest cache (default: the store's cache file for this source directory). */
    digestCache?: DigestCache;
    log?: (m: string) => void;
};

export type ProduceResult = {
    snapshot: StoredSnapshot;
    merkleRoot: string;
    certified: boolean;
    digests: ImmutableFileDigest[];
    archivesWritten: number;
    archivesReused: number;
    seconds: number;
};

export async function produceCardanoDatabaseSnapshot(o: ProduceOptions): Promise<ProduceResult> {
    const t0 = performance.now();
    const log = o.log ?? (() => {});
    const n = o.beacon.immutableFileNumber;
    const level = o.compressionLevel ?? ZSTD_LEVEL;
    const files = listImmutableFiles(o.immutableDir);
    const cache = o.digestCache ?? (await DigestCache.load(o.store.digestCachePath(o.immutableDir)));
    log(`digesting immutable files 0..${n} of ${o.immutableDir}`);
    const digests = await computeImmutableDigests(o.immutableDir, { from: 0, to: n }, {
        cache,
        files,
        onProgress: (done, total) => log(`  digests ${done}/${total}`),
    });
    await cache.save();
    const merkleRoot = cardanoDatabaseMerkleRoot(digests, n);
    log(`merkle root ${merkleRoot} over ${digests.length} files`);

    let certified = false;
    if (o.certificate) {
        const c = o.certificate;
        const set = c.signature.kind === "multi" ? c.signature.signedEntityType : null;
        if (!set || set.type !== "CardanoDatabase") throw new Error(`certificate ${c.hash} does not sign a cardano database snapshot`);
        if (set.immutableFileNumber !== BigInt(n) || set.epoch !== BigInt(o.beacon.epoch)) {
            throw new Error(`certificate ${c.hash} signs beacon e${set.epoch}/i${set.immutableFileNumber}, not e${o.beacon.epoch}/i${n}`);
        }
        if (!cardanoDatabaseMessageMatches(c, merkleRoot)) {
            throw new Error(`computed merkle root ${merkleRoot} is not the root certificate ${c.hash} signed (${c.protocolMessage.get("cardano_database_merkle_root")})`);
        }
        certified = true;
        log(`certificate ${c.hash} signs this root`);
    }

    // Aggregator rule (compute_immutable_files_total_uncompressed_size): trios 1..=n, trio 0 excluded.
    let total = 0;
    for (const f of files) if (f.number >= 1 && f.number <= n) total += f.size;
    const digestMap = new Map(digests.map((d) => [d.immutable_file_name, d.digest]));

    const from = Math.max(0, o.archiveRange?.from ?? 0);
    const to = Math.min(n, o.archiveRange?.to ?? n);
    let written = 0;
    let reused = 0;
    for (let i = from; i <= to; i++) {
        const path = o.store.immutableArchive(i);
        if (await isFile(path)) {
            reused++;
            continue;
        }
        const { archive } = await buildImmutableArchive(o.immutableDir, i, digestMap, level);
        await writeFileAtomic(path, archive);
        written++;
        if (written % 1000 === 0) log(`  archives written ${written} (at ${immutableStem(i)})`);
    }
    log(`archives ${from}..${to}: ${written} written, ${reused} already present`);

    const stem = digestsFileStem(o.network, o.beacon.epoch, n);
    const digestsFile = `${stem}.tar.zst`;
    const da = buildDigestsArchive(stem, digests, level);
    await writeFileAtomic(o.store.digestsArchive(digestsFile), da.archive);

    for (const c of o.certificateChain ?? (o.certificate ? [o.certificate] : [])) {
        const p = o.store.certificatePath(c.hash);
        if (!(await isFile(p))) await writeFileAtomic(p, stringifyJsonLossless(c.raw));
    }

    const snapshot: StoredSnapshot = {
        hash: cardanoDatabaseSnapshotHash(o.beacon.epoch, merkleRoot),
        merkle_root: merkleRoot,
        network: o.network,
        beacon: { epoch: o.beacon.epoch, immutable_file_number: n },
        certificate_hash: certified ? o.certificate!.hash : "",
        total_db_size_uncompressed: total,
        digests: { size_uncompressed: da.json.length, file: digestsFile },
        immutables: { average_size_uncompressed: n > 0 ? Math.floor(total / n) : 0, archived: { from, to } },
        ancillary: { size_uncompressed: 0 },
        cardano_node_version: o.cardanoNodeVersion ?? "",
        created_at: o.createdAt ?? new Date().toISOString(),
        source: o.immutableDir,
    };
    // Written last: a snapshot is listed only once all its files are in place.
    await writeFileAtomic(o.store.snapshotPath(snapshot.hash), JSON.stringify(snapshot, null, 1));
    return { snapshot, merkleRoot, certified, digests, archivesWritten: written, archivesReused: reused, seconds: (performance.now() - t0) / 1000 };
}

/** True when the store holds the archive of immutable file number `n`. */
export function archivePresent(store: ArtifactStore, n: number): Promise<boolean> {
    return isFile(store.immutableArchive(n));
}
