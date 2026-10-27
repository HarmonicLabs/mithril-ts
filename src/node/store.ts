/**
 * On-disk layout of a cardano-database v2 artifact store (what `produceCardanoDatabaseSnapshot`
 * writes and `createMithrilArtifactHandler` serves):
 *
 *   <root>/cardano-database-download/immutable/NNNNN.tar.zst    one archive per immutable trio
 *   <root>/cardano-database-download/digests/<stem>.tar.zst      digests list of one snapshot
 *   <root>/snapshots/<snapshot hash>.json                        snapshot record (written last)
 *   <root>/certificates/<certificate hash>.json                  certificate chain, as published
 *   <root>/digest-cache-<source id>.json                         digests already computed
 *
 * The download paths mirror the aggregator's `cardano-database-download` route
 * (mithril-aggregator `http_server/routes/artifact_routes/cardano_database.rs` with a local
 * file uploader), so the HTTP handler maps a URL path to a file without a lookup table.
 */

import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { parseJsonLossless } from "../json";
import { immutableStem } from "./digests";

export const DOWNLOAD_DIR = "cardano-database-download";

/** The record of one produced snapshot: the aggregator's `CardanoDatabaseSnapshotMessage` fields, plus where the chunks came from. */
export type StoredSnapshot = {
    hash: string;
    merkle_root: string;
    network: string;
    beacon: { epoch: number; immutable_file_number: number };
    /** Empty when no Mithril certificate signs this root. */
    certificate_hash: string;
    total_db_size_uncompressed: number;
    digests: { size_uncompressed: number; file: string };
    immutables: { average_size_uncompressed: number; archived: { from: number; to: number } };
    ancillary: { size_uncompressed: number };
    cardano_node_version: string;
    created_at: string;
    /** Where the chunks came from (not part of the aggregator message). */
    source: string;
};

const HASH = /^[0-9a-f]{64}$/;

async function readOrNull(path: string): Promise<string | null> {
    try {
        return await readFile(path, "utf8");
    } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw e;
    }
}

async function jsonFiles(dir: string): Promise<string[]> {
    try {
        return (await readdir(dir)).filter((n) => /^[0-9a-f]{64}\.json$/.test(n));
    } catch {
        return [];
    }
}

export class ArtifactStore {
    readonly root: string;
    constructor(root: string) {
        this.root = resolve(root);
    }

    immutableArchive(n: number): string {
        return join(this.root, DOWNLOAD_DIR, "immutable", `${immutableStem(n)}.tar.zst`);
    }

    digestsArchive(file: string): string {
        if (!/^[A-Za-z0-9._-]+$/.test(file) || file.startsWith(".")) throw new Error(`bad digests file name ${JSON.stringify(file)}`);
        return join(this.root, DOWNLOAD_DIR, "digests", file);
    }

    snapshotPath(hash: string): string {
        return join(this.root, "snapshots", `${hash}.json`);
    }

    certificatePath(hash: string): string {
        return join(this.root, "certificates", `${hash}.json`);
    }

    /** Digest cache file for one source directory (keyed by its absolute path). */
    digestCachePath(sourceDir: string): string {
        return join(this.root, `digest-cache-${createHash("sha256").update(resolve(sourceDir)).digest("hex").slice(0, 16)}.json`);
    }

    async readSnapshot(hash: string): Promise<StoredSnapshot | null> {
        if (!HASH.test(hash)) return null;
        const text = await readOrNull(this.snapshotPath(hash));
        return text == null ? null : (JSON.parse(text) as StoredSnapshot);
    }

    /** Snapshots, newest first (by immutable file number, then creation time). */
    async listSnapshots(): Promise<StoredSnapshot[]> {
        const dir = join(this.root, "snapshots");
        const out: StoredSnapshot[] = [];
        for (const name of await jsonFiles(dir)) {
            try {
                out.push(JSON.parse(await readFile(join(dir, name), "utf8")) as StoredSnapshot);
            } catch {
                /* partial write or foreign file: skip */
            }
        }
        out.sort((a, b) => b.beacon.immutable_file_number - a.beacon.immutable_file_number || b.created_at.localeCompare(a.created_at));
        return out;
    }

    /** Raw certificate JSON text as published by the aggregator, or null. */
    async readCertificateText(hash: string): Promise<string | null> {
        if (!HASH.test(hash)) return null;
        return readOrNull(this.certificatePath(hash));
    }

    /** Every stored certificate, parsed losslessly (u64 stakes stay exact). */
    async listCertificates(): Promise<Record<string, unknown>[]> {
        const dir = join(this.root, "certificates");
        const out: Record<string, unknown>[] = [];
        for (const name of await jsonFiles(dir)) {
            try {
                out.push(parseJsonLossless(await readFile(join(dir, name), "utf8")) as Record<string, unknown>);
            } catch {
                /* skip */
            }
        }
        return out;
    }
}
