/**
 * Cardano database v2 digests of a directory of immutable files, as mithril-common computes them.
 *
 * - Every immutable file (`NNNNN.chunk`, `.primary`, `.secondary`) gets a digest:
 *   hex(SHA-256(file bytes)) (`ImmutableFile::compute_raw_hash::<Sha256>`).
 * - The signed Merkle root is the MKTree over the digests of every file numbered 0..=beacon
 *   (`CardanoImmutableDigester::compute_merkle_tree`): core `cardanoDatabaseMerkleRoot`.
 * - The highest-numbered trio on disk is the one cardano-node is still appending to, so it is never
 *   digested (mithril-signer `ImmutableFileObserver` signs up to the last completed number).
 *
 * Immutable files never change once complete, so digests are worth keeping across runs:
 * `DigestCache` keys them by file name and invalidates on any size or mtime change.
 */

import { readdirSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { ImmutableFileDigest } from "../mkTree";
import { sha256File, writeFileAtomic } from "./files";

const IMMUTABLE_FILE = /^(\d{5,})\.(chunk|primary|secondary)$/;
const EXT_ORDER: Record<string, number> = { chunk: 0, primary: 1, secondary: 2 };
const TRIO = ["chunk", "primary", "secondary"] as const;

/** Five-digit (or wider) immutable file number, as in `00042.chunk`. */
export const immutableStem = (n: number): string => String(n).padStart(5, "0");

/** The three file names of an immutable file number. */
export const immutableTrio = (n: number): string[] => TRIO.map((e) => `${immutableStem(n)}.${e}`);

export type ImmutableFileInfo = { number: number; name: string; path: string; size: number; mtimeMs: number };

/** Immutable files of a directory, ordered by number then chunk, primary, secondary (mithril `ImmutableFile` order). */
export function listImmutableFiles(immutableDir: string): ImmutableFileInfo[] {
    const out: ImmutableFileInfo[] = [];
    for (const name of readdirSync(immutableDir)) {
        const m = IMMUTABLE_FILE.exec(name);
        if (!m) continue;
        const path = join(immutableDir, name);
        const st = statSync(path);
        if (!st.isFile()) continue;
        out.push({ number: Number(m[1]), name, path, size: st.size, mtimeMs: st.mtimeMs });
    }
    out.sort((a, b) => a.number - b.number || EXT_ORDER[a.name.split(".")[1]!]! - EXT_ORDER[b.name.split(".")[1]!]!);
    return out;
}

/**
 * The newest immutable file number whose trio is complete: every number below the highest one on
 * disk (the highest chunk is still being written by the node), when 0..n all have their three files.
 */
export function lastCompletedImmutable(files: ImmutableFileInfo[]): number | null {
    if (files.length === 0) return null;
    const max = files[files.length - 1]!.number;
    const counts = new Map<number, number>();
    for (const f of files) counts.set(f.number, (counts.get(f.number) ?? 0) + 1);
    let n = -1;
    while (n + 1 < max && counts.get(n + 1) === 3) n++;
    return n >= 0 ? n : null;
}

type CacheEntry = { size: number; mtimeMs: number; digest: string };

/**
 * File-name keyed digest cache, invalidated by size or mtime change. `path` null keeps it in memory
 * only; otherwise `load` reads it and `save` writes it atomically (JSON object of name to entry).
 */
export class DigestCache {
    private readonly entries = new Map<string, CacheEntry>();
    private dirty = false;
    constructor(readonly path: string | null = null) {}

    static async load(path: string | null): Promise<DigestCache> {
        const c = new DigestCache(path);
        if (path) {
            try {
                const doc = JSON.parse(await readFile(path, "utf8")) as Record<string, CacheEntry>;
                for (const [k, v] of Object.entries(doc)) {
                    if (v && typeof v.digest === "string" && typeof v.size === "number" && typeof v.mtimeMs === "number") c.entries.set(k, v);
                }
            } catch {
                /* absent or unreadable: start empty */
            }
        }
        return c;
    }

    get size(): number {
        return this.entries.size;
    }

    get(f: ImmutableFileInfo): string | null {
        const e = this.entries.get(f.name);
        return e && e.size === f.size && e.mtimeMs === f.mtimeMs ? e.digest : null;
    }

    set(f: ImmutableFileInfo, digest: string): void {
        this.entries.set(f.name, { size: f.size, mtimeMs: f.mtimeMs, digest });
        this.dirty = true;
    }

    async save(): Promise<void> {
        if (!this.path || !this.dirty) return;
        await writeFileAtomic(this.path, JSON.stringify(Object.fromEntries(this.entries)));
        this.dirty = false;
    }
}

export type ComputeDigestsOptions = {
    cache?: DigestCache;
    /** Called every 3000 files and at the end. */
    onProgress?: (done: number, total: number) => void;
    /** A listing already taken with `listImmutableFiles` (saves a directory scan). */
    files?: ImmutableFileInfo[];
};

/**
 * Digests of every immutable file numbered `from..=to`, in file order; all three files of each
 * number must exist. Files are only read.
 */
export async function computeImmutableDigests(immutableDir: string, range: { from: number; to: number }, opts: ComputeDigestsOptions = {}): Promise<ImmutableFileDigest[]> {
    const files = (opts.files ?? listImmutableFiles(immutableDir)).filter((f) => f.number >= range.from && f.number <= range.to);
    const expected = (range.to - range.from + 1) * 3;
    if (files.length !== expected) {
        const have = new Set(files.map((f) => f.name));
        const missing: string[] = [];
        for (let n = range.from; n <= range.to && missing.length < 5; n++) for (const name of immutableTrio(n)) if (!have.has(name)) missing.push(name);
        throw new Error(`immutable files ${range.from}..${range.to}: ${files.length} of ${expected} present (missing e.g. ${missing.join(", ")})`);
    }
    const out: ImmutableFileDigest[] = [];
    for (let i = 0; i < files.length; i++) {
        const f = files[i]!;
        let d = opts.cache?.get(f) ?? null;
        if (d == null) {
            d = await sha256File(f.path);
            opts.cache?.set(f, d);
        }
        out.push({ immutable_file_name: f.name, digest: d });
        if (opts.onProgress && (i % 3000 === 0 || i === files.length - 1)) opts.onProgress(i + 1, files.length);
    }
    return out;
}
