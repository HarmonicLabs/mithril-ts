/**
 * Cardano database v2 downloads over HTTP: the immutable archives and the ancillary archive of a
 * snapshot, unpacked into a download directory in cardano-node's layout, as mithril-client
 * `cardano-db download` does (mithril-client `cardano_database_client/download_unpack`):
 *
 *   GET <immutables template with {immutable_file_number} = 00042>  ->  <dir>/immutable/00042.{chunk,primary,secondary}
 *   GET <ancillary url>                                              ->  <dir>/ledger/<slot>/{meta,state,tables},
 *                                                                        <dir>/immutable/<last trio>, <dir>/ancillary_manifest.json
 *
 * Archives are streamed from the response body through zstd into the tar reader (extract.ts), so
 * memory stays flat whatever the archive size. Nothing here trusts the bytes: an immutable archive
 * may only carry its own trio, and the caller checks the files against the certified digests
 * (verifyDownload.ts) and the ancillary files against their signed manifest (ancillary.ts).
 */

import { access, constants as fsConstants, mkdir, open, readdir, rename, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";

import { extractTarZst, extractTarZstFile } from "./extract";
import { immutableStem, immutableTrio } from "./digests";
import { ancillaryUrl, immutableUrlTemplate, type CardanoDatabaseSnapshotMessage } from "./snapshot";

/** What the downloads need from `fetch`: the global `fetch` fits, and so does a test double. */
export type DownloadFetch = (url: string) => Promise<{ ok: boolean; status: number; body: ReadableStream<Uint8Array> | null; headers?: { get(name: string): string | null } }>;

const defaultFetch: DownloadFetch = (url) => fetch(url);

/** Archives kept with `keepArchive` (and the ancillary archive while it is unpacked) live here. */
export const ARCHIVES_DIR = ".mithril-archives";

async function get(fetchImpl: DownloadFetch, url: string): Promise<{ body: ReadableStream<Uint8Array>; length: number | null }> {
    const res = await fetchImpl(url);
    if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
    if (!res.body) throw new Error(`GET ${url}: empty body`);
    const len = Number(res.headers?.get("content-length") ?? NaN);
    return { body: res.body, length: Number.isFinite(len) ? len : null };
}

function webToNode(body: ReadableStream<Uint8Array>): Readable {
    return Readable.fromWeb(body as unknown as import("node:stream/web").ReadableStream<Uint8Array>);
}

/**
 * Stream a URL to a file (written as `<dest>.part`, renamed when complete). Resolves with the
 * number of bytes written; `onBytes` sees the running count and the announced length, if any.
 */
export async function downloadToFile(url: string, dest: string, opts: { fetch?: DownloadFetch; onBytes?: (received: number, total: number | null) => void } = {}): Promise<number> {
    const { body, length } = await get(opts.fetch ?? defaultFetch, url);
    const part = `${dest}.part`;
    const fh = await open(part, "w");
    let received = 0;
    try {
        for await (const chunk of webToNode(body)) {
            const b = chunk as Uint8Array;
            let off = 0;
            while (off < b.length) off += (await fh.write(b, off, b.length - off)).bytesWritten;
            received += b.length;
            opts.onBytes?.(received, length);
        }
        await fh.close();
    } catch (e) {
        await fh.close().catch(() => {});
        await rm(part, { force: true }).catch(() => {});
        throw e;
    }
    if (length != null && received !== length) {
        await rm(part, { force: true });
        throw new Error(`GET ${url}: ${received} bytes received, ${length} announced`);
    }
    await rename(part, dest);
    return received;
}

/** True when `<immutableDir>/NNNNN.{chunk,primary,secondary}` all exist. */
export async function hasCompleteImmutableTrio(immutableDir: string, n: number): Promise<boolean> {
    for (const name of immutableTrio(n)) {
        try {
            if (!(await stat(join(immutableDir, name))).isFile()) return false;
        } catch {
            return false;
        }
    }
    return true;
}

export type ImmutableDownloadOptions = {
    /** The snapshot's immutables URL template (`immutableUrlTemplate(snapshot)`). */
    template: string;
    /** Immutable file number. */
    number: number;
    /** Download directory; files land in `<downloadDir>/immutable`. */
    downloadDir: string;
    /** Also keep `<downloadDir>/.mithril-archives/NNNNN.tar.zst` (default false: stream straight to the files). */
    keepArchive?: boolean;
    /** Skip the download when the trio is already on disk (default true). */
    skipIfPresent?: boolean;
    fetch?: DownloadFetch;
    log?: (m: string) => void;
};

export type ImmutableDownloadResult = { immutableDir: string; files: string[]; skipped: boolean };

/** Download one immutable file number's archive and unpack its trio. */
export async function downloadImmutableFile(o: ImmutableDownloadOptions): Promise<ImmutableDownloadResult> {
    const log = o.log ?? (() => {});
    const stem = immutableStem(o.number);
    const root = resolve(o.downloadDir);
    const immutableDir = join(root, "immutable");
    const files = immutableTrio(o.number);
    if (o.skipIfPresent !== false && (await hasCompleteImmutableTrio(immutableDir, o.number))) {
        log(`  skip ${stem} (trio present)`);
        return { immutableDir, files, skipped: true };
    }
    const url = o.template.replaceAll("{immutable_file_number}", stem);
    // An immutable archive carries its own trio only; anything else could overwrite other files.
    const allowed = new Set(files.map((f) => `immutable/${f}`));
    const accept = (name: string) => allowed.has(name);
    log(`GET ${url}`);
    let written: string[];
    if (o.keepArchive) {
        const archive = join(root, ARCHIVES_DIR, `${stem}.tar.zst`);
        await mkdir(join(root, ARCHIVES_DIR), { recursive: true });
        await downloadToFile(url, archive, { fetch: o.fetch });
        written = await extractTarZstFile(archive, root, { accept });
    } else {
        await mkdir(root, { recursive: true });
        const { body } = await get(o.fetch ?? defaultFetch, url);
        written = await extractTarZst(body, root, { accept });
    }
    const missing = [...allowed].filter((f) => !written.includes(f));
    if (missing.length) throw new Error(`archive ${stem}.tar.zst lacks ${missing.join(", ")}`);
    return { immutableDir, files, skipped: false };
}

export type ImmutableRangeOptions = {
    /** The snapshot message (its immutables template and beacon), or a template alone. */
    snapshot?: CardanoDatabaseSnapshotMessage;
    template?: string;
    downloadDir: string;
    /** First and last immutable file numbers, inclusive (default 0 and the snapshot's beacon). */
    from?: number;
    to?: number;
    /** Parallel downloads (default 1; archives are ~0.1 to 10 MB each, 8 suits a full chain). */
    concurrency?: number;
    skipIfPresent?: boolean;
    keepArchive?: boolean;
    fetch?: DownloadFetch;
    log?: (m: string) => void;
    /** After every immutable file number (done so far, total, the number). */
    onProgress?: (done: number, total: number, number: number) => void;
};

export type ImmutableRangeResult = { immutableDir: string; downloaded: number[]; skipped: number[] };

/** Download immutable file numbers `from..=to`; complete trios on disk are kept unless `skipIfPresent` is false. */
export async function downloadImmutableRange(o: ImmutableRangeOptions): Promise<ImmutableRangeResult> {
    const template = o.template ?? (o.snapshot ? immutableUrlTemplate(o.snapshot) : null);
    if (!template) throw new Error("downloadImmutableRange: pass a snapshot or a template");
    const beacon = o.snapshot?.beacon.immutable_file_number;
    const from = Math.max(0, o.from ?? 0);
    const to = beacon != null ? Math.min(beacon, o.to ?? beacon) : o.to;
    if (to == null) throw new Error("downloadImmutableRange: pass `to` with a template");
    if (from > to) throw new Error(`invalid immutable range ${from}..${to}${beacon != null ? ` (beacon ${beacon})` : ""}`);

    const total = to - from + 1;
    const concurrency = Math.max(1, Math.min(total, Math.trunc(o.concurrency ?? 1)));
    const skipped = new Set<number>();
    let next = from;
    let done = 0;
    let failed: unknown = null;
    const worker = async (): Promise<void> => {
        while (failed === null) {
            const n = next++;
            if (n > to) return;
            try {
                const r = await downloadImmutableFile({ template, number: n, downloadDir: o.downloadDir, skipIfPresent: o.skipIfPresent, keepArchive: o.keepArchive, fetch: o.fetch, log: o.log });
                if (r.skipped) skipped.add(n);
            } catch (e) {
                failed ??= e;
                return;
            }
            o.onProgress?.(++done, total, n);
        }
    };
    await Promise.all(Array.from({ length: concurrency }, worker));
    if (failed !== null) throw failed;
    const downloaded: number[] = [];
    for (let n = from; n <= to; n++) if (!skipped.has(n)) downloaded.push(n);
    return { immutableDir: join(resolve(o.downloadDir), "immutable"), downloaded, skipped: [...skipped].sort((a, b) => a - b) };
}

export type AncillaryDownloadOptions = {
    snapshot: CardanoDatabaseSnapshotMessage;
    downloadDir: string;
    /** Keep `<downloadDir>/.mithril-archives/<name>.tar.zst` after unpacking (default false). */
    keepArchive?: boolean;
    fetch?: DownloadFetch;
    log?: (m: string) => void;
    /** Archive bytes received so far and the announced length. */
    onBytes?: (received: number, total: number | null) => void;
};

export type AncillaryDownloadResult = { url: string; bytes: number; files: string[]; ledgerDir: string | null };

/**
 * Download the ancillary archive to disk (an archive already there from an earlier run is reused),
 * then unpack it, streaming, under `downloadDir`. Verify it with `verifyAncillaryDir` before use.
 */
export async function downloadAncillary(o: AncillaryDownloadOptions): Promise<AncillaryDownloadResult> {
    const log = o.log ?? (() => {});
    const url = ancillaryUrl(o.snapshot);
    if (!url) throw new Error(`snapshot ${o.snapshot.hash} has no ancillary location`);
    const root = resolve(o.downloadDir);
    const archivesDir = join(root, ARCHIVES_DIR);
    await mkdir(archivesDir, { recursive: true });
    const base = (url.split("?")[0]!.split("/").pop() ?? "").replace(/\.tar\.zst$/i, "").replace(/[^A-Za-z0-9._-]/g, "_") || "ancillary";
    const archive = join(archivesDir, `${base}.tar.zst`);
    let bytes = 0;
    try {
        bytes = (await stat(archive)).size;
    } catch {
        bytes = 0;
    }
    if (bytes > 0) log(`  reusing ${archive} (${bytes} bytes)`);
    else {
        log(`GET ${url}`);
        bytes = await downloadToFile(url, archive, { fetch: o.fetch, onBytes: o.onBytes });
    }
    log(`  unpacking ${archive} into ${root}`);
    const files = await extractTarZstFile(archive, root);
    log(`  ${files.length} ancillary files`);
    if (!o.keepArchive) await rm(archive, { force: true });
    return { url, bytes, files, ledgerDir: await findAncillaryLedgerDir(root) };
}

async function readable(dir: string): Promise<string[] | null> {
    try {
        await access(dir, fsConstants.R_OK);
        return await readdir(dir);
    } catch {
        return null;
    }
}

/**
 * The ledger state directory (`ledger/`, holding `<slot>/{meta,state,tables}`) under a download
 * root: `ledger`, `db/ledger` (mithril-client's layout) or `ancillary/ledger`, else one level down.
 */
export async function findAncillaryLedgerDir(root: string): Promise<string | null> {
    for (const c of [resolve(root, "ledger"), resolve(root, "db", "ledger"), resolve(root, "ancillary", "ledger")]) {
        const names = await readable(c);
        if (names && (names.some((n) => /^\d+$/.test(n)) || names.includes("state") || names.includes("meta"))) return c;
    }
    for (const ent of await readdir(root, { withFileTypes: true }).catch(() => [])) {
        if (!ent.isDirectory() || ent.name.startsWith(".") || ent.name === "immutable") continue;
        const found = await findAncillaryLedgerDir(resolve(root, ent.name));
        if (found) return found;
    }
    return null;
}

/**
 * The immutable files directory under a download root: `db/immutable` (mithril-client's layout),
 * `immutable`, or `db` itself, else one level down. Null when none holds immutable files.
 */
export async function findImmutableDir(root: string): Promise<string | null> {
    const looksImmutable = (names: string[]) => names.some((n) => /^\d{5,}\.(chunk|primary|secondary)$/.test(n));
    for (const c of [resolve(root, "db", "immutable"), resolve(root, "immutable"), resolve(root, "db")]) {
        const names = await readable(c);
        if (names && looksImmutable(names)) return c;
    }
    for (const ent of await readdir(root, { withFileTypes: true }).catch(() => [])) {
        if (!ent.isDirectory() || ent.name.startsWith(".")) continue;
        const found = await findImmutableDir(resolve(root, ent.name));
        if (found) return found;
    }
    return null;
}
