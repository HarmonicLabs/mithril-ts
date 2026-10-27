/**
 * File helpers shared by the node entry point: streaming SHA-256 of a file (immutable chunks and
 * ledger state files are megabytes to gigabytes, so they are never read whole), atomic writes
 * (a reader never sees half a file: write a sibling, then rename) and zstd through the runtime's
 * own `node:zlib` (Node >= 22.15 / 23.8, Bun >= 1.2.x), at the compression level the Mithril
 * aggregator uses (mithril-aggregator `CompressionAlgorithm::Zstandard`, level 9).
 */

import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { constants as zlibConstants, zstdCompressSync, zstdDecompressSync } from "node:zlib";

/** The aggregator's zstd level for immutable, digests and ancillary archives. */
export const ZSTD_LEVEL = 9;

/** hex(SHA-256(file bytes)), streamed (`ImmutableFile::compute_raw_hash::<Sha256>`). */
export function sha256File(path: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const h = createHash("sha256");
        const s = createReadStream(path);
        s.on("data", (chunk) => h.update(chunk));
        s.on("error", reject);
        s.on("end", () => resolve(h.digest("hex")));
    });
}

/** Write `data` to `path` through a uniquely named sibling and a rename; parents are created. */
export async function writeFileAtomic(path: string, data: Uint8Array | string): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
    try {
        await writeFile(tmp, data);
        await rename(tmp, path);
    } catch (e) {
        await rm(tmp, { force: true }).catch(() => {});
        throw e;
    }
}

/** True when `path` is a regular file. */
export async function isFile(path: string): Promise<boolean> {
    try {
        return (await stat(path)).isFile();
    } catch {
        return false;
    }
}

/** zstd-compress into one frame (deterministic for a given input, level and runtime zstd version). */
export function zstdCompress(data: Uint8Array, level = ZSTD_LEVEL): Uint8Array<ArrayBuffer> {
    const out = zstdCompressSync(data, { params: { [zlibConstants.ZSTD_c_compressionLevel]: level } });
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}

/** zstd-decompress an archive held in memory (small archives: digests lists, single immutable trios). */
export function zstdDecompress(data: Uint8Array): Uint8Array<ArrayBuffer> {
    const out = zstdDecompressSync(data);
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}
