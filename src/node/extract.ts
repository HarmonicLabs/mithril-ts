/**
 * Streaming extraction of Mithril `.tar.zst` archives to a directory.
 *
 * Every cardano-database v2 artifact is a zstd-compressed tar (mithril-aggregator `FileArchiver`,
 * level 9): `immutable/NNNNN.tar.zst` carries `immutable/NNNNN.{chunk,primary,secondary}`, the
 * digests archive carries one `<stem>.json`, and the ancillary archive carries
 * `ledger/<slot>/{meta,state,tables}`, the last immutable trio and `ancillary_manifest.json`
 * (mithril-client `CardanoDatabaseClient::download_unpack`). The ancillary archive is about 1 GB of
 * tar on mainnet-sized ledgers, so nothing here holds a whole archive: bytes flow from the source
 * through `node:zlib`'s zstd decompressor into the core `TarStreamReader`, and each file goes to
 * disk as it arrives, at most one decompressed buffer in memory.
 *
 * Archives come from the network and are untrusted until their files are checked against certified
 * digests, so entry names are confined to the target directory: absolute names, drive letters,
 * backslashes, NUL bytes and `..` segments are refused before anything is written. Only regular
 * files are extracted (the tar reader skips links and devices), and each file is written as
 * `<name>.part` and renamed when complete, so an interrupted extraction never leaves a file that
 * looks whole.
 */

import { createReadStream } from "node:fs";
import { mkdir, open, rename, rm, type FileHandle } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { pipeline, Readable } from "node:stream";
import { createZstdDecompress } from "node:zlib";

import { TarStreamReader } from "../tar";

export type ExtractOptions = {
    /**
     * Called with each entry's normalized name before it is written; returning false refuses the
     * whole archive (an immutable archive may carry its own trio only, for instance).
     */
    accept?: (name: string) => boolean;
    /** Called after each file is complete, with its normalized name and size. */
    onFile?: (name: string, size: number) => void;
};

/** A byte source: a Node stream, an async iterable of chunks, or a WHATWG stream (a fetch body). */
export type ByteSource = AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>;

/**
 * The path a tar entry may be written to under `root`, or throw. Returns the entry's normalized
 * relative name (`./a//b` becomes `a/b`) and its absolute destination.
 */
export function tarEntryPath(root: string, name: string): { name: string; path: string } {
    const bad = (why: string) => new Error(`tar: refusing entry ${JSON.stringify(name)}: ${why}`);
    if (!name) throw bad("empty name");
    if (name.includes("\0")) throw bad("NUL byte in name");
    if (name.includes("\\")) throw bad("backslash in name");
    if (name.startsWith("/") || /^[A-Za-z]:/.test(name)) throw bad("absolute path");
    const parts = name.split("/").filter((p) => p !== "" && p !== ".");
    if (parts.length === 0) throw bad("no file name");
    if (parts.includes("..")) throw bad("parent directory segment");
    const rootAbs = resolve(root);
    const path = resolve(rootAbs, ...parts);
    if (!path.startsWith(rootAbs + sep)) throw bad("outside the target directory");
    return { name: parts.join("/"), path };
}

function nodeReadable(source: ByteSource): Readable {
    if (source instanceof Readable) return source;
    if (typeof (source as ReadableStream<Uint8Array>).getReader === "function") {
        return Readable.fromWeb(source as unknown as import("node:stream/web").ReadableStream<Uint8Array>);
    }
    return Readable.from(source as AsyncIterable<Uint8Array>, { objectMode: false });
}

type Op = { kind: "open"; name: string; path: string } | { kind: "data"; chunk: Uint8Array } | { kind: "end" };

/**
 * Extract an uncompressed tar stream under `root`. Resolves with the normalized names of the files
 * written, in archive order. The archive must end with the end-of-archive marker (a truncated
 * download that happens to stop between entries is an error, not a shorter archive).
 */
export async function extractTar(source: ByteSource, root: string, opts: ExtractOptions = {}): Promise<string[]> {
    const rootAbs = resolve(root);
    // listen before the first await: an error emitted meanwhile (bad zstd, a dropped download) must reject this
    // promise, not escape as an unhandled stream error; the loop below rethrows it from the errored stream
    const input = nodeReadable(source);
    input.on("error", () => {});
    await mkdir(rootAbs, { recursive: true });
    const written: string[] = [];
    const ops: Op[] = [];
    const reader = new TarStreamReader({
        entry(entryName) {
            const { name, path } = tarEntryPath(rootAbs, entryName);
            if (opts.accept && !opts.accept(name)) throw new Error(`tar: unexpected entry ${JSON.stringify(name)}`);
            ops.push({ kind: "open", name, path });
        },
        data(chunk) {
            ops.push({ kind: "data", chunk });
        },
        end() {
            ops.push({ kind: "end" });
        },
    });

    let current: { name: string; path: string; part: string; fh: FileHandle; size: number } | null = null;
    const drain = async (): Promise<void> => {
        for (const op of ops) {
            if (op.kind === "open") {
                await mkdir(dirname(op.path), { recursive: true });
                const part = `${op.path}.part`;
                current = { name: op.name, path: op.path, part, fh: await open(part, "w"), size: 0 };
            } else if (op.kind === "data") {
                const c = current!;
                let off = 0;
                while (off < op.chunk.length) {
                    const { bytesWritten } = await c.fh.write(op.chunk, off, op.chunk.length - off);
                    off += bytesWritten;
                }
                c.size += op.chunk.length;
            } else {
                const c = current!;
                current = null;
                await c.fh.close();
                await rename(c.part, c.path);
                written.push(c.name);
                opts.onFile?.(c.name, c.size);
            }
        }
        ops.length = 0;
    };

    try {
        for await (const chunk of input) {
            // The chunks are consumed (written) before the next one is read, so subarrays stay valid.
            reader.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk as ArrayBuffer));
            await drain();
        }
        if (!reader.finish()) throw new Error("tar: archive has no end-of-archive marker (truncated?)");
    } catch (e) {
        input.destroy();
        const c = current as { part: string; fh: FileHandle } | null;
        if (c) {
            await c.fh.close().catch(() => {});
            await rm(c.part, { force: true }).catch(() => {});
        }
        throw e;
    }
    return written;
}

/** Extract a zstd-compressed tar stream under `root` (see `extractTar`). */
export async function extractTarZst(source: ByteSource, root: string, opts: ExtractOptions = {}): Promise<string[]> {
    const input = nodeReadable(source);
    // pipeline listens on both streams and passes an error of either to the other, so nothing is left unhandled
    const zstd = pipeline(input, createZstdDecompress(), () => {});
    try {
        return await extractTar(zstd, root, opts);
    } finally {
        input.destroy();
        zstd.destroy();
    }
}

/** Extract a `.tar.zst` file under `root`, streaming (fit for the gigabyte ancillary archive). */
export function extractTarZstFile(archivePath: string, root: string, opts: ExtractOptions = {}): Promise<string[]> {
    return extractTarZst(createReadStream(archivePath), root, opts);
}

/** Extract a `.tar.zst` archive held in memory under `root`. */
export function extractTarZstBytes(archive: Uint8Array, root: string, opts: ExtractOptions = {}): Promise<string[]> {
    return extractTarZst(Readable.from([archive]), root, opts);
}
