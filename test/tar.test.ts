import { describe, expect, test } from "bun:test";
import { buildTar, readTar, TarStreamReader, type TarEntry } from "../src/tar";

const enc = new TextEncoder();
const entries: TarEntry[] = [
    { name: "immutable/00042.chunk", data: new Uint8Array(1300).map((_, i) => i % 251) },
    { name: "immutable/00042.primary", data: enc.encode("primary") },
    { name: "empty", data: new Uint8Array(0) },
    { name: `${"d".repeat(120)}/file.json`, data: enc.encode("{}") }, // ustar prefix field
];

/** Feed an archive to the streaming reader in chunks of `size` bytes; collect the files. */
function stream(tar: Uint8Array, size: number): { files: TarEntry[]; done: boolean } {
    const files: TarEntry[] = [];
    let parts: Uint8Array[] = [];
    let name = "";
    const r = new TarStreamReader({
        entry: (n) => { name = n; parts = []; },
        data: (c) => { parts.push(c.slice()); },
        end: () => {
            const data = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
            let o = 0;
            for (const p of parts) { data.set(p, o); o += p.length; }
            files.push({ name, data });
        },
    });
    for (let i = 0; i < tar.length; i += size) r.push(tar.subarray(i, i + size));
    return { files, done: r.finish() };
}

describe("tar", () => {
    test("deterministic: the same files give the same bytes", () => {
        expect(buildTar(entries)).toEqual(buildTar(entries));
    });

    test("read back in memory and streamed in any chunk size", () => {
        const tar = buildTar(entries);
        expect(readTar(tar)).toEqual(entries);
        for (const size of [1, 7, 511, 512, 513, 4096, tar.length]) {
            const { files, done } = stream(tar, size);
            expect(files).toEqual(entries);
            expect(done).toBe(true);
        }
    });

    test("the streaming reader can skip files and refuses a truncated archive or a bad checksum", () => {
        const tar = buildTar(entries);
        const seen: string[] = [];
        const r = new TarStreamReader({ entry: (n) => { seen.push(n); return n.endsWith(".chunk"); }, data: () => {}, end: () => {} });
        r.push(tar);
        expect(seen).toHaveLength(4);
        const cut = new TarStreamReader({ entry: () => {}, data: () => {}, end: () => {} });
        cut.push(tar.subarray(0, 700));
        expect(() => cut.finish()).toThrow(/inside an entry/);
        const bad = tar.slice();
        bad[10] ^= 1;
        expect(() => readTar(bad)).toThrow(/checksum/);
    });
});
