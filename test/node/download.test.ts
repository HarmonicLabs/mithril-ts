import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ancillaryManifestHash } from "../../src/ancillary";
import { buildTar, type TarEntry } from "../../src/tar";
import {
    ancillaryImmutableDigests,
    ARCHIVES_DIR,
    computeImmutableDigests,
    downloadAncillary,
    downloadImmutableFile,
    downloadImmutableRange,
    downloadToFile,
    extractTarZst,
    extractTarZstBytes,
    extractTarZstFile,
    fetchVerifiedDigests,
    findImmutableDir,
    immutableUrlTemplate,
    resolveVerificationKey,
    selectSnapshot,
    tarEntryPath,
    verifyAncillaryDir,
    zstdCompress,
    type CardanoDatabaseSnapshotMessage,
} from "../../src/node";
import { bytes, FIXTURES } from "./helpers";
import { testAncillaryKey } from "./syntheticChain";

const enc = new TextEncoder();
const sha256hex = (b: Uint8Array) => new Bun.CryptoHasher("sha256").update(b).digest("hex");

/** A tar with raw entry names (buildTar refuses nothing; the extractor must). */
const tarZst = (entries: TarEntry[]) => zstdCompress(buildTar(entries));

describe("tar.zst extraction", () => {
    let dir: string;
    beforeAll(() => {
        dir = mkdtempSync(join(tmpdir(), "mts-extract-"));
    });
    afterAll(() => rmSync(dir, { recursive: true, force: true }));

    test("entry names are confined to the target directory", () => {
        const root = join(dir, "root");
        for (const bad of ["../x", "a/../../x", "a/..", "/etc/passwd", "//x", "C:/x", "c:x", "a\\b", "..\\x", "", ".", "./", "a\0b"]) {
            expect(() => tarEntryPath(root, bad)).toThrow(/tar: refusing entry/);
        }
        expect(tarEntryPath(root, "./immutable//00001.chunk")).toEqual({ name: "immutable/00001.chunk", path: join(root, "immutable", "00001.chunk") });
        expect(tarEntryPath(root, "a..b/c").name).toBe("a..b/c"); // dots inside a name are fine
    });

    test("an archive with a path traversal or absolute entry is refused and writes nothing outside", async () => {
        for (const name of ["../escaped", "sub/../../escaped", "/tmp/mts-absolute-escape"]) {
            const root = join(dir, `t-${Math.random().toString(16).slice(2)}`);
            await expect(extractTarZstBytes(tarZst([{ name: "ok.txt", data: enc.encode("fine") }, { name, data: enc.encode("evil") }]), root)).rejects.toThrow(/tar: refusing entry/);
            expect(existsSync(join(dir, "escaped"))).toBe(false);
            expect(existsSync("/tmp/mts-absolute-escape")).toBe(false);
            expect(existsSync(join(root, "..", "escaped"))).toBe(false);
        }
    });

    test("streamed in odd-sized pieces: contents intact, no .part files, names in archive order", async () => {
        const big = bytes(3, 3_000_001);
        const archive = tarZst([{ name: "a/big.bin", data: big }, { name: "empty", data: new Uint8Array() }, { name: "a/b/small", data: enc.encode("x") }]);
        async function* pieces() {
            for (let i = 0; i < archive.length; i += 777) yield archive.subarray(i, i + 777);
        }
        const root = join(dir, "stream");
        const sizes: number[] = [];
        const names = await extractTarZst(pieces(), root, { onFile: (_n, size) => sizes.push(size) });
        expect(names).toEqual(["a/big.bin", "empty", "a/b/small"]);
        expect(sizes).toEqual([3_000_001, 0, 1]);
        expect(Buffer.compare(readFileSync(join(root, "a", "big.bin")), big)).toBe(0);
        expect(readdirSync(join(root, "a")).sort()).toEqual(["b", "big.bin"]);
        // A web ReadableStream source works too.
        const web = new Blob([archive]).stream() as ReadableStream<Uint8Array>;
        expect(await extractTarZst(web, join(dir, "web"))).toEqual(names);
    });

    test("a truncated archive is an error and leaves no partial file", async () => {
        const tar = buildTar([{ name: "one", data: bytes(1, 600) }, { name: "two", data: bytes(2, 5000) }]);
        const root = join(dir, "trunc");
        await expect(extractTarZstBytes(zstdCompress(tar.subarray(0, 512 + 1024 + 512 + 2048)), root)).rejects.toThrow(/ends inside an entry/);
        expect(existsSync(join(root, "two"))).toBe(false);
        expect(existsSync(join(root, "two.part"))).toBe(false);
        // Cut exactly between entries: no end-of-archive marker.
        await expect(extractTarZstBytes(zstdCompress(tar.subarray(0, 512 + 1024)), join(dir, "trunc2"))).rejects.toThrow(/no end-of-archive marker/);
        // Not zstd at all.
        await expect(extractTarZstBytes(enc.encode("not an archive"), join(dir, "trunc3"))).rejects.toThrow();
    });

    test("`accept` refuses an archive before the unexpected entry is written", async () => {
        const root = join(dir, "accept");
        await expect(extractTarZstBytes(tarZst([{ name: "keep", data: enc.encode("1") }, { name: "other", data: enc.encode("2") }]), root, { accept: (n) => n === "keep" })).rejects.toThrow(/unexpected entry "other"/);
        expect(existsSync(join(root, "other"))).toBe(false);
    });

    test("a .tar.zst file on disk (the preview 00100 archive)", async () => {
        const root = join(dir, "file");
        expect(await extractTarZstFile(join(FIXTURES, "00100.tar.zst"), root)).toEqual(["immutable/00100.chunk", "immutable/00100.primary", "immutable/00100.secondary"]);
        expect(await computeImmutableDigests(join(root, "immutable"), { from: 100, to: 100 })).toEqual(JSON.parse(readFileSync(join(FIXTURES, "00100.digests.json"), "utf8")));
    });
});

describe("HTTP downloads (local server)", () => {
    let dir: string;
    let server: ReturnType<typeof Bun.serve>;
    const requests: string[] = [];
    const anc = testAncillaryKey();
    let ancillaryFiles: TarEntry[];
    let ancillaryArchive: Uint8Array<ArrayBuffer>;
    let base: string;

    const snapshot = (): CardanoDatabaseSnapshotMessage => ({
        hash: "ab".repeat(32),
        merkle_root: "cd".repeat(32),
        network: "preview",
        beacon: { epoch: 50, immutable_file_number: 101 },
        certificate_hash: "ef".repeat(32),
        digests: { locations: [] },
        immutables: { locations: [{ type: "cloud_storage", uri: { Template: `${base}/immutable/{immutable_file_number}.tar.zst` }, compression_algorithm: "zstandard" }] },
        ancillary: { locations: [{ type: "cloud_storage", uri: `${base}/ancillary.tar.zst`, compression_algorithm: "zstandard" }] },
    });

    beforeAll(() => {
        dir = mkdtempSync(join(tmpdir(), "mts-dl-"));
        const fixture = readFileSync(join(FIXTURES, "00100.tar.zst"));
        ancillaryFiles = [
            { name: "ledger/4242/meta", data: enc.encode("{}") },
            { name: "ledger/4242/state", data: bytes(7, 9000) },
            { name: "ledger/4242/tables", data: bytes(8, 12000) },
            { name: "immutable/00102.chunk", data: bytes(9, 100) },
            { name: "immutable/00102.primary", data: bytes(10, 100) },
            { name: "immutable/00102.secondary", data: bytes(11, 100) },
        ];
        const data: Record<string, string> = {};
        for (const f of ancillaryFiles) data[f.name] = sha256hex(f.data);
        const manifest = { data, signature: anc.sign(ancillaryManifestHash({ data, signature: null })) };
        ancillaryArchive = tarZst([...ancillaryFiles, { name: "ancillary_manifest.json", data: enc.encode(JSON.stringify(manifest)) }]);
        server = Bun.serve({
            port: 0,
            hostname: "127.0.0.1",
            fetch: (req) => {
                const p = new URL(req.url).pathname;
                requests.push(p);
                if (p === "/immutable/00100.tar.zst") return new Response(new Uint8Array(fixture));
                if (p === "/immutable/00101.tar.zst") return new Response(tarZst(["chunk", "primary", "secondary"].map((e) => ({ name: `immutable/00101.${e}`, data: bytes(101, 50) }))));
                if (p === "/immutable/00099.tar.zst") return new Response(tarZst([{ name: "immutable/00099.chunk", data: bytes(1, 10) }])); // incomplete trio
                if (p === "/immutable/00098.tar.zst") return new Response(tarZst([{ name: "../00098.chunk", data: bytes(1, 10) }]));
                if (p === "/ancillary.tar.zst") return new Response(ancillaryArchive);
                if (p === "/digests.tar.zst") return new Response(tarZst([{ name: "x.digests.json", data: new Uint8Array(readFileSync(join(FIXTURES, "00100.digests.json"))) }]));
                return new Response("missing", { status: 404 });
            },
        });
        base = `http://127.0.0.1:${server.port}`;
    });
    afterAll(() => {
        server?.stop(true);
        rmSync(dir, { recursive: true, force: true });
    });

    test("a range of immutable files, resumed without re-downloading complete trios", async () => {
        const dl = join(dir, "range");
        const progress: Array<[number, number, number]> = [];
        const r = await downloadImmutableRange({ snapshot: snapshot(), downloadDir: dl, from: 100, concurrency: 2, onProgress: (d, t, n) => progress.push([d, t, n]) });
        expect(r.downloaded).toEqual([100, 101]); // `to` defaults to the beacon
        expect(r.immutableDir).toBe(join(dl, "immutable"));
        expect(progress.map((p) => p[1])).toEqual([2, 2]);
        expect(progress.map((p) => p[2]).sort()).toEqual([100, 101]);
        expect(await computeImmutableDigests(r.immutableDir, { from: 100, to: 100 })).toEqual(JSON.parse(readFileSync(join(FIXTURES, "00100.digests.json"), "utf8")));
        expect(await findImmutableDir(dl)).toBe(r.immutableDir);
        expect(readdirSync(r.immutableDir).some((n) => n.endsWith(".part"))).toBe(false);
        expect(existsSync(join(dl, ARCHIVES_DIR))).toBe(false); // streamed, nothing kept
        const before = requests.length;
        const again = await downloadImmutableRange({ snapshot: snapshot(), downloadDir: dl, from: 100, to: 101 });
        expect(again.skipped).toEqual([100, 101]);
        expect(requests.length).toBe(before);
        await expect(downloadImmutableRange({ snapshot: snapshot(), downloadDir: dl, from: 100, to: 500 })).resolves.toMatchObject({ skipped: [100, 101] }); // clamped to the beacon
        await expect(downloadImmutableRange({ snapshot: snapshot(), downloadDir: dl, from: 102 })).rejects.toThrow(/invalid immutable range/);
    });

    test("keepArchive keeps the .tar.zst; incomplete, unsafe and missing archives fail", async () => {
        const dl = join(dir, "single");
        const template = immutableUrlTemplate(snapshot());
        const r = await downloadImmutableFile({ template, number: 100, downloadDir: dl, keepArchive: true });
        expect(r.skipped).toBe(false);
        expect(Buffer.compare(readFileSync(join(dl, ARCHIVES_DIR, "00100.tar.zst")), readFileSync(join(FIXTURES, "00100.tar.zst")))).toBe(0);
        await expect(downloadImmutableFile({ template, number: 99, downloadDir: dl })).rejects.toThrow(/lacks immutable\/00099\.primary/);
        await expect(downloadImmutableFile({ template, number: 98, downloadDir: dl })).rejects.toThrow(/tar: refusing entry/);
        expect(existsSync(join(dir, "00098.chunk"))).toBe(false);
        await expect(downloadImmutableFile({ template, number: 97, downloadDir: dl })).rejects.toThrow(/HTTP 404/);
        await expect(downloadImmutableRange({ template, downloadDir: join(dir, "r404"), from: 96, to: 100, concurrency: 3 })).rejects.toThrow(/HTTP 404/);
    });

    test("downloadToFile streams to disk with byte progress, and leaves nothing on failure", async () => {
        const dest = join(dir, "anc-copy.tar.zst");
        let last = 0;
        const n = await downloadToFile(`${base}/ancillary.tar.zst`, dest, { onBytes: (r) => (last = r) });
        expect(n).toBe(ancillaryArchive.length);
        expect(last).toBe(n);
        expect(Buffer.compare(readFileSync(dest), ancillaryArchive)).toBe(0);
        await expect(downloadToFile(`${base}/nope`, join(dir, "nope"))).rejects.toThrow(/HTTP 404/);
        expect(existsSync(join(dir, "nope.part"))).toBe(false);
        // A custom fetch is used for every request.
        const seen: string[] = [];
        await downloadToFile("https://example.invalid/a", join(dir, "custom"), { fetch: async (u) => (seen.push(u), new Response("hello")) });
        expect(seen).toEqual(["https://example.invalid/a"]);
        expect(readFileSync(join(dir, "custom"), "utf8")).toBe("hello");
    });

    test("the ancillary archive: downloaded, unpacked, verified against its signed manifest", async () => {
        const dl = join(dir, "anc");
        const r = await downloadAncillary({ snapshot: snapshot(), downloadDir: dl });
        expect(r.ledgerDir).toBe(join(dl, "ledger"));
        expect(r.files).toContain("ancillary_manifest.json");
        expect(r.bytes).toBe(ancillaryArchive.length);
        expect(existsSync(join(dl, ARCHIVES_DIR, "ancillary.tar.zst"))).toBe(false);

        const v = await verifyAncillaryDir(dl, anc.vkeyHex);
        expect(v).toMatchObject({ ok: true, files: 6, signatureOk: true, errors: [] });
        expect([...ancillaryImmutableDigests(v.manifest!).keys()]).toEqual(["00102.chunk", "00102.primary", "00102.secondary"]);
        expect((await verifyAncillaryDir(dl, testAncillaryKey(12).vkeyHex)).signatureOk).toBe(false);
        writeFileSync(join(dl, "ledger", "4242", "state"), bytes(1, 10));
        const tampered = await verifyAncillaryDir(dl, anc.vkeyHex);
        expect(tampered.ok).toBe(false);
        expect(tampered.errors.join()).toMatch(/ledger\/4242\/state: sha256/);
        rmSync(join(dl, "ledger", "4242", "meta"));
        expect((await verifyAncillaryDir(dl, anc.vkeyHex)).errors).toContain("missing ledger/4242/meta");
        expect((await verifyAncillaryDir(join(dir, "nowhere"), anc.vkeyHex)).ok).toBe(false);
        // A kept archive is reused instead of downloaded again.
        const before = requests.length;
        await downloadAncillary({ snapshot: snapshot(), downloadDir: join(dir, "anc2"), keepArchive: true });
        await downloadAncillary({ snapshot: snapshot(), downloadDir: join(dir, "anc2"), keepArchive: true });
        expect(requests.length).toBe(before + 1);
    });

    test("digests list from a zstd tar location; certificate kind is checked first", async () => {
        const fake = { signature: { kind: "genesis" }, hash: "00" } as never;
        const snap = { ...snapshot(), digests: { locations: [{ type: "cloud_storage", uri: `${base}/digests.tar.zst`, compression_algorithm: "zstandard" }] } };
        await expect(fetchVerifiedDigests(snap, fake)).rejects.toThrow(/does not sign a cardano database snapshot/);
    });

    test("snapshot selection and verification keys from a value, a file or a URL", async () => {
        const list = [{ hash: "aa".repeat(32) }, { hash: "bb".repeat(32) }];
        expect(selectSnapshot(list).hash).toBe("aa".repeat(32));
        expect(selectSnapshot(list, "BB".repeat(32)).hash).toBe("bb".repeat(32));
        expect(() => selectSnapshot(list, "cc".repeat(32))).toThrow(/not listed/);
        expect(() => selectSnapshot([])).toThrow(/lists no/);
        const key = testAncillaryKey().vkeyHex;
        expect(await resolveVerificationKey(key)).toBe(key);
        const f = join(dir, "k.vkey");
        writeFileSync(f, `${key}\n`);
        expect(await resolveVerificationKey(f)).toBe(key);
        expect(await resolveVerificationKey("https://keys.example/genesis.vkey", async (u) => ({ ok: true, status: 200, text: async () => `${key} ${u.length}`.split(" ")[0]! }))).toBe(key);
    });
});
