import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ancillaryManifestHash } from "../../src/ancillary";
import { cardanoDatabaseMerkleRoot, cardanoDatabaseSnapshotHash, certifiedDigests } from "../../src/mkTree";
import { buildTar, readTar, type TarEntry } from "../../src/tar";
import {
    ArtifactStore,
    buildImmutableArchive,
    computeImmutableDigests,
    createMithrilArtifactHandler,
    describeVerification,
    DigestCache,
    immutableStem,
    lastCompletedImmutable,
    listImmutableFiles,
    produceCardanoDatabaseSnapshot,
    produceCertifiedSnapshot,
    restoreCardanoDatabase,
    sha256File,
    verifyImmutableFiles,
    zstdCompress,
    zstdDecompress,
} from "../../src/node";
import { bytes, FIXTURES, routeFetch, writeTrio } from "./helpers";
import { buildSyntheticChain, testAncillaryKey, type SyntheticChain } from "./syntheticChain";

describe("cardano-database v2 artifacts", () => {
    test("our immutable archive has the aggregator's layout and contents (00100, preview)", async () => {
        const published = readTar(zstdDecompress(readFileSync(join(FIXTURES, "00100.tar.zst"))));
        expect(published.map((e) => e.name)).toEqual(["immutable/00100.chunk", "immutable/00100.primary", "immutable/00100.secondary"]);
        const dir = mkdtempSync(join(tmpdir(), "cdb-arch-"));
        try {
            mkdirSync(join(dir, "immutable"));
            for (const e of published) writeFileSync(join(dir, e.name), e.data);
            const digests = await computeImmutableDigests(join(dir, "immutable"), { from: 100, to: 100 });
            const want = JSON.parse(readFileSync(join(FIXTURES, "00100.digests.json"), "utf8"));
            expect(digests).toEqual(want); // the certified digests of preview 00100.*
            const ours = await buildImmutableArchive(join(dir, "immutable"), 100, new Map(digests.map((d) => [d.immutable_file_name, d.digest])));
            const entries = readTar(zstdDecompress(ours.archive));
            expect(entries.map((e) => e.name)).toEqual(published.map((e) => e.name));
            for (let i = 0; i < 3; i++) expect(Buffer.compare(entries[i]!.data, published[i]!.data)).toBe(0);
            // Deterministic: a second build is byte-identical.
            const again = await buildImmutableArchive(join(dir, "immutable"), 100);
            expect(Buffer.compare(again.archive, ours.archive)).toBe(0);
            // A file changed after it was digested is refused.
            await expect(buildImmutableArchive(join(dir, "immutable"), 100, new Map([["00100.chunk", "00".repeat(32)]]))).rejects.toThrow(/changed since it was digested/);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    test("digest filtering for a beacon (core certifiedDigests): numbered <= beacon, by name, duplicates refused", () => {
        const list = [
            { immutable_file_name: "00002.chunk", digest: "aa".repeat(32) },
            { immutable_file_name: "00001.secondary", digest: "bb".repeat(32) },
            { immutable_file_name: "00003.chunk", digest: "cc".repeat(32) },
            { immutable_file_name: "garbage", digest: "dd".repeat(32) },
        ];
        expect(certifiedDigests(list, 2)).toEqual([
            { immutable_file_name: "00001.secondary", digest: "bb".repeat(32) },
            { immutable_file_name: "00002.chunk", digest: "aa".repeat(32) },
        ]);
        expect(() => certifiedDigests([...list, { immutable_file_name: "00002.chunk", digest: "ee".repeat(32) }], 2)).toThrow(/listed twice/);
    });

    test("listing, last completed trio, digests (streamed SHA-256) and the digest cache", async () => {
        const dir = mkdtempSync(join(tmpdir(), "cdb-dig-"));
        try {
            for (let n = 0; n <= 3; n++) writeTrio(dir, n);
            writeFileSync(join(dir, "clean"), "x"); // not an immutable file
            rmSync(join(dir, "00001.primary"));
            expect(lastCompletedImmutable(listImmutableFiles(dir))).toBe(0);
            writeTrio(dir, 1);
            const files = listImmutableFiles(dir);
            expect(files.map((f) => f.name).slice(0, 3)).toEqual(["00000.chunk", "00000.primary", "00000.secondary"]);
            expect(lastCompletedImmutable(files)).toBe(2); // 3 is the chunk "being written"
            await expect(computeImmutableDigests(dir, { from: 0, to: 4 })).rejects.toThrow(/missing e\.g\. 00004\.chunk/);

            const cachePath = join(dir, "cache.json");
            const cache = await DigestCache.load(cachePath);
            const d = await computeImmutableDigests(dir, { from: 0, to: 2 }, { cache });
            expect(d[0]!.digest).toBe(new Bun.CryptoHasher("sha256").update(readFileSync(join(dir, "00000.chunk"))).digest("hex"));
            expect(await sha256File(join(dir, "00000.chunk"))).toBe(d[0]!.digest);
            await cache.save();
            const reloaded = await DigestCache.load(cachePath);
            expect(reloaded.size).toBe(9);
            const f0 = listImmutableFiles(dir)[0]!;
            expect(reloaded.get(f0)).toBe(d[0]!.digest);
            utimesSync(f0.path, new Date(), new Date(Date.now() + 5000)); // touched: the cached digest no longer applies
            expect(reloaded.get(listImmutableFiles(dir)[0]!)).toBeNull();
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    test("download verification: extra trio needs its own digests (ancillary manifest)", async () => {
        const dir = mkdtempSync(join(tmpdir(), "cdb-ver-"));
        try {
            for (let n = 0; n <= 3; n++) writeTrio(dir, n);
            const d = await computeImmutableDigests(dir, { from: 0, to: 3 });
            const verified = { digests: new Map(d.filter((x) => !x.immutable_file_name.startsWith("00003")).map((x) => [x.immutable_file_name, x.digest])) };
            const without = await verifyImmutableFiles(dir, { from: 0, to: 2 }, verified);
            expect(without.nonVerifiable).toEqual(["00003.chunk", "00003.primary", "00003.secondary"]);
            const extra = new Map(d.filter((x) => x.immutable_file_name.startsWith("00003")).map((x) => [x.immutable_file_name, x.digest]));
            const withExtra = await verifyImmutableFiles(dir, { from: 0, to: 2 }, verified, extra);
            expect(describeVerification(withExtra)).toBeNull();
            const missing = await verifyImmutableFiles(dir, { from: 0, to: 4 }, verified, extra);
            expect(missing.missing).toEqual(["00004.chunk", "00004.primary", "00004.secondary"]);
            writeFileSync(join(dir, "00002.primary"), bytes(1, 10));
            expect(describeVerification(await verifyImmutableFiles(dir, { from: 0, to: 2 }, verified, extra))).toMatch(/1 tampered \(00002\.primary\)/);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    test("snapshot hash rule (preview e1444/i28880 published hash)", () => {
        expect(cardanoDatabaseSnapshotHash(1444, "5985ac8592ba7c9095705a8924b8a4ef1b0e650900690fbfb2697dca720973a0")).toBe("23156c7e7ff6b62fd423da43079df1e24048fba642e7ffdd211f6b19483674fb");
    });

    describe("produce, serve, restore (offline, synthetic certificate chain)", () => {
        let root: string;
        let src: string;
        let store: ArtifactStore;
        let chain: SyntheticChain;
        let server: ReturnType<typeof routeFetch>;
        let merkleRoot: string;
        const anc = testAncillaryKey();
        let ancillaryArchive: Uint8Array<ArrayBuffer>;

        beforeAll(async () => {
            root = mkdtempSync(join(tmpdir(), "cdb-e2e-"));
            src = join(root, "node", "immutable");
            mkdirSync(src, { recursive: true });
            for (let n = 0; n <= 3; n++) writeTrio(src, n); // 3 is the chunk "being written"
            expect(lastCompletedImmutable(listImmutableFiles(src))).toBe(2);
            merkleRoot = cardanoDatabaseMerkleRoot(await computeImmutableDigests(src, { from: 0, to: 2 }), 2);
            chain = buildSyntheticChain({
                signedEntityType: { CardanoDatabase: { epoch: 10, immutable_file_number: 2 } },
                messageParts: { cardano_database_merkle_root: merkleRoot },
            });
            store = new ArtifactStore(join(root, "artifacts"));
            const r = await produceCardanoDatabaseSnapshot({
                immutableDir: src,
                store,
                network: "preview",
                beacon: { epoch: 10, immutableFileNumber: 2 },
                certificate: chain.standard,
                certificateChain: [chain.standard, chain.genesis],
                cardanoNodeVersion: "mithril-ts-test",
            });
            expect(r.certified).toBe(true);
            expect(r.archivesWritten).toBe(3);
            expect(r.snapshot.hash).toBe(cardanoDatabaseSnapshotHash(10, merkleRoot));

            // An ancillary archive as the aggregator builds it: ledger state, the last trio, a signed manifest.
            const files: TarEntry[] = [
                { name: "ledger/1234/meta", data: new TextEncoder().encode('{"cardano_node_version":"10.5.1"}') },
                { name: "ledger/1234/state", data: bytes(91, 5000) },
                { name: "ledger/1234/tables", data: bytes(92, 7000) },
                ...["chunk", "primary", "secondary"].map((e) => ({ name: `immutable/00003.${e}`, data: new Uint8Array(readFileSync(join(src, `00003.${e}`))) })),
            ];
            const data: Record<string, string> = {};
            for (const f of files) data[f.name] = new Bun.CryptoHasher("sha256").update(f.data).digest("hex");
            const manifest = { data, signature: anc.sign(ancillaryManifestHash({ data, signature: null })) };
            ancillaryArchive = zstdCompress(buildTar([...files, { name: "ancillary_manifest.json", data: new TextEncoder().encode(JSON.stringify(manifest)) }]));

            const handler = createMithrilArtifactHandler({ store });
            const ancHandler = createMithrilArtifactHandler({ store, prefix: "/with-ancillary" });
            server = routeFetch(async (req) => {
                    const url = new URL(req.url);
                    if (url.pathname === "/files/ancillary.tar.zst") return new Response(ancillaryArchive);
                    const res = (await handler(req, url)) ?? (await ancHandler(req, url));
                    if (!res) return new Response("nope", { status: 404 });
                    // The same store, with an ancillary location added to the snapshot detail.
                    if (url.pathname.startsWith("/with-ancillary/artifact/cardano-database/") && res.ok && /[0-9a-f]{64}$/.test(url.pathname)) {
                        const j = (await res.json()) as { ancillary: { locations: unknown[] } };
                        j.ancillary.locations = [{ type: "cloud_storage", uri: `${url.origin}/files/ancillary.tar.zst`, compression_algorithm: "zstandard" }];
                        return Response.json(j);
                    }
                    return res;
            });
        });
        afterAll(() => {
            server?.stop();
            rmSync(root, { recursive: true, force: true });
        });
        const base = () => `${server.origin}/mithril`;

        test("producing a root the certificate did not sign is refused", async () => {
            const other = buildSyntheticChain({ signedEntityType: { CardanoDatabase: { epoch: 10, immutable_file_number: 2 } }, messageParts: { cardano_database_merkle_root: "00".repeat(32) } });
            await expect(produceCardanoDatabaseSnapshot({ immutableDir: src, store: new ArtifactStore(join(root, "other")), network: "preview", beacon: { epoch: 10, immutableFileNumber: 2 }, certificate: other.standard })).rejects.toThrow(/not the root certificate/);
        });

        test("routes: list, detail, certificates, digests, downloads", async () => {
            const list = (await (await fetch(`${base()}/artifact/cardano-database`)).json()) as { hash: string; certificate_hash: string }[];
            expect(list.length).toBe(1);
            expect(list[0]!.certificate_hash).toBe(chain.standard.hash);
            expect(((await (await fetch(`${base()}/artifact/cardano-database/epoch/10`)).json()) as unknown[]).length).toBe(1);
            expect(((await (await fetch(`${base()}/artifact/cardano-database/epoch/11`)).json()) as unknown[]).length).toBe(0);
            const detail = (await (await fetch(`${base()}/artifact/cardano-database/${list[0]!.hash}`)).json()) as { merkle_root: string; immutables: { locations: { uri: { Template: string } }[] } };
            expect(detail.merkle_root).toBe(merkleRoot);
            expect(detail.immutables.locations[0]!.uri.Template).toBe(`${base()}/cardano-database-download/immutable/{immutable_file_number}.tar.zst`);
            const cert = await fetch(`${base()}/certificate/${chain.genesis.hash}`);
            expect(cert.headers.get("mithril-api-version")).toBeTruthy();
            expect(await cert.text()).toBe(chain.texts.get(chain.genesis.hash)!);
            expect(((await (await fetch(`${base()}/certificates`)).json()) as unknown[]).length).toBe(2);
            const digests = (await (await fetch(`${base()}/artifact/cardano-database/digests`)).json()) as unknown[];
            expect(digests.length).toBe(9);
            const arch = await fetch(`${base()}/cardano-database-download/immutable/00001.tar.zst`);
            const archBytes = new Uint8Array(await arch.arrayBuffer());
            expect(Number(arch.headers.get("content-length"))).toBe(archBytes.length);
            expect(Buffer.compare(archBytes, readFileSync(store.immutableArchive(1)))).toBe(0);
            const head = await fetch(`${base()}/cardano-database-download/immutable/00001.tar.zst`, { method: "HEAD" });
            expect(head.status).toBe(200);
            expect(Number(head.headers.get("content-length"))).toBe(archBytes.length);
            expect((await fetch(`${base()}/cardano-database-download/immutable/00009.tar.zst`)).status).toBe(404);
            expect((await fetch(`${base()}/cardano-database-download/../../etc/passwd`)).status).toBe(404);
            expect((await fetch(`${base()}/cardano-database-download/digests/..%2F..%2Fx.tar.zst`)).status).toBe(404);
            expect((await fetch(`${base()}/statistics/cardano-database/complete-restoration`, { method: "POST", body: "{}" })).status).toBe(201);
            expect((await fetch(`${base()}/artifact/cardano-database`, { method: "PUT" })).status).toBe(405);
        });

        test("a restore from the served artifacts gives byte-identical chunks", async () => {
            const dl = join(root, "dl");
            const seen: string[] = [];
            const r = await restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, downloadDir: dl, concurrency: 2, onProgress: (p) => seen.push(p.phase) });
            expect(r.certificate.hash).toBe(chain.standard.hash);
            expect(r.chain.hops.length).toBe(2);
            expect(r.downloaded).toEqual([0, 1, 2]);
            expect(r.verification.checked).toBe(9);
            expect(r.digests.merkleRoot).toBe(merkleRoot);
            expect(new Set(seen)).toEqual(new Set(["certificate", "download", "verify"]));
            for (let n = 0; n <= 2; n++) {
                for (const ext of ["chunk", "primary", "secondary"]) {
                    const name = `${immutableStem(n)}.${ext}`;
                    expect(Buffer.compare(readFileSync(join(r.immutableDir, name)), readFileSync(join(src, name)))).toBe(0);
                }
            }
            // Re-verifying the directory without downloading.
            const again = await restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, downloadDir: dl, skipDownload: true });
            expect(again.downloaded).toEqual([]);
            expect(again.verification.checked).toBe(9);
        });

        test("a restore with the ancillary archive: the last trio is covered by its signed manifest", async () => {
            const dl = join(root, "dl-anc");
            const r = await restoreCardanoDatabase({ network: "preview", aggregator: `${server.origin}/with-ancillary`, genesisVkey: chain.genesisVkeyHex, downloadDir: dl, includeAncillary: true, ancillaryVkey: anc.vkeyHex });
            expect(r.ancillary?.verification.ok).toBe(true);
            expect(r.ancillary?.ledgerDir).toBe(join(dl, "ledger"));
            expect(r.verification.checked).toBe(12);
            expect(r.verification.nonVerifiable).toEqual([]);
            // Another key: the manifest signature fails and the restore stops.
            await expect(restoreCardanoDatabase({ network: "preview", aggregator: `${server.origin}/with-ancillary`, genesisVkey: chain.genesisVkeyHex, downloadDir: join(root, "dl-anc2"), includeAncillary: true, ancillaryVkey: testAncillaryKey(12).vkeyHex })).rejects.toThrow(/ancillary verification failed/);
        });

        test("a stale trio left in a resumed download dir is fetched again", async () => {
            const dl = join(root, "dl-stale");
            mkdirSync(join(dl, "immutable"), { recursive: true });
            writeTrio(join(dl, "immutable"), 1);
            writeFileSync(join(dl, "immutable", "00001.chunk"), bytes(4242, 999)); // complete trio, wrong bytes
            const r = await restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, downloadDir: dl });
            expect(r.skipped).toEqual([1]);
            expect(r.refetched).toEqual([1]);
            expect(Buffer.compare(readFileSync(join(r.immutableDir, "00001.chunk")), readFileSync(join(src, "00001.chunk")))).toBe(0);
        });

        test("a tampered archive is detected by the client", async () => {
            // Replace 00001's archive with one carrying different chunk bytes.
            const evil = join(root, "evil");
            mkdirSync(evil);
            writeTrio(evil, 1);
            writeFileSync(join(evil, "00001.chunk"), bytes(999, 20_777));
            const { archive } = await buildImmutableArchive(evil, 1);
            const path = store.immutableArchive(1);
            const good = readFileSync(path);
            writeFileSync(path, archive);
            try {
                await expect(restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, downloadDir: join(root, "dl-evil") })).rejects.toThrow(/tampered \(00001\.chunk\)/);
            } finally {
                writeFileSync(path, good);
            }
        });

        test("an archive carrying another trio's file is refused before it is written", async () => {
            const entries: TarEntry[] = ["chunk", "primary", "secondary"].map((e) => ({ name: `immutable/00001.${e}`, data: new Uint8Array(readFileSync(join(src, `00001.${e}`))) }));
            entries.unshift({ name: "immutable/00000.chunk", data: bytes(5, 100) });
            const path = store.immutableArchive(1);
            const good = readFileSync(path);
            writeFileSync(path, zstdCompress(buildTar(entries)));
            const dl = join(root, "dl-evil2");
            try {
                await expect(restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, downloadDir: dl, from: 1, to: 1 })).rejects.toThrow(/unexpected entry "immutable\/00000\.chunk"/);
                expect(existsSync(join(dl, "immutable", "00000.chunk"))).toBe(false);
            } finally {
                writeFileSync(path, good);
            }
        });

        test("produceCertifiedSnapshot certifies a second copy of the chunks against the served snapshot", async () => {
            // The served store acts as the aggregator: same list and certificate routes.
            const copy = join(root, "copy", "immutable");
            mkdirSync(copy, { recursive: true });
            for (let n = 0; n <= 3; n++) writeTrio(copy, n);
            const r = await produceCertifiedSnapshot({ immutableDir: copy, store: new ArtifactStore(join(root, "artifacts2")), network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, archiveRange: { from: 0, to: 0 } });
            expect(r.certified).toBe(true);
            expect(r.target.verify.hops.length).toBe(2);
            expect(r.target.chain.map((c) => c.hash).sort()).toEqual([chain.genesis.hash, chain.standard.hash].sort());
            expect(r.snapshot.hash).toBe(cardanoDatabaseSnapshotHash(10, merkleRoot));
            expect(r.archivesWritten).toBe(1);
            // Different bytes in one file: the root no longer matches the certificate.
            writeFileSync(join(copy, "00002.secondary"), bytes(77, 10));
            await expect(produceCertifiedSnapshot({ immutableDir: copy, store: new ArtifactStore(join(root, "artifacts3")), network: "preview", aggregator: base(), genesisVkey: chain.genesisVkeyHex, archiveRange: { from: 0, to: 0 } })).rejects.toThrow(/not the root certificate/);
        });

        test("a wrong genesis key rejects the chain", async () => {
            const key = Buffer.from(JSON.stringify(Array.from({ length: 32 }, (_, i) => i)), "utf8").toString("hex");
            await expect(restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: key, downloadDir: join(root, "dl-key") })).rejects.toThrow(/CertificateGenesis/);
        });

        test("the genesis key can be a file path", async () => {
            const keyFile = join(root, "genesis.vkey");
            writeFileSync(keyFile, chain.genesisVkeyHex + "\n");
            const r = await restoreCardanoDatabase({ network: "preview", aggregator: base(), genesisVkey: keyFile, downloadDir: join(root, "dl"), skipDownload: true });
            expect(r.chain.genesisHash).toBe(chain.genesis.hash);
        });
    });
});
