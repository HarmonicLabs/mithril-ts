/**
 * Live, network-gated tests (skipped unless MITHRIL_LIVE=1):
 *   MITHRIL_LIVE=1 bun test test/mithril/live.test.ts
 * - walks the newest preview cardano-database certificate back to genesis over the IOG aggregator
 *   (MITHRIL_SAVE=1 also refreshes fixtures/chains/preview.json.gz for the offline tests);
 * - runs mithrilAnchor end to end with a light-query stand-in that reads chunk files from a local
 *   cardano-node immutable directory (MITHRIL_CHUNK_DIR; read-only), when one is available.
 */

import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { AggregatorClient, cachingRetriever, mithrilNetworkConfig } from "../src/aggregator";
import { mithrilAnchor, type MithrilLightQuery } from "../src/anchor";
import { MemoryCertificateStore } from "../src/certStore";
import { decodeGenesisVerificationKey, verifyCertificateChain } from "../src/verifier";

const LIVE = process.env.MITHRIL_LIVE === "1";
const CHUNK_DIR = process.env.MITHRIL_CHUNK_DIR ?? "/media/bakon/data/cardano/gerolamo-preview-genesis3037/db/immutable";

/** Serves complete chunks from an immutable directory (a chunk is complete once the next one exists). */
export function diskLightQuery(dir: string): MithrilLightQuery & { has(n: number): boolean } {
    const name = (n: number, ext: string) => join(dir, `${n.toString().padStart(5, "0")}.${ext}`);
    const has = (n: number) => ["chunk", "primary", "secondary"].every((e) => existsSync(name(n, e))) && existsSync(name(n + 1, "chunk"));
    return {
        has,
        async chunk(n) {
            if (!has(n)) return null;
            const [chunk, primary, secondary] = await Promise.all(["chunk", "primary", "secondary"].map(async (e) => new Uint8Array(await Bun.file(name(n, e)).arrayBuffer())));
            return { chunk: chunk!, primary: primary!, secondary: secondary! };
        },
    };
}

describe.skipIf(!LIVE)("live preview (network)", () => {
    test("newest snapshot certificate walks back to genesis over the aggregator", async () => {
        const cfg = mithrilNetworkConfig("preview");
        const client = new AggregatorClient(cfg.aggregator);
        const list = await client.listCardanoDatabase();
        const snapshot = await client.cardanoDatabase(list[0]!.hash);
        const store = new MemoryCertificateStore();
        const retrieve = cachingRetriever(client, store);
        const r = await verifyCertificateChain(await retrieve(snapshot.certificate_hash), { genesisVkey: decodeGenesisVerificationKey(cfg.genesisVkey), retrieve });
        await retrieve.persist();
        console.log(
            `live walk: ${r.hops.length} certificates from ${snapshot.certificate_hash.slice(0, 16)}… to genesis ${r.genesisHash!.slice(0, 16)}…: ${(r.ms / 1000).toFixed(1)} s total, ${(r.verifyMs / 1000).toFixed(1)} s verifying`,
        );
        expect(r.genesisHash).not.toBeNull();
        if (process.env.MITHRIL_SAVE === "1") {
            const certificates = Object.fromEntries(store.map);
            const json = JSON.stringify({ network: "preview", tip: snapshot.certificate_hash, fetchedAt: new Date().toISOString(), snapshot, certificates });
            await Bun.write(join(import.meta.dir, "fixtures/chains/preview.json.gz"), Bun.gzipSync(new TextEncoder().encode(json)));
        }
    }, 600_000);

    test.skipIf(!existsSync(CHUNK_DIR))("mithrilAnchor end to end (chunks from a local immutable directory)", async () => {
        const lq = diskLightQuery(CHUNK_DIR);
        const client = new AggregatorClient(mithrilNetworkConfig("preview").aggregator);
        const list = await client.listCardanoDatabase();
        const pick = list.find((s) => lq.has(s.beacon.immutable_file_number));
        if (!pick) {
            console.log(`no listed snapshot's beacon chunk is complete in ${CHUNK_DIR}; skipping`);
            return;
        }
        const store = new MemoryCertificateStore();
        const lines: string[] = [];
        const t0 = performance.now();
        const a = await mithrilAnchor({ network: "preview", lq, store, snapshotHash: pick.hash, log: (l) => lines.push(l) });
        const first = performance.now() - t0;
        console.log(lines.join("\n"));
        console.log(`anchor: slot ${a.slot} hash ${a.hash} (chunk ${a.chunkNo}, ${a.blocksInChunk} blocks) in ${(first / 1000).toFixed(1)} s`);
        expect(a.slot).toBeGreaterThan(0);
        expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
        expect(a.chain.downloads).toBe(a.chain.certificates);

        // Second run: certificates from the cache, verified again.
        const t1 = performance.now();
        const b = await mithrilAnchor({ network: "preview", lq, store, snapshotHash: pick.hash });
        console.log(`anchor again with a warm certificate cache: ${((performance.now() - t1) / 1000).toFixed(1)} s, ${b.chain.cacheHits} cache hits`);
        expect(b.hash).toBe(a.hash);
        expect(b.chain.cacheHits).toBe(b.chain.certificates);

        // A relay serving different bytes is refused.
        const lying: MithrilLightQuery = {
            async chunk(n) {
                const f = await lq.chunk(n);
                if (!f) return null;
                const chunk = f.chunk.slice();
                chunk[chunk.length - 1]! ^= 1;
                return { ...f, chunk };
            },
        };
        await expect(mithrilAnchor({ network: "preview", lq: lying, store, snapshotHash: pick.hash })).rejects.toThrow(/does not match its certified digest/);
    }, 900_000);
});
