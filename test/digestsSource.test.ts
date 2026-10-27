import { describe, expect, test } from "bun:test";
import { loadDigests } from "../src/anchor";
import { AggregatorClient } from "../src/aggregator";
import { cardanoDatabaseMerkleRoot, type ImmutableFileDigest } from "../src/mkTree";

/** Digests of immutable files 0..n (fake but well-formed). */
const list = (n: number, salt = ""): ImmutableFileDigest[] =>
    Array.from({ length: (n + 1) * 3 }, (_, i) => ({ immutable_file_name: `${String(Math.floor(i / 3)).padStart(5, "0")}.${["chunk", "primary", "secondary"][i % 3]}`, digest: new Bun.CryptoHasher("sha256").update(`${i}${salt}`).digest("hex") }));
const N = 10;
const good = list(N);
const root = cardanoDatabaseMerkleRoot(good, N);

/** A peer serving `digests` in pages of `per` immutable files; counts its requests. */
function peer(digests: ImmutableFileDigest[] | null, per = 4) {
    const calls: Array<[number, number]> = [];
    return {
        calls,
        lq: {
            chunk: async () => null,
            digests: async (from: number, to: number) => {
                calls.push([from, to]);
                if (!digests) return null;
                const end = Math.min(to, from + per - 1);
                return { from, to: end, entries: digests.filter((d) => { const k = Number(d.immutable_file_name.slice(0, 5)); return k >= from && k <= end; }) };
            },
        },
    };
}
/** An aggregator that serves `digests` and counts downloads. */
function aggregator(digests: ImmutableFileDigest[]) {
    let downloads = 0;
    const client = new AggregatorClient("https://agg.example", async () => { downloads++; return { ok: true, status: 200, text: async () => JSON.stringify(digests) }; });
    return { client, downloads: () => downloads };
}
const quiet = () => {};

describe("Mithril start: where the immutable file digests come from", () => {
    test("from the peer, page by page, when they reproduce the certified root: no aggregator download", async () => {
        const p = peer(good), a = aggregator(good);
        const r = await loadDigests(a.client, { network: "preview", lq: p.lq }, N, root, quiet);
        expect(r.source).toBe("peer");
        expect(p.calls).toEqual([[0, 10], [4, 10], [8, 10]]);
        expect(a.downloads()).toBe(0);
    });

    test("wrong digests from the peer, or none yet: the aggregator, and its list must match", async () => {
        for (const bad of [list(N, "x"), null]) {
            const a = aggregator(good);
            const r = await loadDigests(a.client, { network: "preview", lq: peer(bad).lq }, N, root, quiet);
            expect(r.source).toBe("aggregator");
            expect(a.downloads()).toBe(1);
        }
        await expect(loadDigests(aggregator(list(N, "y")).client, { network: "preview", lq: peer(null).lq }, N, root, quiet)).rejects.toThrow(/Merkle root/);
    });

    test("the aggregator setting never asks the peer", async () => {
        const p = peer(good);
        const r = await loadDigests(aggregator(good).client, { network: "preview", lq: p.lq, digestsFrom: "aggregator" }, N, root, quiet);
        expect(r.source).toBe("aggregator");
        expect(p.calls).toHaveLength(0);
    });
});
