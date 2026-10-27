import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import type { FetchLike } from "../src/aggregator";
import { mithrilAnchor } from "../src/anchor";

const chain = JSON.parse(new TextDecoder().decode(Bun.gunzipSync(await Bun.file(join(import.meta.dir, "fixtures/chains/preview.json.gz")).bytes()))) as {
    snapshot: { hash: string; network: string };
    certificates: Record<string, string>;
};

/** An aggregator stand-in serving the saved snapshot and chain. */
const fakeFetch = (snapshot: object): FetchLike => async (url) => {
    const path = new URL(url).pathname.replace(/^\/aggregator/, "");
    const body =
        path === "/artifact/cardano-database" ? JSON.stringify([snapshot])
        : path.startsWith("/artifact/cardano-database/") ? JSON.stringify(snapshot)
        : path.startsWith("/certificate/") ? chain.certificates[path.split("/").pop()!]
        : undefined;
    return { ok: body !== undefined, status: body === undefined ? 404 : 200, text: async () => body ?? "" };
};

describe("mithrilAnchor (offline)", () => {
    test("a relay without any certified beacon chunk: tries the listed snapshots, then fails clearly", async () => {
        const asked: number[] = [];
        const lines: string[] = [];
        await expect(
            mithrilAnchor({ network: "preview", lq: { chunk: async (n) => (asked.push(n), null) }, fetch: fakeFetch(chain.snapshot), store: null, log: (l) => lines.push(l) }),
        ).rejects.toThrow(/relay has none of the certified snapshots' last chunks/);
        expect(asked.length).toBe(1);
        expect(lines.some((l) => l.includes("does not have complete chunk"))).toBe(true);
    });

    test("a snapshot for another network is refused", async () => {
        const files = { chunk: new Uint8Array(1), primary: new Uint8Array(1), secondary: new Uint8Array(0) };
        await expect(mithrilAnchor({ network: "preview", lq: { chunk: async () => files }, fetch: fakeFetch({ ...chain.snapshot, network: "preprod" }), store: null })).rejects.toThrow(
            /snapshot is for preprod/,
        );
    });

    test("unknown network names are refused", async () => {
        await expect(mithrilAnchor({ network: "sanchonet", lq: { chunk: async () => null }, store: null })).rejects.toThrow(/unknown network/);
    });
});
