/**
 * Download a Mithril certificate chain from an aggregator and save it as an offline fixture:
 *   bun test/mithril/fixtures/fetchChain.ts [network=preview] [certificateHash]
 * Without a hash, starts from the newest cardano-database snapshot's certificate. Writes
 * test/mithril/fixtures/chains/<network>.json.gz: { network, tip, snapshot, certificates: { hash: rawJson } }.
 * Certificates are stored as served (raw text); nothing is verified here.
 */

import { join } from "node:path";

import { AggregatorClient, mithrilNetworkConfig } from "../../src/aggregator";
import { parseCertificate } from "../../src/certificate";

const network = process.argv[2] ?? "preview";
const cfg = mithrilNetworkConfig(network);
const client = new AggregatorClient(cfg.aggregator);

let tip = process.argv[3];
let snapshot: unknown = null;
if (!tip) {
    const list = await client.listCardanoDatabase();
    snapshot = await client.cardanoDatabase(list[0]!.hash);
    tip = (snapshot as { certificate_hash: string }).certificate_hash;
}
const certificates: Record<string, string> = {};
const t0 = performance.now();
let h = tip;
for (;;) {
    const text = await client.certificateText(h);
    certificates[h] = text;
    const c = parseCertificate(text);
    if (c.signature.kind === "genesis") break;
    h = c.previousHash;
    if (Object.keys(certificates).length % 50 === 0) console.log(`${Object.keys(certificates).length} certificates, epoch ${c.epoch}`);
}
const out = join(import.meta.dir, "chains", `${network}.json.gz`);
const json = JSON.stringify({ network, tip, fetchedAt: new Date().toISOString(), snapshot, certificates });
await Bun.write(out, Bun.gzipSync(new TextEncoder().encode(json)));
console.log(`${Object.keys(certificates).length} certificates from ${tip.slice(0, 16)}… to genesis ${h.slice(0, 16)}… in ${((performance.now() - t0) / 1000).toFixed(1)} s -> ${out}`);
