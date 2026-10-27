/**
 * BLS12-381 test vectors for Mithril's scheme, produced with Gerolamo's noble-based code
 * (@noble/curves 1.9.7 from the sibling gerolamo checkout; dev-only, never runtime):
 *   bun test/mithril/fixtures/genBls.ts [/path/to/gerolamo]
 * Writes test/mithril/fixtures/bls-vectors.json.
 *
 * Contents: hash-to-G1 with the empty DST; single min_sig signatures (sigma = sk * H(msg) in G1,
 * vk = sk * g2); Mithril-weighted aggregates (Gerolamo's aggregateBls); the expected verdicts.
 */

import { join, resolve } from "node:path";

const gerolamo = process.argv[2] ?? resolve(import.meta.dir, "../../../../gerolamo");
// Resolve noble exactly as stm.ts does (same module instance, so points pass its instanceof checks).
const { bls12_381: bls } = await import(Bun.resolveSync("@noble/curves/bls12-381", join(gerolamo, "src/mithril/verify")));
const stm = await import(join(gerolamo, "src/mithril/verify/stm.ts"));

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const EMPTY = new Uint8Array(0);
const enc = new TextEncoder();
let seed = 0x5eed;
const rndBytes = (n: number) => Uint8Array.from({ length: n }, () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 24));
const ORDER: bigint = bls.params.r;
const scalar = () => {
    let s = 0n;
    for (const b of rndBytes(40)) s = (s << 8n) | BigInt(b);
    return (s % (ORDER - 1n)) + 1n;
};
const H = (m: Uint8Array) => bls.G1.hashToCurve(m, { DST: EMPTY });

const hashToG1 = [enc.encode(""), enc.encode("abc"), rndBytes(32), rndBytes(200), enc.encode("a".repeat(64) + "map")].map((m) => ({
    msg: hex(m),
    point: hex(H(m).toRawBytes(true)),
}));

const singles = Array.from({ length: 6 }, (_, i) => {
    const sk = scalar();
    const msg = rndBytes(32 + i * 13);
    const vk = bls.G2.ProjectivePoint.BASE.multiply(sk);
    const sig = H(msg).multiply(sk);
    return { msg: hex(msg), vk: hex(vk.toRawBytes(true)), sig: hex(sig.toRawBytes(true)), valid: stm.blsVerify(msg, vk, sig) as boolean };
});

const aggregates = [2, 3, 7].map((n) => {
    const msg = rndBytes(96);
    const sks = Array.from({ length: n }, scalar);
    const vks = sks.map((sk) => bls.G2.ProjectivePoint.BASE.multiply(sk));
    const sigs = sks.map((sk) => H(msg).multiply(sk));
    const sigBytes = sigs.map((s) => s.toRawBytes(true) as Uint8Array);
    const agg = stm.aggregateBls(vks, sigs, sigBytes);
    return {
        msg: hex(msg),
        vks: vks.map((v) => hex(v.toRawBytes(true))),
        sigs: sigBytes.map(hex),
        aggVk: hex(agg.vk.toRawBytes(true)),
        aggSig: hex(agg.sig.toRawBytes(true)),
        valid: stm.blsVerify(msg, agg.vk, agg.sig) as boolean,
    };
});

const out = join(import.meta.dir, "bls-vectors.json");
await Bun.write(out, JSON.stringify({ generator: "gerolamo src/mithril/verify/stm.ts + @noble/curves 1.9.7", dst: "", hashToG1, singles, aggregates }, null, 1));
console.log(`wrote ${out}: ${hashToG1.length} hash-to-G1, ${singles.length} signatures, ${aggregates.length} aggregates`);
