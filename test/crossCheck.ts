/**
 * Cross-check: the same certificates through Gerolamo's verifier (noble-based, imported from the
 * sibling gerolamo checkout, test-only) and through Gerolamino's (@harmoniclabs/crypto). Verdicts
 * must agree on every case, untampered and tampered.
 *
 *   bun test/mithril/crossCheck.ts [--gerolamo /path/to/gerolamo] [--fuzz 200]
 *
 * Exported as `runCrossCheck` for crossCheck.test.ts. Runtime code never imports Gerolamo.
 */

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

import * as mine from "../src/index";
import { concatenationProofJson, parseConcatenationProof, verifyConcatenationProof as myStm } from "../src/stm";
import { encodeJsonHex, parseJsonLossless, stringifyJsonLossless } from "../src/json";
import { protocolMessageHash as myPmHash } from "../src/certificate";

export const DEFAULT_GEROLAMO = resolve(import.meta.dir, "../../gerolamo");
const FIX = join(import.meta.dir, "fixtures");

type Side = {
    name: string;
    parseCertificate(t: string): any;
    computeCertificateHash(c: any): string;
    verifyStandardCertificate(c: any, p: any): unknown;
    verifyStandardCertificateIntegrity(c: any): unknown;
    verifyGenesisCertificate(c: any, k: Uint8Array): void;
    decodeGenesisVerificationKey(s: string): Uint8Array;
    verifyCertificateChain(c: any, o: any): Promise<{ hops: unknown[]; genesisHash: string | null }>;
};

export type CaseResult = { name: string; gerolamo: string; gerolamino: string; agree: boolean };
export type CrossCheckReport = {
    cases: CaseResult[];
    agreed: number;
    disagreed: number;
    accepted: number;
    rejected: number;
    chain: { certificates: number; gerolamoMs: number; gerolaminoMs: number; bothReachedGenesis: boolean };
};

async function loadGerolamo(dir: string): Promise<Side> {
    const v = await import(join(dir, "src/mithril/verify/verifier.ts"));
    const c = await import(join(dir, "src/mithril/verify/certificate.ts"));
    return {
        name: "gerolamo",
        parseCertificate: c.parseCertificate,
        computeCertificateHash: c.computeCertificateHash,
        verifyStandardCertificate: v.verifyStandardCertificate,
        verifyStandardCertificateIntegrity: v.verifyStandardCertificateIntegrity,
        verifyGenesisCertificate: v.verifyGenesisCertificate,
        decodeGenesisVerificationKey: v.decodeGenesisVerificationKey,
        verifyCertificateChain: v.verifyCertificateChain,
    };
}

const MINE: Side = {
    name: "gerolamino",
    parseCertificate: mine.parseCertificate,
    computeCertificateHash: mine.computeCertificateHash,
    verifyStandardCertificate: mine.verifyStandardCertificate,
    verifyStandardCertificateIntegrity: mine.verifyStandardCertificateIntegrity,
    verifyGenesisCertificate: mine.verifyGenesisCertificate,
    decodeGenesisVerificationKey: mine.decodeGenesisVerificationKey,
    verifyCertificateChain: mine.verifyCertificateChain,
};

/** "ok" or the error code (the text before the first colon). */
function verdict(f: () => unknown): string {
    try {
        f();
        return "ok";
    } catch (e) {
        const m = (e as Error).message ?? String(e);
        return `reject:${m.split(":")[0]}`;
    }
}
const accepted = (v: string) => v === "ok" || /^[0-9a-f]{64,}$/.test(v);

type Raw = Record<string, any>;
const clone = (o: Raw): Raw => parseJsonLossless(stringifyJsonLossless(o)) as Raw;
const text = (o: Raw) => stringifyJsonLossless(o);

/** Edit the concatenation proof inside multi_signature (canonical re-encoding). */
function editProof(o: Raw, edit: (p: ReturnType<typeof parseConcatenationProof>) => void): Raw {
    const p = parseConcatenationProof(o.multi_signature);
    edit(p);
    o.multi_signature = encodeJsonHex(concatenationProofJson(p));
    return o;
}

/** Recompute the content hash with Gerolamo's function (so the tampering reaches the deeper checks). */
function rehash(o: Raw, g: Side): Raw {
    o.hash = g.computeCertificateHash(g.parseCertificate(text(o)));
    return o;
}

function flipHexChar(s: string, at: number): string {
    return s.slice(0, at) + (parseInt(s[at]!, 16) ^ 1).toString(16) + s.slice(at + 1);
}

/** Deterministic PRNG for the fuzz cases. */
function prng(seed: number) {
    return () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32);
}

export async function runCrossCheck(opts: { gerolamoDir?: string; fuzz?: number; log?: (l: string) => void } = {}): Promise<CrossCheckReport> {
    const log = opts.log ?? (() => {});
    const g = await loadGerolamo(opts.gerolamoDir ?? DEFAULT_GEROLAMO);
    const sides = [g, MINE];
    const rnd = prng(20261016);
    const cases: CaseResult[] = [];
    const run = (name: string, f: (s: Side) => unknown) => {
        const [a, b] = sides.map((s) => verdict(() => f(s))) as [string, string];
        cases.push({ name, gerolamo: a, gerolamino: b, agree: accepted(a) === accepted(b) });
    };

    const rawOf = async (rel: string) => parseJsonLossless(await Bun.file(join(FIX, "certs", rel)).text()) as Raw;
    const previewKey = await Bun.file(join(FIX, "certs/preview/genesis.vkey")).text();
    const mainnetKey = await Bun.file(join(FIX, "certs/mainnet/genesis.vkey")).text();

    // --- certificate pairs: published fixtures plus every consecutive pair of the saved preview chain
    const chainFx = JSON.parse(new TextDecoder().decode(Bun.gunzipSync(await Bun.file(join(FIX, "chains/preview.json.gz")).bytes()))) as {
        tip: string;
        certificates: Record<string, string>;
    };
    const pairs: { name: string; cert: Raw; prev: Raw; next?: Raw }[] = [
        { name: "preview cdb", cert: await rawOf("preview/cdb.json"), prev: await rawOf("preview/cdb-previous.json") },
        { name: "preview hop2 (new epoch)", cert: await rawOf("preview/hop2.json"), prev: await rawOf("preview/hop1.json") },
        { name: "preview hop1 (after genesis)", cert: await rawOf("preview/hop1.json"), prev: await rawOf("preview/genesis.json") },
        { name: "mainnet 56 signers", cert: await rawOf("mainnet/multi.json"), prev: await rawOf("mainnet/multi-previous.json") },
    ];
    let genesisRaw: Raw | null = null;
    {
        let h = chainFx.tip;
        let i = 0;
        let next: Raw | null = null;
        for (;;) {
            const c = parseJsonLossless(chainFx.certificates[h]!) as Raw;
            if (c.genesis_signature) {
                genesisRaw = c;
                break;
            }
            pairs.push({ name: `chain[${i}] epoch ${c.epoch}`, cert: c, prev: parseJsonLossless(chainFx.certificates[c.previous_hash]!) as Raw, next: next ?? undefined });
            next = c;
            h = c.previous_hash;
            i++;
        }
    }

    // --- untampered
    for (const p of pairs) run(`${p.name}: untampered`, (s) => s.verifyStandardCertificate(s.parseCertificate(text(p.cert)), s.parseCertificate(text(p.prev))));
    for (const [label, raw, key] of [
        ["preview genesis (fixture)", await rawOf("preview/genesis.json"), previewKey],
        ["preview genesis (chain)", genesisRaw!, previewKey],
    ] as const) {
        run(`${label}: preview key`, (s) => s.verifyGenesisCertificate(s.parseCertificate(text(raw)), s.decodeGenesisVerificationKey(key)));
        run(`${label}: mainnet key (must reject)`, (s) => s.verifyGenesisCertificate(s.parseCertificate(text(raw)), s.decodeGenesisVerificationKey(mainnetKey)));
        for (const at of [0, 40, 127]) {
            const t = clone(raw);
            t.genesis_signature = flipHexChar(t.genesis_signature, at);
            run(`${label}: genesis signature hex char ${at} flipped`, (s) => s.verifyGenesisCertificate(s.parseCertificate(text(t)), s.decodeGenesisVerificationKey(previewKey)));
            run(`${label}: genesis signature hex char ${at} flipped, rehashed`, (s) => s.verifyGenesisCertificate(s.parseCertificate(text(rehash(clone(t), g))), s.decodeGenesisVerificationKey(previewKey)));
        }
    }

    // --- tampered: the fixtures and every 20th chain certificate
    const targets = pairs.filter((_, i) => i < 4 || i % 20 === 0);
    for (const p of targets) {
        const integ = (o: Raw) => (s: Side) => s.verifyStandardCertificateIntegrity(s.parseCertificate(text(o)));
        const vsPrev = (o: Raw) => (s: Side) => s.verifyStandardCertificate(s.parseCertificate(text(o)), s.parseCertificate(text(p.prev)));
        const nSig = parseConcatenationProof(p.cert.multi_signature).signatures.length;
        const tamper = (label: string, edit: (o: Raw) => Raw) => {
            const t = edit(clone(p.cert));
            const r = rehash(clone(t), g);
            run(`${p.name}: ${label}`, vsPrev(t));
            // Rehashed: the content hash no longer catches it; the certificate alone, then with its predecessor.
            run(`${p.name}: ${label}, rehashed, alone`, integ(r));
            run(`${p.name}: ${label}, rehashed, with predecessor`, vsPrev(r));
            // ...and as the predecessor of the real next certificate, whose previous_hash binds its content.
            if (p.next) run(`${p.name}: ${label}, rehashed, under its successor`, (s) => s.verifyStandardCertificate(s.parseCertificate(text(p.next!)), s.parseCertificate(text(r))));
        };
        tamper("sigma byte flipped", (o) => editProof(o, (pr) => void (pr.signatures[0]!.sigma[20]! ^= 0x01)));
        tamper("sigma last byte flipped", (o) => editProof(o, (pr) => void (pr.signatures[nSig - 1]!.sigma[47]! ^= 0x80)));
        tamper("vk byte flipped", (o) => editProof(o, (pr) => void (pr.signatures[0]!.vk[50]! ^= 0x04)));
        tamper("multi-signature stake +1", (o) => editProof(o, (pr) => void (pr.signatures[0]!.stake += 1n)));
        tamper("lottery index changed", (o) => editProof(o, (pr) => void (pr.signatures[0]!.indexes[0]! += 1n)));
        tamper("batch path value byte flipped", (o) =>
            editProof(o, (pr) => {
                if (pr.batchProof.values[0]) pr.batchProof.values[0][5]! ^= 0x01;
                else pr.signatures[0]!.stake ^= 1n;
            }),
        );
        if (nSig >= 2) tamper("one signer dropped", (o) => editProof(o, (pr) => void pr.signatures.pop()));
        tamper("signed_message hex char flipped", (o) => ((o.signed_message = flipHexChar(o.signed_message, 10)), o));
        tamper("protocol message part changed, signed_message recomputed", (o) => {
            const parts = o.protocol_message.message_parts as Record<string, string>;
            const k = parts.cardano_database_merkle_root ? "cardano_database_merkle_root" : parts.snapshot_digest ? "snapshot_digest" : "next_protocol_parameters";
            parts[k] = flipHexChar(parts[k]!, 0);
            o.signed_message = myPmHash(new Map(Object.entries(parts)) as never);
            return o;
        });
        tamper("metadata signer stake +1", (o) => {
            if (o.metadata.signers?.[0]) o.metadata.signers[0].stake = BigInt(o.metadata.signers[0].stake) + 1n;
            return o;
        });
        tamper("AVK total_stake +1", (o) => {
            const avk = parseJsonLossless(new TextDecoder().decode(Uint8Array.from(Buffer.from(o.aggregate_verification_key, "hex")))) as Raw;
            avk.total_stake = BigInt(avk.total_stake) + 1n;
            o.aggregate_verification_key = encodeJsonHex(stringifyJsonLossless(avk));
            return o;
        });
        tamper("epoch +1", (o) => ((o.epoch = Number(o.epoch) + 1), o));
        tamper("previous_hash changed", (o) => ((o.previous_hash = flipHexChar(o.previous_hash, 3)), o));
        tamper("phi_f lowered", (o) => ((o.metadata.parameters.phi_f = 0.0001), o));
    }

    // --- STM level: random single-byte flips in the signed bytes, sigmas, vks and stakes
    const fuzz = opts.fuzz ?? 200;
    const stmTargets = targets.map((p) => p.cert);
    for (let i = 0; i < fuzz; i++) {
        const raw = stmTargets[Math.floor(rnd() * stmTargets.length)]!;
        const which = ["msg", "sigma", "vk", "stake", "root"][Math.floor(rnd() * 5)]!;
        const msg = new TextEncoder().encode(raw.signed_message as string);
        const proof = parseConcatenationProof(raw.multi_signature);
        const avk = mine.parseCertificate(text(raw)).avk;
        const si = Math.floor(rnd() * proof.signatures.length);
        const bit = 1 << Math.floor(rnd() * 8);
        if (which === "msg") msg[Math.floor(rnd() * msg.length)]! ^= bit;
        if (which === "sigma") proof.signatures[si]!.sigma[Math.floor(rnd() * 48)]! ^= bit;
        if (which === "vk") proof.signatures[si]!.vk[Math.floor(rnd() * 96)]! ^= bit;
        if (which === "stake") proof.signatures[si]!.stake ^= BigInt(bit);
        if (which === "root") avk.root[Math.floor(rnd() * 32)]! ^= bit;
        const params = mine.parseCertificate(text(raw)).metadata.parameters;
        const gStm = (await import(join(opts.gerolamoDir ?? DEFAULT_GEROLAMO, "src/mithril/verify/stm.ts"))).verifyConcatenationProof;
        const a = verdict(() => gStm(msg, avk, params, proof));
        const b = verdict(() => myStm(msg, avk, params, proof));
        cases.push({ name: `fuzz ${i}: ${which} bit flipped (sig ${si})`, gerolamo: a, gerolamino: b, agree: accepted(a) === accepted(b) });
    }

    // --- cardano-database Merkle roots (MKTree over Blake2s): Gerolamo's noble blake2s vs our pure-TS one
    {
        const gMk = await import(join(opts.gerolamoDir ?? DEFAULT_GEROLAMO, "src/mithril/pureTs/mkTree.ts"));
        for (const n of [1, 2, 3, 7, 64, 100, 1000, 3001]) {
            const files = Math.ceil(n / 3);
            const list = Array.from({ length: n }, (_, i) => ({
                immutable_file_name: `${String(Math.floor(i / 3)).padStart(5, "0")}.${["chunk", "primary", "secondary"][i % 3]}`,
                digest: Array.from({ length: 64 }, () => Math.floor(rnd() * 16).toString(16)).join(""),
            }));
            const a = gMk.computeCardanoDatabaseMerkleRootFromDigests(list, files - 1).rootHex as string;
            const b = mine.cardanoDatabaseMerkleRoot(list, files - 1);
            cases.push({ name: `MKTree root of ${n} digests`, gerolamo: a, gerolamino: b, agree: a === b });
        }
    }

    // --- full chain walk by both
    const timeWalk = async (s: Side) => {
        const t0 = performance.now();
        const r = await s.verifyCertificateChain(s.parseCertificate(chainFx.certificates[chainFx.tip]!), {
            genesisVkey: s.decodeGenesisVerificationKey(previewKey),
            retrieve: async (h: string) => s.parseCertificate(chainFx.certificates[h]!),
        });
        return { ms: performance.now() - t0, ok: r.genesisHash !== null, hops: r.hops.length };
    };
    const gw = await timeWalk(g);
    const mw = await timeWalk(MINE);
    log(`chain walk: gerolamo ${gw.ms.toFixed(0)} ms, gerolamino ${mw.ms.toFixed(0)} ms, ${mw.hops} certificates`);

    const disagreed = cases.filter((c) => !c.agree).length;
    return {
        cases,
        agreed: cases.length - disagreed,
        disagreed,
        accepted: cases.filter((c) => accepted(c.gerolamino)).length,
        rejected: cases.filter((c) => !accepted(c.gerolamino)).length,
        chain: { certificates: mw.hops, gerolamoMs: gw.ms, gerolaminoMs: mw.ms, bothReachedGenesis: gw.ok && mw.ok },
    };
}

if (import.meta.main) {
    const args = process.argv.slice(2);
    const at = (f: string) => (args.includes(f) ? args[args.indexOf(f) + 1] : undefined);
    const dir = at("--gerolamo") ?? DEFAULT_GEROLAMO;
    if (!existsSync(join(dir, "src/mithril/verify/verifier.ts"))) {
        console.error(`Gerolamo's verifier not found under ${dir}`);
        process.exit(2);
    }
    const r = await runCrossCheck({ gerolamoDir: dir, fuzz: Number(at("--fuzz") ?? 200), log: console.log });
    const tampered = r.cases.filter((c) => !/untampered|preview key$|^MKTree/.test(c.name));
    const alone = tampered.filter((c) => c.name.endsWith("rehashed, alone"));
    const counts = new Map<string, number>();
    for (const c of r.cases) counts.set(`${c.gerolamo} | ${c.gerolamino}`, (counts.get(`${c.gerolamo} | ${c.gerolamino}`) ?? 0) + 1);
    console.log(`\n${r.cases.length} cases: ${r.agreed} agree, ${r.disagreed} disagree; gerolamino accepted ${r.accepted}, rejected ${r.rejected}`);
    console.log(`tampered cases: ${tampered.length}, accepted by gerolamino: ${tampered.filter((c) => c.gerolamino === "ok").length}`);
    console.log("\nverdict pairs (gerolamo | gerolamino):");
    for (const [k, n] of [...counts].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(5)}  ${k}`);
    const kinds = (cs: CaseResult[]) => [...new Set(cs.map((c) => c.name.replace(/^.*?: /, "")))].join("; ");
    console.log(`rehashed certificates checked alone and accepted (bound only by the chain links): ${alone.filter((c) => c.gerolamino === "ok").length}: ${kinds(alone.filter((c) => c.gerolamino === "ok"))}`);
    const succ = tampered.filter((c) => c.name.endsWith("under its successor"));
    console.log(`rehashed certificates checked under their successor: ${succ.length}, accepted: ${succ.filter((c) => c.gerolamino === "ok" || c.gerolamo === "ok").length}`);
    const acceptedTampered = tampered.filter((c) => !c.name.endsWith("rehashed, alone") && (c.gerolamino === "ok" || c.gerolamo === "ok"));
    if (acceptedTampered.length) {
        console.log("\ntampered cases accepted with their predecessor (by either):");
        for (const c of acceptedTampered) console.log(`  ${c.name}: gerolamo ${c.gerolamo}, gerolamino ${c.gerolamino}`);
    }
    if (r.disagreed) {
        console.log("\nDISAGREEMENTS:");
        for (const c of r.cases.filter((x) => !x.agree)) console.log(`  ${c.name}: gerolamo ${c.gerolamo}, gerolamino ${c.gerolamino}`);
    }
    console.log(`\nchain: ${r.chain.certificates} certificates, both reached genesis: ${r.chain.bothReachedGenesis}; gerolamo ${(r.chain.gerolamoMs / 1000).toFixed(2)} s, gerolamino ${(r.chain.gerolaminoMs / 1000).toFixed(2)} s`);
    process.exit(r.disagreed === 0 && r.chain.bothReachedGenesis ? 0 : 1);
}
