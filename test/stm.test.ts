import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import { encodeJsonHex, parseJsonLossless } from "../src/json";
import { evToBigInt, isLotteryWon, rationalFromFloat, taylorComparison } from "../src/lottery";
import {
    aggregateVerificationKeyJson,
    concatenationProofJson,
    parseAggregateVerificationKey,
    parseConcatenationProof,
    verifyConcatenationProof,
    type ConcatenationProof,
    type StmParameters,
} from "../src/stm";

const FIX = join(import.meta.dir, "fixtures");

function fromRaw(c: Record<string, any>) {
    const params: StmParameters = { k: BigInt(c.metadata.parameters.k), m: BigInt(c.metadata.parameters.m), phiF: c.metadata.parameters.phi_f };
    return {
        raw: c,
        msg: new TextEncoder().encode(c.signed_message as string),
        avk: parseAggregateVerificationKey(c.aggregate_verification_key),
        proof: parseConcatenationProof(c.multi_signature),
        params,
    };
}
const load = async (rel: string) => fromRaw(parseJsonLossless(await Bun.file(join(FIX, "certs", rel)).text()) as Record<string, any>);

/** Certificates of the live preview chain saved by fixtures/fetchChain.ts. */
const chain = JSON.parse(new TextDecoder().decode(Bun.gunzipSync(await Bun.file(join(FIX, "chains/preview.json.gz")).bytes()))) as {
    tip: string;
    certificates: Record<string, string>;
};
const chainMulti = Object.values(chain.certificates)
    .map((t) => parseJsonLossless(t) as Record<string, any>)
    .filter((c) => !c.genesis_signature);

const clone = (p: ConcatenationProof): ConcatenationProof => ({
    signatures: p.signatures.map((s) => ({ ...s, sigma: s.sigma.slice(), vk: s.vk.slice(), indexes: s.indexes.slice() })),
    batchProof: { values: p.batchProof.values.map((v) => v.slice()), indices: p.batchProof.indices.slice() },
});

describe("STM concatenation proof on real certificates", () => {
    test("preview certificate, one signer", async () => {
        const f = await load("preview/cdb.json");
        const r = verifyConcatenationProof(f.msg, f.avk, f.params, f.proof);
        expect(r.mode).toBe("single");
        expect(r.indices).toBeGreaterThanOrEqual(Number(f.params.k));
    });

    test("mainnet certificate, 56 signers: weighted BLS aggregate", async () => {
        const f = await load("mainnet/multi.json");
        const r = verifyConcatenationProof(f.msg, f.avk, f.params, f.proof);
        expect(r.signatures).toBe(56);
        expect(r.mode).toBe("aggregate");
        expect(r.indices).toBe(1960);
    });

    test(`live preview chain (fetched 2026-10-16): all ${chainMulti.length} standard certificates verify`, () => {
        const modes = { single: 0, aggregate: 0 };
        for (const c of chainMulti) {
            const f = fromRaw(c);
            modes[verifyConcatenationProof(f.msg, f.avk, f.params, f.proof).mode]++;
        }
        expect(modes.single + modes.aggregate).toBe(chainMulti.length);
        expect(modes.aggregate).toBeGreaterThan(0);
    }, 60_000);

    test("canonical re-encoding equals the published JSON hex", async () => {
        const raws = [
            ...(await Promise.all(["preview/cdb.json", "preview/hop1.json", "mainnet/multi.json", "mainnet/multi-previous.json"].map(async (r) => (await load(r)).raw))),
            ...chainMulti.slice(0, 50),
        ];
        for (const raw of raws) {
            const f = fromRaw(raw);
            expect(encodeJsonHex(aggregateVerificationKeyJson(f.avk))).toBe(raw.aggregate_verification_key);
            expect(encodeJsonHex(concatenationProofJson(f.proof))).toBe(raw.multi_signature);
        }
    });

    describe("tampered", () => {
        const reject = async (rel: string, mutate: (f: Awaited<ReturnType<typeof load>>) => void, code: RegExp) => {
            const f = await load(rel);
            f.proof = clone(f.proof);
            mutate(f);
            expect(() => verifyConcatenationProof(f.msg, f.avk, f.params, f.proof)).toThrow(code);
        };
        test("one flipped bit in a sigma", () => reject("mainnet/multi.json", (f) => void (f.proof.signatures[7]!.sigma[20]! ^= 0x01), /SignatureInvalid|LotteryLost/));
        test("one flipped bit in the signed message", () => reject("preview/cdb.json", (f) => ((f.msg = f.msg.slice()), void (f.msg[3]! ^= 0x01)), /LotteryLost|SignatureInvalid/));
        test("one flipped bit in the AVK root", () => reject("preview/cdb.json", (f) => ((f.avk = { ...f.avk, root: f.avk.root.slice() }), void (f.avk.root[0]! ^= 0x80)), /LotteryLost|BatchPathInvalid|SignatureInvalid/));
        test("inflated signer stake", () => reject("mainnet/multi.json", (f) => void (f.proof.signatures[0]!.stake += 1n), /BatchPathInvalid|LotteryLost/));
        test("one flipped bit in a verification key", () => reject("mainnet/multi.json", (f) => void (f.proof.signatures[3]!.vk[50]! ^= 0x04), /BatchPathInvalid/));
        test("one flipped bit in a batch path value", () => reject("mainnet/multi.json", (f) => void (f.proof.batchProof.values[0]![5]! ^= 0x01), /BatchPathInvalid/));
        test("duplicated lottery index", () => reject("mainnet/multi.json", (f) => void f.proof.signatures[0]!.indexes.push(f.proof.signatures[0]!.indexes[0]!), /IndexNotUnique/));
        test("index above m", () => reject("preview/cdb.json", (f) => void (f.params = { ...f.params, m: f.proof.signatures[0]!.indexes[0]! - 1n }), /IndexBoundFailed/));
        test("quorum k not reached", () =>
            reject("mainnet/multi.json", (f) => void (f.params = { ...f.params, k: BigInt(f.proof.signatures.reduce((a, s) => a + s.indexes.length, 0) + 1) }), /NotEnoughSignatures/));
        test("a signer dropped", () => reject("mainnet/multi.json", (f) => void f.proof.signatures.pop(), /NotEnoughSignatures|BatchPathInvalid/));
        test("lower phi_f makes a ticket lose", () => reject("preview/cdb.json", (f) => void (f.params = { ...f.params, phiF: 0.0001 }), /LotteryLost/));
        test("two sigmas swapped", () =>
            reject("mainnet/multi.json", (f) => {
                const [a, b] = [f.proof.signatures[0]!, f.proof.signatures[1]!];
                [a.sigma, b.sigma] = [b.sigma, a.sigma];
            }, /LotteryLost|SignatureInvalid/));
        test("phi_f = 1 (every ticket wins): a wrong sigma is caught by the pairing alone", () =>
            reject("preview/cdb.json", (f) => {
                f.params = { ...f.params, phiF: 1 };
                const other = parseConcatenationProof(chainMulti[3]!.multi_signature).signatures[0]!.sigma;
                f.proof.signatures[0]!.sigma = other.slice();
            }, /SignatureInvalid: aggregate BLS signature does not verify/));
    });
});

describe("lottery (exact rational port of is_lottery_won)", () => {
    test("rationalFromFloat is exact", () => {
        expect(rationalFromFloat(0.5)).toEqual([1n, 2n]);
        expect(rationalFromFloat(-0.75)).toEqual([-3n, 4n]);
        const [n, d] = rationalFromFloat(Math.log(0.3));
        expect(Number(n) / Number(d)).toBe(Math.log(0.3));
    });

    test("edge rules: phi_f = 1 always wins, zero stake never wins, zero total stake throws, phi_f out of range throws", () => {
        const ev = new Uint8Array(64).fill(0xff);
        expect(isLotteryWon(1.0, ev, 1n, 10n)).toBe(true);
        expect(isLotteryWon(0.7, new Uint8Array(64).fill(1), 0n, 10n)).toBe(false);
        expect(() => isLotteryWon(0.7, ev, 1n, 0n)).toThrow(/ZeroTotalStake/);
        expect(() => isLotteryWon(1.5, ev, 1n, 10n)).toThrow(/PhiFValueOutOfRange/);
    });

    test("agrees with an f64 reference away from the threshold", () => {
        let seed = 12345;
        const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
        let compared = 0;
        for (let i = 0; i < 400; i++) {
            const ev = new Uint8Array(64).map(() => Math.floor(rnd() * 256));
            const phi = [0.2, 0.65, 0.7][i % 3]!;
            const total = 10n ** 15n + BigInt(Math.floor(rnd() * 1e9));
            const stake = BigInt(Math.floor(rnd() * 1e6)) * 10n ** 9n;
            const p = Number(evToBigInt(ev)) / 2 ** 512;
            const thr = 1 - Math.pow(1 - phi, Number(stake) / Number(total));
            if (Math.abs(p - thr) < 1e-9) continue;
            expect(isLotteryWon(phi, ev, stake, total)).toBe(p < thr);
            compared++;
        }
        expect(compared).toBeGreaterThan(350);
    });

    test("taylorComparison: inconclusive gives false; clear cases decide", () => {
        expect(taylorComparison(10, 1n, 1n, 0n, 1n)).toBe(false);
        expect(taylorComparison(1000, 2n, 1n, 1n, 1n)).toBe(true);
        expect(taylorComparison(1000, 3n, 1n, 1n, 1n)).toBe(false);
    });
});
