import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import {
    BlsG1,
    BlsG2,
    bls12_381_G1_add,
    bls12_381_G1_compress,
    bls12_381_G1_equal,
    bls12_381_G1_scalarMul,
    bls12_381_G1_uncompress,
    bls12_381_G2_add,
    bls12_381_G2_compress,
    bls12_381_G2_equal,
    bls12_381_G2_scalarMul,
    bls12_381_G2_uncompress,
} from "@harmoniclabs/crypto";

import { aggregateBls, aggregationScalars, blsVerify, decodeSignature, decodeVerificationKey, FP_MODULUS, hashToG1, msm, VerificationKeyCache } from "../src/bls";
import { bytesToHex, concatBytes, hexToBytes } from "../src/bytes";
import { parseCertificate } from "../src/certificate";

type Vectors = {
    hashToG1: { msg: string; point: string }[];
    singles: { msg: string; vk: string; sig: string; valid: boolean }[];
    aggregates: { msg: string; vks: string[]; sigs: string[]; aggVk: string; aggSig: string; valid: boolean }[];
};
const FIX = join(import.meta.dir, "fixtures");
const V = (await Bun.file(join(FIX, "bls-vectors.json")).json()) as Vectors;

const beBytes = (n: bigint, len: number) => {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return out;
};
const beInt = (b: Uint8Array) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
const modpow = (b: bigint, e: bigint, m: bigint) => {
    let r = 1n;
    b %= m;
    while (e > 0n) {
        if (e & 1n) r = (r * b) % m;
        b = (b * b) % m;
        e >>= 1n;
    }
    return r;
};

describe("BLS12-381 on @harmoniclabs/crypto: vectors from Gerolamo's noble code", () => {
    test("hash to G1 with the empty DST equals noble's hashToCurve(msg, { DST: '' })", () => {
        for (const v of V.hashToG1) expect(bytesToHex(bls12_381_G1_compress(hashToG1(hexToBytes(v.msg))))).toBe(v.point);
    });

    test("single min_sig signatures verify; wrong message or wrong key do not", () => {
        for (const v of V.singles) {
            expect(v.valid).toBe(true);
            const msg = hexToBytes(v.msg);
            const vk = decodeVerificationKey(hexToBytes(v.vk));
            const sig = decodeSignature(hexToBytes(v.sig));
            expect(blsVerify(msg, vk, sig)).toBe(true);
            const bad = msg.slice();
            bad[0]! ^= 1;
            expect(blsVerify(bad, vk, sig)).toBe(false);
        }
        const other = decodeVerificationKey(hexToBytes(V.singles[1]!.vk));
        expect(blsVerify(hexToBytes(V.singles[0]!.msg), other, decodeSignature(hexToBytes(V.singles[0]!.sig)))).toBe(false);
    });

    test("Mithril-weighted aggregates equal noble's (Pippenger) points and verify", () => {
        for (const a of V.aggregates) {
            const sigBytes = a.sigs.map(hexToBytes);
            const agg = aggregateBls(a.vks.map((x) => decodeVerificationKey(hexToBytes(x))), sigBytes.map(decodeSignature), sigBytes);
            expect(bytesToHex(bls12_381_G2_compress(agg.vk))).toBe(a.aggVk);
            expect(bytesToHex(bls12_381_G1_compress(agg.sig))).toBe(a.aggSig);
            expect(blsVerify(hexToBytes(a.msg), agg.vk, agg.sig)).toBe(true);
            // Plain (unweighted) sums are not Mithril's aggregate: they verify as a plain BLS
            // aggregate, but the points differ from the weighted ones.
            const plainSig = sigBytes.map(decodeSignature).reduce((x, y) => bls12_381_G1_add(x, y));
            expect(bls12_381_G1_equal(plainSig, agg.sig)).toBe(false);
        }
    });

    test("msm equals the sum of scalar multiplications (G1 and G2, 1..40 points)", () => {
        let seed = 99;
        const rnd = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32);
        for (const n of [1, 2, 5, 17, 40]) {
            const sc = Array.from({ length: n }, () => BigInt(Math.floor(rnd() * 2 ** 32)) * BigInt(Math.floor(rnd() * 2 ** 32)) * BigInt(Math.floor(rnd() * 2 ** 32)));
            sc[0] = 0n;
            const p1 = sc.map((_, i) => bls12_381_G1_scalarMul(BigInt(i + 3), BlsG1.BASE));
            const p2 = sc.map((_, i) => bls12_381_G2_scalarMul(BigInt(i + 5), BlsG2.BASE));
            const n1 = p1.reduce((acc, p, i) => bls12_381_G1_add(acc, bls12_381_G1_scalarMul(sc[i]!, p)), BlsG1.ZERO);
            const n2 = p2.reduce((acc, p, i) => bls12_381_G2_add(acc, bls12_381_G2_scalarMul(sc[i]!, p)), BlsG2.ZERO);
            expect(bls12_381_G1_equal(msm(p1, sc, bls12_381_G1_add, BlsG1.ZERO), n1)).toBe(true);
            expect(bls12_381_G2_equal(msm(p2, sc, bls12_381_G2_add, BlsG2.ZERO), n2)).toBe(true);
        }
    }, 30_000); // 80 multi-scalar multiplications in pure TS: about 5 s

    test("aggregation scalars: Blake2b-128 over all sigmas then the u64 BE index, little-endian", () => {
        const sigs = V.aggregates[0]!.sigs.map(hexToBytes);
        const s = aggregationScalars(sigs);
        expect(s.length).toBe(sigs.length);
        for (const x of s) expect(x < 1n << 128n).toBe(true);
        expect(new Set(s.map(String)).size).toBe(s.length);
    });

    test("a real certificate's single signer verifies: msgp = signed_message (UTF-8) || AVK root", async () => {
        const c = parseCertificate(await Bun.file(join(FIX, "certs/preview/cdb.json")).text());
        if (c.signature.kind !== "multi") throw new Error("expected a multi-signature");
        const s = c.signature.proof.signatures[0]!;
        const msgp = concatBytes(new TextEncoder().encode(c.signedMessage), c.avk.root);
        expect(blsVerify(msgp, decodeVerificationKey(s.vk), decodeSignature(s.sigma))).toBe(true);
        expect(blsVerify(new TextEncoder().encode(c.signedMessage), decodeVerificationKey(s.vk), decodeSignature(s.sigma))).toBe(false);
    });
});

describe("decoding with blst sig_validate / key_validate semantics", () => {
    test("identity sigma and vk are rejected (HL itself decodes them as ZERO)", () => {
        const inf1 = new Uint8Array(48);
        inf1[0] = 0xc0;
        const inf2 = new Uint8Array(96);
        inf2[0] = 0xc0;
        expect(bls12_381_G1_equal(bls12_381_G1_uncompress(inf1), BlsG1.ZERO)).toBe(true);
        expect(() => decodeSignature(inf1)).toThrow(/SignatureInvalid/);
        expect(() => decodeVerificationKey(inf2)).toThrow(/VerificationKeyInvalid/);
    });

    test("a G1 point on the curve but outside the prime-order subgroup is rejected", () => {
        // y^2 = x^3 + 4 over Fp; p = 3 mod 4, so sqrt(a) = a^((p+1)/4).
        let x = 5n;
        let bytes: Uint8Array | null = null;
        while (!bytes) {
            const rhs = (modpow(x, 3n, FP_MODULUS) + 4n) % FP_MODULUS;
            const y = modpow(rhs, (FP_MODULUS + 1n) / 4n, FP_MODULUS);
            if ((y * y) % FP_MODULUS === rhs) {
                bytes = beBytes(x, 48);
                bytes[0]! |= 0x80;
                if (y > (FP_MODULUS - 1n) / 2n) bytes[0]! |= 0x20;
            }
            x++;
        }
        expect(() => bls12_381_G1_uncompress(bytes!)).toThrow(/subgroup/);
        expect(() => decodeSignature(bytes!)).toThrow(/SignatureInvalid.*subgroup/);
    });

    test("missing compression flag and wrong lengths are rejected", () => {
        const sig = hexToBytes(V.singles[0]!.sig);
        const noFlag = sig.slice();
        noFlag[0]! &= 0x7f;
        expect(() => decodeSignature(noFlag)).toThrow(/SignatureInvalid/);
        expect(() => decodeSignature(sig.subarray(0, 47))).toThrow(/SignatureInvalid/);
        expect(() => decodeVerificationKey(hexToBytes(V.singles[0]!.vk).subarray(0, 95))).toThrow(/VerificationKeyInvalid/);
    });

    test("HL gap: uncompress accepts a non-canonical x >= p (reduces it mod p); decodeSignature rejects it", () => {
        // Find a signature whose x + p still fits the 381 bits of the encoding.
        const limit = (1n << 381n) - FP_MODULUS;
        const candidates = Array.from({ length: 64 }, (_, k) => bls12_381_G1_compress(bls12_381_G1_scalarMul(BigInt(k + 2), BlsG1.BASE)));
        const sig = candidates.find((b) => beInt(Uint8Array.from([b[0]! & 0x1f, ...b.subarray(1)])) < limit);
        expect(sig).toBeDefined();
        const xs = beInt(Uint8Array.from([sig![0]! & 0x1f, ...sig!.subarray(1)]));
        const alias = beBytes(xs + FP_MODULUS, 48);
        alias[0]! |= sig![0]! & 0xe0;
        expect(bytesToHex(alias)).not.toBe(bytesToHex(sig!));
        // HL decodes the alias to the very same point (blst returns BLST_BAD_ENCODING here).
        expect(bls12_381_G1_equal(bls12_381_G1_uncompress(alias), bls12_381_G1_uncompress(sig!))).toBe(true);
        expect(() => decodeSignature(alias)).toThrow(/SignatureInvalid: sigma is x coordinate not below p/);
    });

    test("HL gap, G2: a non-canonical x.c1 >= p is accepted by HL, rejected by decodeVerificationKey", () => {
        const limit = (1n << 381n) - FP_MODULUS;
        const candidates = Array.from({ length: 64 }, (_, k) => bls12_381_G2_compress(bls12_381_G2_scalarMul(BigInt(k + 2), BlsG2.BASE)));
        const vk = candidates.find((b) => beInt(Uint8Array.from([b[0]! & 0x1f, ...b.subarray(1, 48)])) < limit);
        expect(vk).toBeDefined();
        const x1 = beInt(Uint8Array.from([vk![0]! & 0x1f, ...vk!.subarray(1, 48)]));
        const alias = concatBytes(beBytes(x1 + FP_MODULUS, 48), vk!.subarray(48));
        alias[0]! |= vk![0]! & 0xe0;
        expect(bls12_381_G2_equal(bls12_381_G2_uncompress(alias), bls12_381_G2_uncompress(vk!))).toBe(true);
        expect(() => decodeVerificationKey(alias)).toThrow(/VerificationKeyInvalid: vk is x coordinate not below p/);
    });

    test("verification key cache returns the decoded point and never caches failures", () => {
        const cache = new VerificationKeyCache(2);
        const vks = V.singles.slice(0, 3).map((v) => hexToBytes(v.vk));
        const a = cache.decode(vks[0]!);
        expect(cache.decode(vks[0]!)).toBe(a);
        cache.decode(vks[1]!);
        cache.decode(vks[2]!); // evicts the oldest
        expect(bls12_381_G2_equal(cache.decode(vks[0]!), a)).toBe(true);
        const bad = vks[0]!.slice();
        bad[0]! &= 0x7f;
        expect(() => cache.decode(bad)).toThrow();
        expect(() => cache.decode(bad)).toThrow();
    });
});
