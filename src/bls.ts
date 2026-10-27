/**
 * BLS12-381 for Mithril STM, on @harmoniclabs/crypto's Plutus builtin set
 * (`bls12_381_G1_*`, `bls12_381_G2_*`, `bls12_381_millerLoop`, `bls12_381_finalVerify`).
 *
 * Mithril STM is blst "min_sig": signatures in G1 (48-byte compressed), verification keys in G2
 * (96-byte compressed), hash-to-G1 with the empty domain separation tag (blst's default when the
 * caller passes `&[]`), i.e. hash_to_curve BLS12381G1_XMD:SHA-256_SSWU_RO_ with DST = "".
 *
 * Aggregation (mithril-stm `BlsSignature::aggregate`): one signer is used as is; for n >= 2 every
 * signer i gets the scalar s_i = Blake2b-128(sigma_0 || ... || sigma_{n-1} || u64_be(i)), read as a
 * little-endian integer (blst scalars), and the aggregate is (sum s_i * vk_i, sum s_i * sigma_i).
 * blst computes the sums with Pippenger multi-scalar multiplication; so does `msm` below, built on
 * the builtin `add` (complete formulas, so add(P, P) doubles).
 *
 * Verification: e(sigma, g2) == e(H(msg), vk), as finalVerify(millerLoop(sigma, g2),
 * millerLoop(H(msg), vk)).
 *
 * Decoding follows blst `sig_validate(true)` / `key_validate`: canonical compressed encoding, on the
 * curve, in the prime-order subgroup, not the identity. HL's uncompress checks curve and subgroup
 * but reduces the x coordinate mod p, so a non-canonical x >= p is rejected here first.
 */

import {
    BlsG1,
    BlsG2,
    bls12_381_G1_add,
    bls12_381_G1_equal,
    bls12_381_G1_hashToGroup,
    bls12_381_G1_uncompress,
    bls12_381_G2_add,
    bls12_381_G2_equal,
    bls12_381_G2_uncompress,
    bls12_381_finalVerify,
    bls12_381_millerLoop,
} from "./hl";

import { bytesToHex, concatBytes, u64be } from "./bytes";
import { blake2b128 } from "./hash";

export type G1Point = BlsG1;
export type G2Point = BlsG2;

/** The hash-to-curve DST Mithril STM uses (blst min_sig with `dst = &[]`). */
export const MITHRIL_STM_DST = new Uint8Array(0);

/** BLS12-381 base field modulus. */
export const FP_MODULUS = BigInt(
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
);

export class BlsDecodeError extends Error {
    constructor(readonly code: "SignatureInvalid" | "VerificationKeyInvalid", message: string) {
        super(`${code}: ${message}`);
        this.name = "BlsDecodeError";
    }
}

const G1_ZERO = (): G1Point => BlsG1.ZERO as G1Point;
const G2_ZERO = (): G2Point => BlsG2.ZERO as G2Point;

function beInt(b: Uint8Array, from: number, to: number, mask = 0xff): bigint {
    let n = BigInt(b[from]! & mask);
    for (let i = from + 1; i < to; i++) n = (n << 8n) | BigInt(b[i]!);
    return n;
}

/** Compression flag set, infinity flag clear, and every 48-byte x limb below p (blst BLST_BAD_ENCODING otherwise). */
function canonicalCompressed(bytes: Uint8Array): string | null {
    const flags = bytes[0]! & 0xe0;
    if ((flags & 0x80) === 0) return "compression flag not set";
    if ((flags & 0x40) !== 0) return "the identity";
    for (let off = 0; off < bytes.length; off += 48) {
        if (beInt(bytes, off, off + 48, off === 0 ? 0x1f : 0xff) >= FP_MODULUS) return "x coordinate not below p";
    }
    return null;
}

/** Compressed G1 signature with blst `sig_validate(true)` semantics. */
export function decodeSignature(bytes: Uint8Array): G1Point {
    if (bytes.length !== 48) throw new BlsDecodeError("SignatureInvalid", `sigma is ${bytes.length} bytes, want 48`);
    const bad = canonicalCompressed(bytes);
    if (bad) throw new BlsDecodeError("SignatureInvalid", `sigma is ${bad}`);
    let p: G1Point;
    try {
        p = bls12_381_G1_uncompress(bytes) as G1Point; // on curve and in the prime-order subgroup
    } catch (e) {
        throw new BlsDecodeError("SignatureInvalid", `sigma does not decode: ${(e as Error).message}`);
    }
    if (bls12_381_G1_equal(p, G1_ZERO())) throw new BlsDecodeError("SignatureInvalid", "sigma is the identity");
    return p;
}

/** Compressed G2 verification key with blst `key_validate` semantics. */
export function decodeVerificationKey(bytes: Uint8Array): G2Point {
    if (bytes.length !== 96) throw new BlsDecodeError("VerificationKeyInvalid", `vk is ${bytes.length} bytes, want 96`);
    const bad = canonicalCompressed(bytes);
    if (bad) throw new BlsDecodeError("VerificationKeyInvalid", `vk is ${bad}`);
    let p: G2Point;
    try {
        p = bls12_381_G2_uncompress(bytes) as G2Point;
    } catch (e) {
        throw new BlsDecodeError("VerificationKeyInvalid", `vk does not decode: ${(e as Error).message}`);
    }
    if (bls12_381_G2_equal(p, G2_ZERO())) throw new BlsDecodeError("VerificationKeyInvalid", "vk is the identity");
    return p;
}

/**
 * Decoded verification keys, keyed by their bytes. A chain walk sees the same signers on every
 * certificate of an epoch; decoding a G2 key (square root in Fp2 plus subgroup check) is the most
 * expensive part of decoding, and its result depends on the bytes only.
 */
export class VerificationKeyCache {
    private readonly map = new Map<string, G2Point>();
    constructor(readonly capacity = 4096) {}
    decode(bytes: Uint8Array): G2Point {
        const k = bytesToHex(bytes);
        const hit = this.map.get(k);
        if (hit) return hit;
        const p = decodeVerificationKey(bytes); // throws: failures are never cached
        if (this.map.size >= this.capacity) this.map.delete(this.map.keys().next().value!);
        this.map.set(k, p);
        return p;
    }
}

export const defaultVerificationKeyCache = new VerificationKeyCache();

/** The Blake2b-128 aggregation scalars of BlsSignature::aggregate (little-endian). */
export function aggregationScalars(sigBytes: Uint8Array[]): bigint[] {
    const all = concatBytes(...sigBytes);
    return sigBytes.map((_, i) => {
        const h = blake2b128(all, u64be(BigInt(i)));
        let s = 0n;
        for (let j = 15; j >= 0; j--) s = (s << 8n) | BigInt(h[j]!);
        return s;
    });
}

/**
 * Pippenger multi-scalar multiplication sum(scalars[i] * points[i]) from `add` alone
 * (scalars >= 0; doubling is add(P, P), valid with complete addition formulas).
 */
export function msm<P>(points: P[], scalars: bigint[], add: (a: P, b: P) => P, zero: P): P {
    if (points.length !== scalars.length) throw new Error("msm: length mismatch");
    let bits = 0;
    for (const s of scalars) {
        if (s < 0n) throw new Error("msm: negative scalar");
        bits = Math.max(bits, s.toString(2).length);
    }
    if (bits === 0 || points.length === 0) return zero;
    // Window width minimising (windows * (n + 2^(c+1) + c)).
    let c = 1;
    let best = Infinity;
    for (let w = 1; w <= 16; w++) {
        const cost = Math.ceil(bits / w) * (points.length + 2 ** (w + 1) + w);
        if (cost < best) {
            best = cost;
            c = w;
        }
    }
    const mask = (1n << BigInt(c)) - 1n;
    const windows = Math.ceil(bits / c);
    let acc: P = zero;
    for (let w = windows - 1; w >= 0; w--) {
        for (let i = 0; i < c; i++) acc = add(acc, acc);
        const buckets: (P | null)[] = new Array(2 ** c).fill(null);
        const shift = BigInt(w * c);
        for (let i = 0; i < points.length; i++) {
            const d = Number((scalars[i]! >> shift) & mask);
            if (d === 0) continue;
            const b = buckets[d];
            buckets[d] = b === null ? points[i]! : add(b, points[i]!);
        }
        // sum_d d * bucket[d] by running sums from the top bucket down.
        let running: P | null = null;
        let sum: P | null = null;
        for (let d = buckets.length - 1; d >= 1; d--) {
            const b = buckets[d];
            if (b !== null) running = running === null ? b : add(running, b);
            if (running !== null) sum = sum === null ? running : add(sum, running);
        }
        if (sum !== null) acc = add(acc, sum);
    }
    return acc;
}

/** BlsSignature::aggregate: (vk, sig) for one signer, else the Blake2b-128 weighted sums. */
export function aggregateBls(vks: G2Point[], sigs: G1Point[], sigBytes: Uint8Array[]): { vk: G2Point; sig: G1Point } {
    if (vks.length !== sigs.length || vks.length !== sigBytes.length || vks.length === 0) {
        throw new Error("AggregateSignatureInvalid: empty or mismatched aggregation");
    }
    if (vks.length === 1) return { vk: vks[0]!, sig: sigs[0]! };
    const scalars = aggregationScalars(sigBytes);
    return {
        vk: msm(vks, scalars, (a, b) => bls12_381_G2_add(a, b) as G2Point, G2_ZERO()),
        sig: msm(sigs, scalars, (a, b) => bls12_381_G1_add(a, b) as G1Point, G1_ZERO()),
    };
}

/** Hash to G1 with Mithril's (empty) DST. */
export function hashToG1(msg: Uint8Array): G1Point {
    return bls12_381_G1_hashToGroup(msg, MITHRIL_STM_DST) as G1Point;
}

/** blst min_sig `verify(false, msg, dst = [], aug = [], pk, false)`. */
export function blsVerify(msg: Uint8Array, vk: G2Point, sig: G1Point): boolean {
    if (bls12_381_G2_equal(vk, G2_ZERO()) || bls12_381_G1_equal(sig, G1_ZERO())) return false;
    const h = hashToG1(msg);
    return bls12_381_finalVerify(bls12_381_millerLoop(sig, BlsG2.BASE as G2Point), bls12_381_millerLoop(h, vk));
}
