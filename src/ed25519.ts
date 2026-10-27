/**
 * Strict Ed25519 verification (ed25519-dalek `verify_strict`), built on @harmoniclabs/crypto's
 * Edwards primitives (`pointFromBytes`, `scalarMul`, `scalarMultBase`, `addPointsEdwards`,
 * `sha2_512_sync`).
 *
 * HL's own `verifyEd25519Signature_sync` is the plain RFC 8032 equation [S]B = R + [k]A with no
 * further checks: it accepts S >= L (malleable signatures), non-canonical point encodings
 * (y >= p, or x = 0 with the sign bit set), small-order keys and R, and it throws instead of
 * returning false on bad lengths or points off the curve. Mithril's genesis signature is checked
 * with dalek's `verify_strict`, so the checks are added here:
 *   - R and A canonically encoded and on the curve;
 *   - neither R nor A of small order ([8]P = identity);
 *   - S < L;
 *   - k = SHA-512(R || A || M) mod L, then the cofactorless equation [S]B == R + [k]A.
 */

import { addPointsEdwards, pointFromBytes, scalarMul, scalarMultBase, sha2_512_sync, type bigpoint } from "./hl";

import { concatBytes } from "./bytes";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function leInt(b: Uint8Array): bigint {
    let n = 0n;
    for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
    return n;
}

const mod = (a: bigint, m: bigint): bigint => ((a % m) + m) % m;

function pointEq(a: Readonly<bigpoint>, b: Readonly<bigpoint>): boolean {
    return mod(a[0], P) === mod(b[0], P) && mod(a[1], P) === mod(b[1], P);
}

const IDENTITY: bigpoint = [0n, 1n];

/** Decode a point with RFC 8032 strict rules (canonical y, no "negative zero" x); null when invalid. */
export function decodePointStrict(bytes: Uint8Array): bigpoint | null {
    if (bytes.length !== 32) return null;
    const yBytes = bytes.slice();
    yBytes[31]! &= 0x7f;
    if (leInt(yBytes) >= P) return null;
    let pt: bigpoint;
    try {
        pt = pointFromBytes(bytes.slice());
    } catch {
        return null;
    }
    if (mod(pt[0], P) === 0n && (bytes[31]! & 0x80) !== 0) return null;
    return [mod(pt[0], P), mod(pt[1], P)];
}

export function isSmallOrder(pt: Readonly<bigpoint>): boolean {
    return pointEq(scalarMul(pt, 8n), IDENTITY);
}

/** ed25519-dalek `verify_strict`. Never throws. */
export function ed25519VerifyStrict(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
    if (sig.length !== 64 || pk.length !== 32) return false;
    try {
        const Rb = sig.slice(0, 32);
        const R = decodePointStrict(Rb);
        const A = decodePointStrict(pk);
        if (!R || !A) return false;
        if (isSmallOrder(R) || isSmallOrder(A)) return false;
        const S = leInt(sig.subarray(32, 64));
        if (S >= L) return false;
        const k = leInt(sha2_512_sync(concatBytes(Rb, pk, msg))) % L;
        const left = scalarMultBase(S);
        const right = addPointsEdwards(R, scalarMul(A, k));
        return pointEq(left, right);
    } catch {
        return false;
    }
}
