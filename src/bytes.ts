/** Byte helpers for the Mithril verifier. Portable: no Buffer, no node:crypto. */

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

export function bytesToHex(b: Uint8Array): string {
    let s = "";
    for (let i = 0; i < b.length; i++) s += HEX[b[i]!];
    return s;
}

export function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex string");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}

export function u64le(n: bigint): Uint8Array {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n, true);
    return b;
}

export function u64be(n: bigint): Uint8Array {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n, false);
    return b;
}

export function i64be(n: bigint): Uint8Array {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, n, false);
    return b;
}

const enc = new TextEncoder();
export const utf8 = (s: string): Uint8Array => enc.encode(s);
