/**
 * BLAKE2s (RFC 7693), pure TypeScript on 32-bit words. @harmoniclabs/crypto has BLAKE2b only;
 * Mithril's MKTree (cardano-database Merkle root) merges nodes with Blake2s-256.
 *
 * Supports digest lengths 1..32 and keys of 0..32 bytes, one-shot (`blake2s`) and incremental
 * (`Blake2s.update` / `digest`).
 */

const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

// Message word schedule, 10 rounds x 16.
const SIGMA = new Uint8Array([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
]);

export class Blake2s {
    private readonly h = new Uint32Array(8);
    private readonly v = new Uint32Array(16);
    private readonly m = new Uint32Array(16);
    private readonly buf = new Uint8Array(64);
    private bufLen = 0;
    /** Byte counter t (up to 2^64, kept as two 32-bit halves). */
    private t0 = 0;
    private t1 = 0;
    private done = false;

    constructor(readonly outLen = 32, key?: Uint8Array) {
        if (!Number.isInteger(outLen) || outLen < 1 || outLen > 32) throw new RangeError(`blake2s: digest length ${outLen} not in 1..32`);
        const keyLen = key?.length ?? 0;
        if (keyLen > 32) throw new RangeError(`blake2s: key length ${keyLen} > 32`);
        this.h.set(IV);
        // Parameter block word 0: digest length, key length, fanout 1, depth 1.
        this.h[0]! ^= 0x01010000 ^ (keyLen << 8) ^ outLen;
        if (key && keyLen > 0) {
            this.buf.set(key);
            this.bufLen = 64; // the key block is a full (zero-padded) block
        }
    }

    update(data: Uint8Array): this {
        if (this.done) throw new Error("blake2s: update after digest");
        let i = 0;
        const n = data.length;
        while (i < n) {
            // Compress a full buffer only when more input follows (the last block is compressed in digest).
            if (this.bufLen === 64) {
                this.increment(64);
                this.compress(this.buf, 0, false);
                this.bufLen = 0;
            }
            const take = Math.min(64 - this.bufLen, n - i);
            this.buf.set(data.subarray(i, i + take), this.bufLen);
            this.bufLen += take;
            i += take;
        }
        return this;
    }

    digest(): Uint8Array {
        if (this.done) throw new Error("blake2s: digest called twice");
        this.done = true;
        this.increment(this.bufLen);
        this.buf.fill(0, this.bufLen);
        this.compress(this.buf, 0, true);
        const out = new Uint8Array(this.outLen);
        for (let i = 0; i < this.outLen; i++) out[i] = (this.h[i >>> 2]! >>> (8 * (i & 3))) & 0xff;
        return out;
    }

    private increment(n: number): void {
        const t = this.t0 + n;
        this.t0 = t >>> 0;
        if (t > 0xffffffff) this.t1 = (this.t1 + 1) >>> 0;
    }

    private compress(block: Uint8Array, off: number, last: boolean): void {
        const v = this.v;
        const m = this.m;
        const h = this.h;
        for (let i = 0; i < 16; i++) {
            const j = off + 4 * i;
            m[i] = block[j]! | (block[j + 1]! << 8) | (block[j + 2]! << 16) | (block[j + 3]! << 24);
        }
        for (let i = 0; i < 8; i++) {
            v[i] = h[i]!;
            v[i + 8] = IV[i]!;
        }
        v[12]! ^= this.t0;
        v[13]! ^= this.t1;
        if (last) v[14] = ~v[14]!;
        for (let r = 0; r < 10; r++) {
            const s = r * 16;
            g(v, m, 0, 4, 8, 12, SIGMA[s]!, SIGMA[s + 1]!);
            g(v, m, 1, 5, 9, 13, SIGMA[s + 2]!, SIGMA[s + 3]!);
            g(v, m, 2, 6, 10, 14, SIGMA[s + 4]!, SIGMA[s + 5]!);
            g(v, m, 3, 7, 11, 15, SIGMA[s + 6]!, SIGMA[s + 7]!);
            g(v, m, 0, 5, 10, 15, SIGMA[s + 8]!, SIGMA[s + 9]!);
            g(v, m, 1, 6, 11, 12, SIGMA[s + 10]!, SIGMA[s + 11]!);
            g(v, m, 2, 7, 8, 13, SIGMA[s + 12]!, SIGMA[s + 13]!);
            g(v, m, 3, 4, 9, 14, SIGMA[s + 14]!, SIGMA[s + 15]!);
        }
        for (let i = 0; i < 8; i++) h[i] = h[i]! ^ v[i]! ^ v[i + 8]!;
    }
}

function g(v: Uint32Array, m: Uint32Array, a: number, b: number, c: number, d: number, x: number, y: number): void {
    let va = v[a]!, vb = v[b]!, vc = v[c]!, vd = v[d]!;
    va = (va + vb + m[x]!) >>> 0;
    vd ^= va;
    vd = (vd >>> 16) | (vd << 16);
    vc = (vc + vd) >>> 0;
    vb ^= vc;
    vb = (vb >>> 12) | (vb << 20);
    va = (va + vb + m[y]!) >>> 0;
    vd ^= va;
    vd = (vd >>> 8) | (vd << 24);
    vc = (vc + vd) >>> 0;
    vb ^= vc;
    vb = (vb >>> 7) | (vb << 25);
    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
}

/** One-shot BLAKE2s. */
export function blake2s(data: Uint8Array, outLen = 32, key?: Uint8Array): Uint8Array {
    return new Blake2s(outLen, key).update(data).digest();
}

/** Blake2s-256 of the concatenation of `parts` (Mithril MKTreeNode merge). */
export function blake2s256(...parts: Uint8Array[]): Uint8Array {
    const h = new Blake2s(32);
    for (const p of parts) h.update(p);
    return h.digest();
}
