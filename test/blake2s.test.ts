import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";

import { Blake2s, blake2s, blake2s256 } from "../src/blake2s";
import { bytesToHex } from "../src/bytes";

const utf8 = (s: string) => new TextEncoder().encode(s);

/** RFC 7693 Appendix E: deterministic input generator (Fibonacci-style, u32). */
function selftestSeq(len: number, seed: number): Uint8Array {
    const out = new Uint8Array(len);
    let a = Math.imul(0xdead4bad, seed) >>> 0;
    let b = 1;
    for (let i = 0; i < len; i++) {
        const t = (a + b) >>> 0;
        a = b;
        b = t;
        out[i] = (t >>> 24) & 0xff;
    }
    return out;
}

describe("BLAKE2s (RFC 7693)", () => {
    test('Appendix B: BLAKE2s-256("abc")', () => {
        expect(bytesToHex(blake2s(utf8("abc")))).toBe("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    });

    test("Appendix E: self-test grand hash (digest lengths 16/20/28/32, inputs 0..1024 bytes, keyed and unkeyed)", () => {
        const grand = new Blake2s(32);
        for (const outLen of [16, 20, 28, 32]) {
            for (const inLen of [0, 3, 64, 65, 255, 1024]) {
                const input = selftestSeq(inLen, inLen);
                grand.update(blake2s(input, outLen));
                const key = selftestSeq(outLen, outLen);
                grand.update(blake2s(input, outLen, key));
            }
        }
        expect(bytesToHex(grand.digest())).toBe("6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe");
    });

    test("reference KAT: empty input, unkeyed and keyed with 00..1f", () => {
        expect(bytesToHex(blake2s(new Uint8Array(0)))).toBe("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
        const key = Uint8Array.from({ length: 32 }, (_, i) => i);
        expect(bytesToHex(blake2s(new Uint8Array(0), 32, key))).toBe("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
    });

    test("agrees with node:crypto blake2s256 on lengths 0..300 and block boundaries", () => {
        for (let n = 0; n <= 300; n++) {
            const data = selftestSeq(n, n + 7);
            expect(bytesToHex(blake2s(data))).toBe(createHash("blake2s256").update(data).digest("hex"));
        }
    });

    test("incremental updates in any split give the one-shot digest", () => {
        const data = selftestSeq(1000, 3);
        const want = bytesToHex(blake2s(data));
        for (const step of [1, 7, 63, 64, 65, 128, 999]) {
            const h = new Blake2s();
            for (let i = 0; i < data.length; i += step) h.update(data.subarray(i, i + step));
            expect(bytesToHex(h.digest())).toBe(want);
        }
        expect(bytesToHex(blake2s256(data.subarray(0, 10), data.subarray(10)))).toBe(want);
    });

    test("parameter checks", () => {
        expect(() => new Blake2s(0)).toThrow(RangeError);
        expect(() => new Blake2s(33)).toThrow(RangeError);
        expect(() => new Blake2s(32, new Uint8Array(33))).toThrow(RangeError);
        const h = new Blake2s();
        h.digest();
        expect(() => h.digest()).toThrow();
    });
});
