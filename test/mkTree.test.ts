import { describe, expect, test } from "bun:test";

import { bytesToHex, utf8 } from "../src/bytes";
import { lastBlockOfChunk, SECONDARY_ENTRY_SIZE } from "../src/chunkIndex";
import { cardanoDatabaseMerkleRoot, certifiedDigests, MKTREE_GOLDEN_LEAVES, MKTREE_GOLDEN_ROOT_HEX, mkTreeRoot } from "../src/mkTree";
import { blake2s256 } from "../src/blake2s";

describe("MKTree (mithril-merkle-tree / ckb MMR, Blake2s-256)", () => {
    test("golden_merkle_root: leaves golden-1..golden-5", () => {
        expect(bytesToHex(mkTreeRoot(MKTREE_GOLDEN_LEAVES.map(utf8)))).toBe(MKTREE_GOLDEN_ROOT_HEX);
    });

    test("small trees by hand: 1, 2 and 3 leaves (bag right to left)", () => {
        const [a, b, c] = ["a", "b", "c"].map(utf8) as [Uint8Array, Uint8Array, Uint8Array];
        expect(bytesToHex(mkTreeRoot([a]))).toBe(bytesToHex(a));
        expect(bytesToHex(mkTreeRoot([a, b]))).toBe(bytesToHex(blake2s256(a, b)));
        // Peaks: H(a,b) and c; bag_rhs_peaks merges (right, left).
        expect(bytesToHex(mkTreeRoot([a, b, c]))).toBe(bytesToHex(blake2s256(c, blake2s256(a, b))));
    });

    test("digests: filtered to the beacon, sorted by name, leaf = UTF-8 of the hex digest", () => {
        const d = (name: string, x: string) => ({ immutable_file_name: name, digest: x.repeat(64) });
        const list = [d("00001.chunk", "b"), d("00000.primary", "a"), d("00000.chunk", "c"), d("00002.chunk", "d"), d("junk", "e")];
        expect(certifiedDigests(list, 1).map((x) => x.immutable_file_name)).toEqual(["00000.chunk", "00000.primary", "00001.chunk"]);
        expect(cardanoDatabaseMerkleRoot(list, 1)).toBe(bytesToHex(mkTreeRoot(["c", "a", "b"].map((x) => utf8(x.repeat(64))))));
        expect(() => cardanoDatabaseMerkleRoot([d("00000.chunk", "z")], 0)).toThrow(/bad digest/);
        expect(() => certifiedDigests([d("00000.chunk", "a"), d("00000.chunk", "b")], 0)).toThrow(/twice/);
    });
});

describe("chunk index (primary / secondary)", () => {
    const entry = (blockOffset: number, slot: number, hashByte: number) => {
        const e = new Uint8Array(SECONDARY_ENTRY_SIZE);
        const dv = new DataView(e.buffer);
        dv.setBigUint64(0, BigInt(blockOffset));
        dv.setUint16(8, 3);
        dv.setUint16(10, 100);
        e.fill(hashByte, 16, 48);
        dv.setBigUint64(48, BigInt(slot));
        return e;
    };
    const primary = (offsets: number[]) => {
        const p = new Uint8Array(1 + 4 * offsets.length);
        p[0] = 1;
        offsets.forEach((o, i) => new DataView(p.buffer).setUint32(1 + 4 * i, o));
        return p;
    };

    test("the last filled slot's entry is the chunk's last block", () => {
        // Blocks at relative slots 1 and 3 of a 5-slot chunk (slot 0 is the EBB slot).
        const sec = new Uint8Array([...entry(0, 1001, 0xaa), ...entry(500, 1003, 0xbb)]);
        const pri = primary([0, 0, 56, 56, 112, 112, 112]);
        const { entry: last, blocks } = lastBlockOfChunk(pri, sec);
        expect(blocks).toBe(2);
        expect(last.slotOrEbb).toBe(1003);
        expect(last.blockOffset).toBe(500);
        expect(last.isEbb).toBe(false);
        expect(bytesToHex(last.headerHash)).toBe("bb".repeat(32));
    });

    test("inconsistent indexes are rejected", () => {
        const sec = new Uint8Array([...entry(0, 1, 1)]);
        expect(() => lastBlockOfChunk(primary([0, 56, 56, 112]), sec)).toThrow();
        expect(() => lastBlockOfChunk(Uint8Array.from([2, 0, 0, 0, 0]), sec)).toThrow(/version/);
        expect(() => lastBlockOfChunk(primary([0, 0]), new Uint8Array(0))).toThrow(/no blocks/);
    });
});
