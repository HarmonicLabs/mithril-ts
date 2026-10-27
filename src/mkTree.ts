/**
 * Mithril MKTree (mithril-merkle-tree on ckb-merkle-mountain-range 0.6): the cardano-database v2
 * Merkle root over the immutable file digests.
 *
 *   - leaves: the digests list in BTreeMap order of `immutable_file_name`, files numbered up to the
 *     snapshot's immutable file number; a leaf is the UTF-8 bytes of the hex digest string
 *     (MKTreeNode `From<&str>`), not the decoded digest;
 *   - merge = Blake2s-256(left || right);
 *   - root = bag_rhs_peaks: while more than one peak, pop right then left, push merge(right, left).
 *
 * Golden vector (mithril-merkle-tree tests::golden_merkle_root): leaves "golden-1".."golden-5" give
 * 3bbced153528697ecde7345a22e50115306478353619411523e804f2323fd921.
 */

import { blake2s256 } from "./blake2s";
import { bytesToHex, concatBytes, utf8 } from "./bytes";
import { sha256 } from "./hash";

export const MKTREE_GOLDEN_LEAVES = ["golden-1", "golden-2", "golden-3", "golden-4", "golden-5"] as const;
export const MKTREE_GOLDEN_ROOT_HEX = "3bbced153528697ecde7345a22e50115306478353619411523e804f2323fd921";

export type ImmutableFileDigest = { immutable_file_name: string; digest: string };

const IMM_NAME = /^(\d+)\.(chunk|primary|secondary)$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;

/** ckb `get_peak_map`: which peak heights are present for an MMR of this size. */
function peakMap(mmrSize: bigint): bigint {
    if (mmrSize === 0n) return 0n;
    let peakSize = (1n << BigInt(mmrSize.toString(2).length)) - 1n;
    let map = 0n;
    let pos = mmrSize;
    while (peakSize > 0n) {
        map <<= 1n;
        if (pos >= peakSize) {
            pos -= peakSize;
            map |= 1n;
        }
        peakSize >>= 1n;
    }
    return map;
}

/** ckb `get_peaks`: peak positions, left to right. */
function peakPositions(mmrSize: bigint): bigint[] {
    if (mmrSize === 0n) return [];
    let peakSize = (1n << BigInt(mmrSize.toString(2).length)) - 1n;
    const out: bigint[] = [];
    let pos = mmrSize;
    let sum = 0n;
    while (peakSize > 0n) {
        if (pos >= peakSize) {
            pos -= peakSize;
            out.push(sum + peakSize - 1n);
            sum += peakSize;
        }
        peakSize >>= 1n;
    }
    return out;
}

/** An append-only Merkle mountain range with Mithril's merge. */
export class MkTree {
    private readonly nodes: Uint8Array[] = [];
    private leaves = 0;

    get size(): number {
        return this.nodes.length;
    }

    get leafCount(): number {
        return this.leaves;
    }

    push(leaf: Uint8Array): void {
        const pm = peakMap(BigInt(this.nodes.length));
        this.nodes.push(leaf);
        let peak = 1n;
        let cur = leaf;
        while ((pm & peak) !== 0n) {
            peak <<= 1n;
            const leftPos = this.nodes.length - Number(peak);
            cur = blake2s256(this.nodes[leftPos]!, cur);
            this.nodes.push(cur);
        }
        this.leaves++;
    }

    root(): Uint8Array {
        if (this.nodes.length === 0) throw new Error("MkTree: root of an empty tree");
        const peaks = peakPositions(BigInt(this.nodes.length)).map((p) => this.nodes[Number(p)]!);
        while (peaks.length > 1) {
            const right = peaks.pop()!;
            const left = peaks.pop()!;
            peaks.push(blake2s256(right, left));
        }
        return peaks[0]!;
    }
}

export function mkTreeRoot(leaves: Uint8Array[]): Uint8Array {
    const t = new MkTree();
    for (const l of leaves) t.push(l);
    return t.root();
}

export function immutableFileNumber(name: string): number | null {
    const m = IMM_NAME.exec(name);
    return m ? Number(m[1]) : null;
}

/** Digests numbered <= lastImmutableFileNumber, sorted by file name (proving.rs VerifiedDigests). */
export function certifiedDigests(digests: ImmutableFileDigest[], lastImmutableFileNumber: number): ImmutableFileDigest[] {
    const out = digests.filter((d) => {
        const n = immutableFileNumber(d.immutable_file_name);
        return n !== null && n <= lastImmutableFileNumber;
    });
    out.sort((a, b) => (a.immutable_file_name < b.immutable_file_name ? -1 : a.immutable_file_name > b.immutable_file_name ? 1 : 0));
    for (let i = 1; i < out.length; i++) {
        if (out[i]!.immutable_file_name === out[i - 1]!.immutable_file_name) throw new Error(`digests: ${out[i]!.immutable_file_name} listed twice`);
    }
    return out;
}

/** The cardano-database Merkle root (hex) of a digests list up to an immutable file number. */
export function cardanoDatabaseMerkleRoot(digests: ImmutableFileDigest[], lastImmutableFileNumber: number): string {
    const list = certifiedDigests(digests, lastImmutableFileNumber);
    if (list.length === 0) throw new Error(`digests: none numbered <= ${lastImmutableFileNumber}`);
    for (const d of list) if (typeof d.digest !== "string" || !HEX64.test(d.digest)) throw new Error(`digests: bad digest for ${d.immutable_file_name}`);
    return bytesToHex(mkTreeRoot(list.map((d) => utf8(d.digest.toLowerCase()))));
}

/** CardanoDatabaseSnapshot::compute_hash: hex(SHA-256(epoch u64 big-endian || merkle root hex)). */
export function cardanoDatabaseSnapshotHash(epoch: number | bigint, merkleRootHex: string): string {
    const e = new Uint8Array(8);
    new DataView(e.buffer).setBigUint64(0, BigInt(epoch));
    return bytesToHex(sha256(concatBytes(e, utf8(merkleRootHex))));
}

/** `{network}-e{epoch}-i{immutable}.digests`: the aggregator's digests file name, without extension. */
export function digestsFileStem(network: string, epoch: number | bigint, immutable: number): string {
    return `${network}-e${epoch}-i${immutable}.digests`;
}
