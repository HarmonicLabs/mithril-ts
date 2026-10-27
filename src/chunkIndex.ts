/**
 * The parts of cardano-node's immutable chunk index the anchor reads (own copy, so src/mithril does
 * not depend on the node's chunk writer):
 *   - `.primary`: version byte 1, then big-endian u32 offsets into `.secondary`, one per relative
 *     slot (EBB slot first) plus an end marker; slot i holds a block when offsets[i+1] > offsets[i];
 *   - `.secondary`: 56-byte entries: block offset u64, header offset u16, header size u16, CRC u32,
 *     header hash (32), slot (or epoch for an EBB) u64, all big-endian.
 */

export const SECONDARY_ENTRY_SIZE = 56;
export const PRIMARY_VERSION = 1;

export type SecondaryEntry = {
    blockOffset: number;
    headerOffset: number;
    headerSize: number;
    crc: number;
    headerHash: Uint8Array;
    /** Slot of a regular block, epoch of a Byron EBB. */
    slotOrEbb: number;
    isEbb: boolean;
};

export function decodePrimary(pri: Uint8Array): number[] {
    if (pri.length < 1 || pri[0] !== PRIMARY_VERSION) throw new Error(`primary index version ${pri[0]} (expected ${PRIMARY_VERSION})`);
    if ((pri.length - 1) % 4 !== 0) throw new Error(`primary index size ${pri.length} is not 1 + 4n`);
    const n = (pri.length - 1) / 4;
    const dv = new DataView(pri.buffer, pri.byteOffset + 1, n * 4);
    const out = new Array<number>(n);
    for (let i = 0; i < n; i++) out[i] = dv.getUint32(i * 4, false);
    return out;
}

/** Relative slots holding a block, in order; the k-th one belongs to secondary entry k. */
export function filledRelativeSlots(offsets: number[]): number[] {
    const out: number[] = [];
    for (let i = 0; i + 1 < offsets.length; i++) if (offsets[i + 1]! > offsets[i]!) out.push(i);
    return out;
}

export function decodeSecondaryEntry(sec: Uint8Array, index: number, isEbb = false): SecondaryEntry {
    const o = index * SECONDARY_ENTRY_SIZE;
    if (o + SECONDARY_ENTRY_SIZE > sec.length) throw new RangeError(`secondary entry ${index} past end (${sec.length} bytes)`);
    const dv = new DataView(sec.buffer, sec.byteOffset + o, SECONDARY_ENTRY_SIZE);
    return {
        blockOffset: Number(dv.getBigUint64(0, false)),
        headerOffset: dv.getUint16(8, false),
        headerSize: dv.getUint16(10, false),
        crc: dv.getUint32(12, false),
        headerHash: sec.slice(o + 16, o + 48),
        slotOrEbb: Number(dv.getBigUint64(48, false)),
        isEbb,
    };
}

/** The last block of a complete chunk, from its two index files (checked for consistency). */
export function lastBlockOfChunk(primary: Uint8Array, secondary: Uint8Array): { entry: SecondaryEntry; blocks: number } {
    const offsets = decodePrimary(primary);
    const filled = filledRelativeSlots(offsets);
    if (secondary.length % SECONDARY_ENTRY_SIZE !== 0) throw new Error(`secondary index size ${secondary.length} is not a multiple of ${SECONDARY_ENTRY_SIZE}`);
    const blocks = secondary.length / SECONDARY_ENTRY_SIZE;
    if (blocks === 0) throw new Error("chunk holds no blocks");
    if (filled.length !== blocks) throw new Error(`primary index has ${filled.length} filled slots, secondary ${blocks} entries`);
    if (offsets[offsets.length - 1] !== secondary.length) throw new Error("primary index end marker does not match the secondary size");
    // Relative slot 0 is the EBB slot.
    return { entry: decodeSecondaryEntry(secondary, blocks - 1, filled[blocks - 1] === 0), blocks };
}
