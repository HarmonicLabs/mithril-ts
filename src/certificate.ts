/**
 * Mithril certificate model and hashing, ported from mithril-common
 * (`CertificateMessage` -> `Certificate`, `Certificate::try_compute_hash`,
 * `ProtocolMessage::compute_hash`, `ProtocolParameters::compute_hash`).
 *
 * Certificates are parsed from the aggregator's JSON without losing u64 precision. Unknown
 * protocol message parts, a non-legacy hash scheme and SNARK-only fields are rejected, as a
 * non-SNARK mithril-client does.
 */

import { bytesToHex, hexToBytes, i64be, u64be } from "./bytes";
import { sha256Hasher, type Hasher } from "./hash";
import { asByteArray, asU64, decodeJsonHex, encodeJsonHex, isObject, parseJsonLossless } from "./json";
import {
    aggregateVerificationKeyJson,
    concatenationProofJson,
    parseAggregateVerificationKey,
    parseAggregateVerificationKeyJson,
    parseConcatenationProof,
    type AggregateVerificationKey,
    type ConcatenationProof,
    type StmParameters,
} from "./stm";

/** ProtocolMessagePartKey in enum declaration order (BTreeMap order, used by compute_hash). */
export const PROTOCOL_MESSAGE_PART_KEYS = [
    "snapshot_digest",
    "cardano_transactions_merkle_root",
    "cardano_blocks_transactions_merkle_root",
    "next_aggregate_verification_key",
    "next_protocol_parameters",
    "current_epoch",
    "latest_block_number",
    "cardano_blocks_transactions_block_number_offset",
    "cardano_stake_distribution_epoch",
    "cardano_stake_distribution_merkle_root",
    "cardano_database_merkle_root",
    "next_aggregate_verification_key_snark",
] as const;
export type ProtocolMessagePartKey = (typeof PROTOCOL_MESSAGE_PART_KEYS)[number];
export type ProtocolMessage = Map<ProtocolMessagePartKey, string>;

export type SignedEntityType =
    | { type: "MithrilStakeDistribution"; epoch: bigint }
    | { type: "CardanoStakeDistribution"; epoch: bigint }
    | { type: "CardanoTransactions"; epoch: bigint; blockNumber: bigint }
    | { type: "CardanoBlocksTransactions"; epoch: bigint; blockNumber: bigint; offset: bigint }
    | { type: "CardanoDatabase"; epoch: bigint; immutableFileNumber: bigint };

export type CertificateMetadata = {
    network: string;
    protocolVersion: string;
    parameters: StmParameters;
    initiatedAt: string;
    sealedAt: string;
    signers: { partyId: string; stake: bigint }[];
};

export type Certificate = {
    hash: string;
    previousHash: string;
    epoch: bigint;
    metadata: CertificateMetadata;
    protocolMessage: ProtocolMessage;
    signedMessage: string;
    avk: AggregateVerificationKey;
    signature:
        | { kind: "genesis"; signature: Uint8Array }
        | { kind: "multi"; signedEntityType: SignedEntityType; proof: ConcatenationProof };
    /** The JSON object as received (for storage and serving). */
    raw: Record<string, unknown>;
};

export class CertificateError extends Error {
    constructor(readonly code: string, message: string) {
        super(`${code}: ${message}`);
        this.name = "CertificateError";
    }
}

const bad = (message: string): never => {
    throw new CertificateError("CertificateDecode", message);
};

function str(v: unknown, label: string): string {
    if (typeof v !== "string") bad(`${label}: not a string`);
    return v as string;
}

/** Field decoders throw plain Errors; surface them as CertificateDecode. */
function decode<T>(f: () => T): T {
    try {
        return f();
    } catch (e) {
        if (e instanceof CertificateError) throw e;
        throw new CertificateError("CertificateDecode", (e as Error).message);
    }
}

function parseSignedEntityType(v: unknown): SignedEntityType {
    if (!isObject(v)) return bad("signed_entity_type: not an object");
    const keys = Object.keys(v);
    if (keys.length !== 1) bad("signed_entity_type: expected exactly one variant");
    const k = keys[0]!;
    const b = v[k];
    const tuple = (n: number): bigint[] => {
        if (!Array.isArray(b) || b.length !== n) bad(`signed_entity_type.${k}: expected ${n} values`);
        return (b as unknown[]).map((x, i) => asU64(x, `signed_entity_type.${k}[${i}]`));
    };
    switch (k) {
        case "MithrilStakeDistribution":
        case "CardanoStakeDistribution":
            return { type: k, epoch: asU64(b, `signed_entity_type.${k}`) };
        case "CardanoTransactions": {
            const [epoch, blockNumber] = tuple(2) as [bigint, bigint];
            return { type: k, epoch, blockNumber };
        }
        case "CardanoBlocksTransactions": {
            const [epoch, blockNumber, offset] = tuple(3) as [bigint, bigint, bigint];
            return { type: k, epoch, blockNumber, offset };
        }
        case "CardanoDatabase": {
            if (!isObject(b)) return bad("signed_entity_type.CardanoDatabase: not an object");
            return { type: k, epoch: asU64(b.epoch, "CardanoDatabase.epoch"), immutableFileNumber: asU64(b.immutable_file_number, "CardanoDatabase.immutable_file_number") };
        }
        default:
            return bad(`signed_entity_type: unknown variant ${k}`);
    }
}

function parseProtocolMessage(v: unknown): ProtocolMessage {
    if (!isObject(v) || !isObject(v.message_parts)) return bad("protocol_message.message_parts missing");
    const scheme = v.hash_scheme;
    if (scheme !== undefined && scheme !== "legacy") bad(`protocol_message.hash_scheme ${String(scheme)} is not supported`);
    const out: ProtocolMessage = new Map();
    for (const [k, val] of Object.entries(v.message_parts as Record<string, unknown>)) {
        if (!(PROTOCOL_MESSAGE_PART_KEYS as readonly string[]).includes(k)) bad(`protocol_message: unknown part ${k}`);
        out.set(k as ProtocolMessagePartKey, str(val, `protocol_message.${k}`));
    }
    return out;
}

/** Ed25519 signature or key: JSON hex of a byte array, or plain bytes hex (ProtocolKey decoding order). */
export function decodeKeyBytes(hex: string, len: number, label: string): Uint8Array {
    const s = hex.trim();
    try {
        const doc = decodeJsonHex(s);
        if (Array.isArray(doc)) return asByteArray(doc, len, label);
    } catch {
        /* not JSON hex: try plain bytes hex */
    }
    let b: Uint8Array;
    try {
        b = hexToBytes(s);
    } catch {
        return bad(`${label}: not hex`);
    }
    if (b.length !== len) bad(`${label}: ${b.length} bytes, want ${len}`);
    return b;
}

/** Parse an aggregator certificate (JSON text or an object parsed without precision loss). */
export function parseCertificate(input: string | Record<string, unknown>): Certificate {
    const c = typeof input === "string" ? decode(() => parseJsonLossless(input)) : input;
    if (!isObject(c)) return bad("certificate: not an object");
    for (const f of ["aggregate_verification_key_snark", "ancillary_prover_data", "ancillary_verifier_data", "genesis_schnorr_signature"]) {
        if (c[f] != null && c[f] !== "") bad(`certificate field ${f} (SNARK) is not supported`);
    }
    return decode(() => {
        const md = c.metadata;
        if (!isObject(md) || !isObject(md.parameters)) return bad("metadata.parameters missing");
        const p = md.parameters;
        if (typeof p.phi_f !== "number") bad("metadata.parameters.phi_f: not a number");
        const signers = md.signers ?? [];
        if (!Array.isArray(signers)) bad("metadata.signers: not an array");
        const metadata: CertificateMetadata = {
            network: str(md.network, "metadata.network"),
            protocolVersion: str(md.version, "metadata.version"),
            parameters: { k: asU64(p.k, "parameters.k"), m: asU64(p.m, "parameters.m"), phiF: p.phi_f as number },
            initiatedAt: str(md.initiated_at, "metadata.initiated_at"),
            sealedAt: str(md.sealed_at, "metadata.sealed_at"),
            signers: (signers as unknown[]).map((s, i) => {
                if (!isObject(s)) return bad(`metadata.signers[${i}]: not an object`);
                return { partyId: str(s.party_id, `signers[${i}].party_id`), stake: asU64(s.stake, `signers[${i}].stake`) };
            }),
        };
        const genesisSig = typeof c.genesis_signature === "string" ? c.genesis_signature : "";
        const multiSig = typeof c.multi_signature === "string" ? c.multi_signature : "";
        const signature: Certificate["signature"] =
            genesisSig.length > 0
                ? { kind: "genesis", signature: decodeKeyBytes(genesisSig, 64, "genesis_signature") }
                : { kind: "multi", signedEntityType: parseSignedEntityType(c.signed_entity_type), proof: parseConcatenationProof(multiSig) };
        return {
            hash: str(c.hash, "hash"),
            previousHash: str(c.previous_hash, "previous_hash"),
            epoch: asU64(c.epoch, "epoch"),
            metadata,
            protocolMessage: parseProtocolMessage(c.protocol_message),
            signedMessage: str(c.signed_message, "signed_message"),
            avk: parseAggregateVerificationKey(str(c.aggregate_verification_key, "aggregate_verification_key")),
            signature,
            raw: c,
        };
    });
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

/** fixed::U8F24::from_num(f64): round to nearest, ties to even, as u32. */
export function phiFFixed(phiF: number): number {
    const x = phiF * 2 ** 24; // exact: scaling by a power of two
    const fl = Math.floor(x);
    const diff = x - fl;
    const r = diff > 0.5 ? fl + 1 : diff < 0.5 ? fl : fl % 2 === 0 ? fl : fl + 1;
    if (r < 0 || r > 0xffffffff) throw new CertificateError("CertificateDecode", `phi_f ${phiF} does not fit U8F24`);
    return r >>> 0;
}

export function protocolParametersHash(p: StmParameters): string {
    const phi = new Uint8Array(4);
    new DataView(phi.buffer).setUint32(0, phiFFixed(p.phiF), false);
    return sha256Hasher().update(u64be(p.k)).update(u64be(p.m)).update(phi).hex();
}

export function protocolMessageHash(pm: ProtocolMessage): string {
    const h = sha256Hasher();
    for (const k of PROTOCOL_MESSAGE_PART_KEYS) {
        const v = pm.get(k);
        if (v !== undefined) h.update(k).update(v);
    }
    return h.hex();
}

/** chrono `DateTime<Utc>::timestamp_nanos_opt` of an RFC 3339 timestamp. */
export function rfc3339Nanos(s: string): bigint {
    const m = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|z|[+-]\d{2}:\d{2})$/.exec(s);
    if (!m) throw new CertificateError("CertificateDecode", `bad RFC 3339 timestamp ${s}`);
    const [, Y, Mo, D, H, Mi, S, frac = "", tz] = m;
    let ms = Date.UTC(+Y!, +Mo! - 1, +D!, +H!, +Mi!, +S!);
    if (tz !== "Z" && tz !== "z") {
        const sign = tz![0] === "-" ? -1 : 1;
        ms -= sign * (+tz!.slice(1, 3) * 60 + +tz!.slice(4, 6)) * 60_000;
    }
    return BigInt(ms) * 1_000_000n + BigInt((frac + "000000000").slice(0, 9));
}

export function metadataHash(md: CertificateMetadata): string {
    const h = sha256Hasher()
        .update(md.network)
        .update(md.protocolVersion)
        .update(protocolParametersHash(md.parameters))
        .update(i64be(rfc3339Nanos(md.initiatedAt)))
        .update(i64be(rfc3339Nanos(md.sealedAt)));
    for (const s of md.signers) h.update(sha256Hasher().update(s.partyId).update(u64be(s.stake)).hex());
    return h.hex();
}

function feedSignedEntityType(h: Hasher, t: SignedEntityType): void {
    if (t.type === "CardanoBlocksTransactions") h.update(new Uint8Array([0, 5])); // SignedEntityTypeId (u16 BE)
    switch (t.type) {
        case "MithrilStakeDistribution":
        case "CardanoStakeDistribution":
            h.update(u64be(t.epoch));
            break;
        case "CardanoDatabase":
            h.update(u64be(t.epoch)).update(u64be(t.immutableFileNumber));
            break;
        case "CardanoTransactions":
            h.update(u64be(t.epoch)).update(u64be(t.blockNumber));
            break;
        case "CardanoBlocksTransactions":
            h.update(u64be(t.epoch)).update(u64be(t.blockNumber)).update(u64be(t.offset));
            break;
    }
}

/** Certificate::try_compute_hash. Keys and signatures are re-encoded canonically, as Rust does. */
export function computeCertificateHash(c: Certificate): string {
    const h = sha256Hasher()
        .update(c.previousHash)
        .update(u64be(c.epoch))
        .update(metadataHash(c.metadata))
        .update(protocolMessageHash(c.protocolMessage))
        .update(c.signedMessage)
        .update(encodeJsonHex(aggregateVerificationKeyJson(c.avk)));
    if (c.signature.kind === "multi") {
        feedSignedEntityType(h, c.signature.signedEntityType);
        h.update(encodeJsonHex(concatenationProofJson(c.signature.proof)));
    } else {
        h.update(bytesToHex(c.signature.signature));
    }
    return h.hex();
}

/** Decode the `next_aggregate_verification_key` part (JSON hex AVK), or null. */
export function decodeNextAvk(pm: ProtocolMessage): AggregateVerificationKey | null {
    const v = pm.get("next_aggregate_verification_key");
    if (v === undefined) return null;
    try {
        return parseAggregateVerificationKeyJson(decodeJsonHex(v));
    } catch {
        return null;
    }
}

/**
 * MessageBuilder::compute_cardano_database_message + Certificate::match_message: the certificate's
 * protocol message with `cardano_database_merkle_root` set to `merkleRootHex` must hash to the
 * certificate's signed message. Only meaningful on a certificate whose chain verified.
 */
export function cardanoDatabaseMessageMatches(c: Certificate, merkleRootHex: string): boolean {
    const root = merkleRootHex.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(root)) return false;
    const pm: ProtocolMessage = new Map(c.protocolMessage);
    pm.set("cardano_database_merkle_root", root);
    return protocolMessageHash(pm) === c.signedMessage;
}
