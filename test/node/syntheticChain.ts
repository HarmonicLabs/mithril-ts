/**
 * Test support: a tiny but valid Mithril certificate chain signed with throwaway keys
 * (ported from Gerolamo's noble-based helper to @harmoniclabs/crypto).
 *
 * genesis certificate (Ed25519, test genesis key) -> one standard certificate signed by a single
 * STM signer (real BLS signature, real lottery with phi_f < 1, one-leaf AVK Merkle tree). The
 * standard certificate can sign any protocol message, e.g. a cardano-database Merkle root, so
 * tests can exercise the client and the artifact server end to end without the network.
 * Never use these keys for anything else.
 */

import { deriveEd25519PublicKey_sync, signEd25519_sync } from "@harmoniclabs/crypto/dist/ed25519.js";

import { hashToG1 } from "../../src/bls";
import { bytesToHex, utf8 } from "../../src/bytes";
import { computeCertificateHash, parseCertificate, protocolMessageHash, protocolParametersHash, type Certificate, type ProtocolMessage } from "../../src/certificate";
import { blake2b256 } from "../../src/hash";
import { BlsG2, bls12_381_G1_compress, bls12_381_G1_scalarMul, bls12_381_G2_compress, bls12_381_G2_scalarMul } from "../../src/hl";
import { encodeJsonHex, stringifyJsonLossless } from "../../src/json";
import { isLotteryWon } from "../../src/lottery";
import { aggregateVerificationKeyJson, concatenationProofJson, evaluateDenseMapping, registrationLeafBytes, type AggregateVerificationKey } from "../../src/stm";

export type SyntheticChain = {
    genesisVkeyHex: string; // JSON hex, as the published genesis.vkey files
    genesis: Certificate;
    standard: Certificate;
    /** Raw JSON text of each certificate, keyed by hash. */
    texts: Map<string, string>;
};

const BLS_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const SEED = (b: number) => new Uint8Array(32).fill(b);
const pm = (o: Record<string, string>) => new Map(Object.entries(o)) as ProtocolMessage;

export function buildSyntheticChain(opts: { network?: string; epoch?: number; signedEntityType: Record<string, unknown>; messageParts: Record<string, string> }): SyntheticChain {
    const network = opts.network ?? "testnet";
    const epoch = opts.epoch ?? 10;
    const params = { k: 5n, m: 100n, phiF: 0.65 };
    const paramsJson = { k: 5, m: 100, phi_f: 0.65 };

    // Signer: sk, vk = sk * G2, stake.
    const sk = (BigInt("0x" + bytesToHex(blake2b256(SEED(7)))) % (BLS_ORDER - 1n)) + 1n;
    const vk = bls12_381_G2_compress(bls12_381_G2_scalarMul(sk, BlsG2.BASE));
    const stake = 1_000_000_000n;
    const avk: AggregateVerificationKey = { root: blake2b256(registrationLeafBytes(vk, stake)), nrLeaves: 1, totalStake: stake };
    const avkHex = encodeJsonHex(aggregateVerificationKeyJson(avk));

    // Genesis key.
    const gsk = SEED(9);
    const gvk = deriveEd25519PublicKey_sync(gsk);
    const genesisVkeyHex = encodeJsonHex(`[${Array.from(gvk).join(",")}]`);

    const time = "2026-01-01T00:00:00.000000001Z";
    const nextParts = { next_aggregate_verification_key: avkHex, next_protocol_parameters: protocolParametersHash(params), current_epoch: String(epoch) };

    // Genesis certificate.
    const gSigned = protocolMessageHash(pm(nextParts));
    const genesisJson: Record<string, unknown> = {
        hash: "",
        previous_hash: "",
        epoch,
        signed_entity_type: { MithrilStakeDistribution: epoch },
        metadata: { network, version: "0.1.0", parameters: paramsJson, initiated_at: time, sealed_at: time, signers: [] },
        protocol_message: { message_parts: nextParts },
        signed_message: gSigned,
        aggregate_verification_key: avkHex,
        multi_signature: "",
        genesis_signature: bytesToHex(signEd25519_sync(utf8(gSigned), gsk).signature),
    };
    genesisJson.hash = computeCertificateHash(parseCertificate(genesisJson));
    const genesis = parseCertificate(genesisJson);

    // Standard certificate, same epoch: same AVK and parameters as the genesis certificate.
    const sPm = { ...nextParts, ...opts.messageParts };
    const sSigned = protocolMessageHash(pm(sPm));
    const msgp = new Uint8Array([...utf8(sSigned), ...avk.root]);
    const sigma = bls12_381_G1_compress(bls12_381_G1_scalarMul(sk, hashToG1(msgp)));
    const indexes: bigint[] = [];
    for (let i = 0n; i <= params.m && indexes.length < Number(params.k); i++) {
        if (isLotteryWon(params.phiF, evaluateDenseMapping(sigma, msgp, i), stake, stake)) indexes.push(i);
    }
    const proofJson = concatenationProofJson({ signatures: [{ sigma, indexes, signerIndex: 0n, vk, stake }], batchProof: { values: [], indices: [0] } });
    const standardJson: Record<string, unknown> = {
        hash: "",
        previous_hash: genesis.hash,
        epoch,
        signed_entity_type: opts.signedEntityType,
        metadata: { network, version: "0.1.0", parameters: paramsJson, initiated_at: time, sealed_at: time, signers: [{ party_id: "pool1synthetic", stake }] },
        protocol_message: { message_parts: sPm },
        signed_message: sSigned,
        aggregate_verification_key: avkHex,
        multi_signature: encodeJsonHex(proofJson),
        genesis_signature: "",
    };
    standardJson.hash = computeCertificateHash(parseCertificate(standardJson));
    const standard = parseCertificate(standardJson);

    const texts = new Map([
        [genesis.hash, stringifyJsonLossless(genesisJson)],
        [standard.hash, stringifyJsonLossless(standardJson)],
    ]);
    return { genesisVkeyHex, genesis, standard, texts };
}

/** An Ed25519 test key pair for ancillary manifests: the vkey in the published hex-of-JSON form, and a signer. */
export function testAncillaryKey(seedByte = 11): { vkeyHex: string; sign(msg: Uint8Array): string } {
    const sk = SEED(seedByte);
    const pk = deriveEd25519PublicKey_sync(sk);
    return { vkeyHex: encodeJsonHex(`[${Array.from(pk).join(",")}]`), sign: (msg) => bytesToHex(signEd25519_sync(msg, sk).signature) };
}
