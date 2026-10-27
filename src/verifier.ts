/**
 * Mithril certificate chain verification, ported from mithril-common `MithrilCertificateVerifier`
 * (concatenation proofs; the SNARK variants are not supported).
 *
 * Standard certificate: not chaining to itself, hash matches content, signed_message equals the
 * protocol message hash, the STM multi-signature verifies against the certificate's AVK and
 * protocol parameters, current_epoch part equals the epoch; then against its previous
 * certificate: no epoch gap, previous_hash matches, AVK chaining (same epoch: same AVK; new
 * epoch: the previous certificate's next_aggregate_verification_key) and protocol parameters
 * chaining (same epoch: equal; new epoch: hash equals the previous next_protocol_parameters).
 *
 * Genesis certificate: hash matches content, signed_message equals the protocol message hash,
 * Ed25519 (strict) signature of the signed_message UTF-8 bytes under the genesis key, and
 * current_epoch part equals the epoch.
 */

import { utf8 } from "./bytes";
import {
    CertificateError,
    computeCertificateHash,
    decodeKeyBytes,
    decodeNextAvk,
    phiFFixed,
    protocolMessageHash,
    protocolParametersHash,
    type Certificate,
} from "./certificate";
import { ed25519VerifyStrict } from "./ed25519";
import { avkEquals, verifyConcatenationProof, type StmVerifyStats } from "./stm";

const err = (code: string, message: string): never => {
    throw new CertificateError(code, message);
};

/** Decode a Mithril genesis verification key (JSON hex of 32 bytes, or bytes hex). */
export function decodeGenesisVerificationKey(raw: string): Uint8Array {
    return decodeKeyBytes(raw.trim(), 32, "genesis verification key");
}

function verifyHashMatchesContent(c: Certificate): void {
    if (computeCertificateHash(c) !== c.hash) err("CertificateHashUnmatch", `certificate ${c.hash} content hash differs`);
}

function verifySignedMessage(c: Certificate): void {
    if (protocolMessageHash(c.protocolMessage) !== c.signedMessage) err("CertificateProtocolMessageUnmatch", `certificate ${c.hash}`);
}

function verifyEpochMatchesProtocolMessage(c: Certificate): void {
    if (c.protocolMessage.get("current_epoch") !== c.epoch.toString()) err("CertificateEpochUnmatch", `certificate ${c.hash}`);
}

export function verifyGenesisCertificate(c: Certificate, genesisVkey: Uint8Array): void {
    if (c.signature.kind !== "genesis") return err("InvalidGenesisCertificateProvided", c.hash);
    verifyHashMatchesContent(c);
    verifySignedMessage(c);
    if (!ed25519VerifyStrict(c.signature.signature, utf8(c.signedMessage), genesisVkey)) err("CertificateGenesis", `genesis signature of ${c.hash} does not verify`);
    verifyEpochMatchesProtocolMessage(c);
}

/** Integrity checks of a standard certificate on its own (no predecessor). */
export function verifyStandardCertificateIntegrity(c: Certificate): StmVerifyStats {
    if (c.signature.kind !== "multi") return err("InvalidStandardCertificateProvided", c.hash);
    if (c.hash === c.previousHash) err("CertificateChainInfiniteLoop", c.hash);
    verifyHashMatchesContent(c);
    verifySignedMessage(c);
    let stats: StmVerifyStats;
    try {
        stats = verifyConcatenationProof(utf8(c.signedMessage), c.avk, c.metadata.parameters, c.signature.proof);
    } catch (e) {
        return err("VerifyMultiSignature", `certificate ${c.hash}: ${(e as Error).message}`);
    }
    verifyEpochMatchesProtocolMessage(c);
    return stats;
}

export function verifyStandardCertificate(c: Certificate, previous: Certificate): StmVerifyStats {
    const stats = verifyStandardCertificateIntegrity(c);
    const gap = c.epoch > previous.epoch ? c.epoch - previous.epoch : previous.epoch - c.epoch;
    if (gap > 1n) err("CertificateChainMissingEpoch", `${c.hash} epoch ${c.epoch}, previous ${previous.epoch}`);
    if (previous.hash !== c.previousHash) err("CertificateChainPreviousHashUnmatch", c.hash);
    const sameEpoch = previous.epoch === c.epoch;
    if (sameEpoch) {
        if (!avkEquals(previous.avk, c.avk)) err("CertificateChainAVKUnmatch", c.hash);
        const a = previous.metadata.parameters;
        const b = c.metadata.parameters;
        if (a.k !== b.k || a.m !== b.m || phiFFixed(a.phiF) !== phiFFixed(b.phiF)) err("CertificateChainProtocolParametersUnmatch", c.hash);
    } else {
        const next = decodeNextAvk(previous.protocolMessage);
        if (!next || !avkEquals(next, c.avk)) err("CertificateChainAVKUnmatch", c.hash);
        const nextParams = previous.protocolMessage.get("next_protocol_parameters");
        if (nextParams === undefined || nextParams !== protocolParametersHash(c.metadata.parameters)) err("CertificateChainProtocolParametersUnmatch", c.hash);
    }
    return stats;
}

export type CertificateRetriever = (hash: string) => Promise<Certificate>;

export type ChainHop = { hash: string; epoch: bigint; kind: "genesis" | "standard"; signatures: number; indices: number; ms: number };

export type ChainVerifyResult = {
    /** From the given certificate back to the genesis certificate (or to a cached hop). */
    hops: ChainHop[];
    genesisHash: string | null;
    /** True when the walk stopped at a certificate already verified earlier (see `verifiedCache`). */
    stoppedAtCache: boolean;
    /** Wall time of the walk, retrieval included. */
    ms: number;
    /** Time spent verifying (retrieval excluded). */
    verifyMs: number;
};

export type ChainVerifyOptions = {
    genesisVkey: Uint8Array;
    retrieve: CertificateRetriever;
    /** Hashes known to chain to genesis (verified before). The walk stops when it reaches one. */
    verifiedCache?: Set<string>;
    /** Safety bound on the number of hops (Mithril has none; a few per epoch in practice). */
    maxHops?: number;
    onHop?: (hop: ChainHop) => void;
    /** Called between certificates so a browser page or worker can keep its event loop responsive. */
    yieldEvery?: number;
};

/**
 * CertificateVerifier::verify_certificate_chain: verify `cert`, then each previous certificate,
 * until the genesis certificate is verified.
 */
export async function verifyCertificateChain(cert: Certificate, opts: ChainVerifyOptions): Promise<ChainVerifyResult> {
    const t0 = performance.now();
    let verifyMs = 0;
    const hops: ChainHop[] = [];
    const seen = new Set<string>();
    const maxHops = opts.maxHops ?? 100_000;
    const yieldEvery = opts.yieldEvery ?? 0;
    let c = cert;
    let prefetch: { hash: string; cert: Promise<Certificate> } | null = null;
    for (;;) {
        if (seen.has(c.hash)) err("CertificateChainInfiniteLoop", c.hash);
        seen.add(c.hash);
        if (hops.length >= maxHops) err("CertificateChainTooLong", `more than ${maxHops} certificates`);
        if (c.signature.kind === "genesis") {
            const v0 = performance.now();
            verifyGenesisCertificate(c, opts.genesisVkey);
            const ms = performance.now() - v0;
            verifyMs += ms;
            const hop: ChainHop = { hash: c.hash, epoch: c.epoch, kind: "genesis", signatures: 0, indices: 0, ms };
            hops.push(hop);
            opts.onHop?.(hop);
            return { hops, genesisHash: c.hash, stoppedAtCache: false, ms: performance.now() - t0, verifyMs };
        }
        if (opts.verifiedCache?.has(c.hash) && hops.length > 0) {
            return { hops, genesisHash: null, stoppedAtCache: true, ms: performance.now() - t0, verifyMs };
        }
        const previous: Certificate = await (prefetch && prefetch.hash === c.previousHash ? prefetch.cert : opts.retrieve(c.previousHash));
        prefetch = null;
        if (previous.hash !== c.previousHash) err("CertificateChainPreviousHashUnmatch", `asked ${c.previousHash}, got ${previous.hash}`);
        // Download the next certificate while this one is verified (the walk is otherwise network bound).
        if (previous.signature.kind === "multi" && !opts.verifiedCache?.has(previous.hash)) {
            const cert = opts.retrieve(previous.previousHash);
            cert.catch(() => {}); // surfaced when awaited next round; never an unhandled rejection
            prefetch = { hash: previous.previousHash, cert };
        }
        const v0 = performance.now();
        const stats = verifyStandardCertificate(c, previous);
        const ms = performance.now() - v0;
        verifyMs += ms;
        const hop: ChainHop = { hash: c.hash, epoch: c.epoch, kind: "standard", signatures: stats.signatures, indices: stats.indices, ms };
        hops.push(hop);
        opts.onHop?.(hop);
        if (yieldEvery > 0 && hops.length % yieldEvery === 0) await new Promise((r) => setTimeout(r, 0));
        c = previous;
    }
}
