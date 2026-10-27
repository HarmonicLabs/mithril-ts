/**
 * Certified pool stake: the CardanoStakeDistribution artifact, checked against its Mithril certificate and the
 * certificate chain checked back to genesis, so the leader check no longer takes the stake from the peer.
 *
 * - Leaves of the Merkle tree are the UTF-8 bytes of `pool_bech32 ‖ stake_decimal` (no separator, not hashed), in
 *   bytewise order of the pool id; the root is the MKTree root (mkTree.ts). The certificate's protocol message with
 *   `cardano_stake_distribution_epoch` and `cardano_stake_distribution_merkle_root` set must hash to its signed
 *   message (mithril-client message.rs).
 * - Artifact epoch E is the snapshot taken at the end of E: it is the leader-election stake of epoch E + 2
 *   (mithril-common epoch.rs, CARDANO_STAKE_DISTRIBUTION_SNAPSHOT_OFFSET; checked on preview against Koios and a
 *   Gerolamo node). So the stake of epoch N is artifact N - 2, and artifact N - 1 is certified one epoch early.
 */
import { decodeBech32 } from "./hl";
import { AggregatorClient, cachingRetriever, mithrilNetworkConfig, type FetchLike } from "./aggregator";
import { bytesToHex, utf8 } from "./bytes";
import { CertificateError, protocolMessageHash, type Certificate, type ProtocolMessage } from "./certificate";
import type { CertificateStore } from "./certStore";
import { OpfsCertificateStore } from "./certStore";
import { isObject, parseJsonLossless } from "./json";
import { mkTreeRoot } from "./mkTree";
import { verifyChainCached } from "./chainCache";
import { decodeGenesisVerificationKey } from "./verifier";

/** Leader-election epoch N uses the stake distribution artifact of epoch N - 2. */
export const STAKE_SNAPSHOT_OFFSET = 2;

export interface StakeArtifact { epoch: number; hash: string; certificateHash: string; stake: Map<string, bigint> }

export interface CertifiedStake {
    /** The epoch whose leader election this stake is for (artifact epoch + 2). */
    leaderEpoch: number;
    artifactEpoch: number;
    certificateHash: string;
    merkleRoot: string;
    /** Stake per pool, keyed by the pool id in hex (28 bytes, blake2b-224 of the cold key). */
    pools: Map<string, bigint>;
    total: bigint;
    certificatesWalked: number;
    ms: number;
}

/** Parse the artifact JSON (lovelace values are u64: parsed without losing digits). */
export function parseStakeArtifact(text: string): StakeArtifact {
    const v = parseJsonLossless(text);
    if (!isObject(v) || !isObject(v.stake_distribution)) throw new Error("stake distribution artifact: unexpected shape");
    const stake = new Map<string, bigint>();
    for (const [pool, amount] of Object.entries(v.stake_distribution)) stake.set(pool, BigInt(amount as any));
    return { epoch: Number(v.epoch), hash: String(v.hash), certificateHash: String(v.certificate_hash), stake };
}

/** The Merkle root a certificate signs for a stake distribution. */
export function stakeDistributionMerkleRoot(stake: Map<string, bigint>): string {
    const enc = new TextEncoder();
    const keys = [...stake.keys()].sort((a, b) => {
        const x = enc.encode(a), y = enc.encode(b);
        for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
        return x.length - y.length;
    });
    return bytesToHex(mkTreeRoot(keys.map((k) => utf8(`${k}${stake.get(k)!.toString()}`))));
}

/** Does the certificate sign this stake distribution of `epoch`? (Only meaningful on a certificate whose chain verified.) */
export function stakeMessageMatches(c: Certificate, epoch: number, merkleRoot: string): boolean {
    const set = c.signature.kind === "multi" ? c.signature.signedEntityType : null;
    if (!set || set.type !== "CardanoStakeDistribution" || set.epoch !== BigInt(epoch)) return false;
    const pm: ProtocolMessage = new Map(c.protocolMessage);
    pm.set("cardano_stake_distribution_epoch", String(epoch));
    pm.set("cardano_stake_distribution_merkle_root", merkleRoot);
    return protocolMessageHash(pm) === c.signedMessage;
}

/** `pool1…` to the pool id in hex. */
export function poolIdHex(bech32: string): string {
    const [hrp, bytes] = decodeBech32(bech32);
    if (hrp !== "pool" || bytes.length !== 28) throw new Error(`not a pool id: ${bech32}`);
    return bytesToHex(Uint8Array.from(bytes));
}

export interface MithrilStakeOptions {
    network: string;
    /** The leader-election epoch to certify the stake of. */
    epoch: number;
    aggregator?: string;
    genesisVkey?: string;
    store?: CertificateStore | null;
    fetch?: FetchLike;
    log?: (l: string) => void;
}

const hasOpfs = (): boolean => typeof (globalThis as { navigator?: { storage?: { getDirectory?: unknown } } }).navigator?.storage?.getDirectory === "function";

/** The Mithril-certified stake of a leader-election epoch (throws when the aggregator has none or a check fails). */
export async function mithrilStake(opts: MithrilStakeOptions): Promise<CertifiedStake> {
    const t0 = performance.now();
    const log = opts.log ?? (() => {});
    const cfg = mithrilNetworkConfig(opts.network);
    const base = (opts.aggregator ?? cfg.aggregator).replace(/\/$/, "");
    const fetchImpl: FetchLike = opts.fetch ?? ((u) => fetch(u));
    const artifactEpoch = opts.epoch - STAKE_SNAPSHOT_OFFSET;
    const r = await fetchImpl(`${base}/artifact/cardano-stake-distribution/epoch/${artifactEpoch}`);
    if (!r.ok) throw new Error(`Mithril: no stake distribution for epoch ${artifactEpoch} (HTTP ${r.status})`);
    const art = parseStakeArtifact(await r.text());
    if (art.epoch !== artifactEpoch) throw new Error(`Mithril: asked the stake distribution of epoch ${artifactEpoch}, got ${art.epoch}`);
    const root = stakeDistributionMerkleRoot(art.stake);

    const client = new AggregatorClient(base, opts.fetch);
    const store = opts.store === undefined ? (hasOpfs() ? OpfsCertificateStore.forNetwork(cfg.network) : undefined) : (opts.store ?? undefined);
    const retrieve = cachingRetriever(client, store);
    const cert = await retrieve(art.certificateHash);
    if (cert.hash !== art.certificateHash) throw new CertificateError("CertificateRetrieve", `asked ${art.certificateHash}, got ${cert.hash}`);
    if (!stakeMessageMatches(cert, artifactEpoch, root)) throw new Error(`Mithril: certificate ${cert.hash.slice(0, 16)}… does not sign this stake distribution (root ${root.slice(0, 16)}…)`);
    log(`Mithril: stake distribution of epoch ${artifactEpoch} (${art.stake.size} pools) matches certificate ${cert.hash.slice(0, 16)}…; verifying its chain`);
    const chain = await verifyChainCached(cert, decodeGenesisVerificationKey(opts.genesisVkey ?? cfg.genesisVkey), retrieve);
    await retrieve.persist();

    const pools = new Map<string, bigint>();
    let total = 0n;
    for (const [id, amount] of art.stake) { pools.set(poolIdHex(id), amount); total += amount; }
    const ms = performance.now() - t0;
    log(`Mithril: stake for epoch ${opts.epoch} certified: ${pools.size} pools, ${total} lovelace; ${chain.hops} certificate(s) checked${chain.cached ? " (the rest verified earlier)" : " to genesis"} in ${(ms / 1000).toFixed(1)} s`);
    return { leaderEpoch: opts.epoch, artifactEpoch, certificateHash: cert.hash, merkleRoot: root, pools, total, certificatesWalked: chain.hops, ms };
}
