/**
 * Certify a locally produced cardano-database snapshot against Mithril: pick the aggregator's
 * snapshot for an immutable file number the local directory has complete, verify its certificate
 * chain to the genesis key (keeping every certificate so the store can serve the chain), then let
 * the producer check that the local Merkle root is the one that certificate signed. A node that is
 * not a Mithril signer can so republish exactly what Mithril certified, from its own chunks.
 */

import { AggregatorClient, cachingRetriever, mithrilNetworkConfig, type FetchLike } from "../aggregator";
import type { Certificate } from "../certificate";
import type { CertificateStore } from "../certStore";
import { decodeGenesisVerificationKey, verifyCertificateChain, type ChainVerifyResult } from "../verifier";
import { lastCompletedImmutable, listImmutableFiles } from "./digests";
import { produceCardanoDatabaseSnapshot, type ProduceResult } from "./produce";
import { listCardanoDatabaseSnapshots, resolveVerificationKey, type CardanoDatabaseSnapshotListItem } from "./snapshot";
import type { ArtifactStore } from "./store";

export type CertifiedTarget = {
    item: CardanoDatabaseSnapshotListItem;
    certificate: Certificate;
    /** Every certificate retrieved while verifying, from `certificate` back to genesis. */
    chain: Certificate[];
    verify: ChainVerifyResult;
};

export type FindCertifiedTargetOptions = {
    client: AggregatorClient;
    /** Genesis verification key (hex of the JSON byte array). */
    genesisVkey: string;
    /** Newest immutable file number complete locally. */
    lastCompleted: number;
    /** Exactly this immutable file number instead of the newest that fits. */
    immutable?: number;
    /** Certificate cache read before downloading (written once the chain verified). */
    certificateStore?: CertificateStore;
    log?: (m: string) => void;
};

/** The newest aggregator snapshot whose beacon is <= `lastCompleted` (or exactly `immutable`), with its verified chain. */
export async function findCertifiedTarget(o: FindCertifiedTargetOptions): Promise<CertifiedTarget> {
    const list = await listCardanoDatabaseSnapshots(o.client);
    const fits = list.filter((s) => (o.immutable != null ? s.beacon.immutable_file_number === o.immutable : s.beacon.immutable_file_number <= o.lastCompleted));
    fits.sort((a, b) => b.beacon.immutable_file_number - a.beacon.immutable_file_number);
    const item = fits[0];
    if (!item) {
        const range = list.length ? `${list[list.length - 1]!.beacon.immutable_file_number}..${list[0]!.beacon.immutable_file_number}` : "none";
        throw new Error(`no certified snapshot for ${o.immutable != null ? `immutable ${o.immutable}` : `immutable <= ${o.lastCompleted}`} (aggregator lists ${range})`);
    }
    const base = cachingRetriever(o.client, o.certificateStore);
    const chain: Certificate[] = [];
    const retrieve = async (h: string) => {
        const c = await base(h);
        chain.push(c);
        return c;
    };
    const certificate = await retrieve(item.certificate_hash);
    if (certificate.hash !== item.certificate_hash) throw new Error(`certificate ${item.certificate_hash}: aggregator returned ${certificate.hash}`);
    o.log?.(`verifying certificate chain of ${certificate.hash} (snapshot e${item.beacon.epoch}/i${item.beacon.immutable_file_number})`);
    let n = 0;
    const verify = await verifyCertificateChain(certificate, {
        genesisVkey: decodeGenesisVerificationKey(o.genesisVkey),
        retrieve,
        onHop: () => {
            if (++n % 100 === 0) o.log?.(`  ${n} certificates verified`);
        },
    });
    await base.persist();
    o.log?.(`certificate chain OK: ${verify.hops.length} certificates to genesis ${verify.genesisHash}`);
    return { item, certificate, chain, verify };
}

export type ProduceCertifiedOptions = {
    immutableDir: string;
    store: ArtifactStore;
    /** Network name (snapshot records, digests file name); preview, preprod and mainnet also give the default aggregator and genesis key. */
    network: string;
    /** Aggregator URL (default: the network's), or a client of your own (custom fetch). */
    aggregator?: string | AggregatorClient;
    fetch?: FetchLike;
    /** Genesis verification key: the key itself, a file path or a URL (default: the network's compiled-in key). */
    genesisVkey?: string;
    immutable?: number;
    archiveRange?: { from: number; to: number };
    certificateStore?: CertificateStore;
    log?: (m: string) => void;
};

/** Produce the snapshot Mithril certified for the newest immutable file number complete in `immutableDir`. */
export async function produceCertifiedSnapshot(o: ProduceCertifiedOptions): Promise<ProduceResult & { target: CertifiedTarget }> {
    // The network's defaults only when needed: a devnet passes its own aggregator and key.
    const client = o.aggregator instanceof AggregatorClient ? o.aggregator : new AggregatorClient(o.aggregator ?? mithrilNetworkConfig(o.network).aggregator, o.fetch);
    const vkey = o.genesisVkey ? await resolveVerificationKey(o.genesisVkey, o.fetch) : mithrilNetworkConfig(o.network).genesisVkey;
    const files = listImmutableFiles(o.immutableDir);
    const lastCompleted = lastCompletedImmutable(files);
    if (lastCompleted == null) throw new Error(`${o.immutableDir}: no complete immutable trio`);
    o.log?.(`${o.immutableDir}: immutable files complete up to ${lastCompleted}`);
    const target = await findCertifiedTarget({ client, genesisVkey: vkey, lastCompleted, immutable: o.immutable, certificateStore: o.certificateStore, log: o.log });
    const r = await produceCardanoDatabaseSnapshot({
        immutableDir: o.immutableDir,
        store: o.store,
        network: o.network,
        beacon: { epoch: target.item.beacon.epoch, immutableFileNumber: target.item.beacon.immutable_file_number },
        certificate: target.certificate,
        certificateChain: target.chain,
        archiveRange: o.archiveRange,
        cardanoNodeVersion: target.item.cardano_node_version,
        log: o.log,
    });
    if (r.merkleRoot !== target.item.merkle_root) throw new Error(`local merkle root ${r.merkleRoot} differs from the aggregator's ${target.item.merkle_root}`);
    if (r.snapshot.hash !== target.item.hash) throw new Error(`local snapshot hash ${r.snapshot.hash} differs from the aggregator's ${target.item.hash}`);
    return { ...r, target };
}
