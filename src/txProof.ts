/**
 * Mithril proofs that transactions are on the chain (CardanoTransactions, legacy `/proof/cardano-transaction`).
 * A relayed answer about a transaction can then be checked: the transaction is in a block of the certified range,
 * not something the peer made up.
 *
 * The aggregator returns, per group of transactions, the hex of a JSON MKMapProof<BlockRange>: a master
 * Merkle-mountain-range proof over block ranges of 15 blocks, each leaf Blake2s256(utf8("start-end") ‖ rangeRoot),
 * and per range a sub-proof over the UTF-8 bytes of the transactions' hex hashes. Merges are Blake2s256(l ‖ r);
 * MMR roots are computed as ckb-merkle-mountain-range 0.6.1 does (the version Mithril pins). The certificate's
 * protocol message with `cardano_transactions_merkle_root` (the master root) and `latest_block_number` set must hash
 * to its signed message (mithril-client message.rs), and its chain must reach genesis.
 */
import { AggregatorClient, cachingRetriever, mithrilNetworkConfig, type FetchLike } from "./aggregator";
import { blake2s256 } from "./blake2s";
import { bytesToHex, utf8 } from "./bytes";
import { CertificateError, protocolMessageHash, type Certificate, type ProtocolMessage } from "./certificate";
import { OpfsCertificateStore, type CertificateStore } from "./certStore";
import { verifyChainCached } from "./chainCache";
import { decodeGenesisVerificationKey } from "./verifier";

type Node = Uint8Array;
type NodeJson = { hash: number[] };
interface MkProofJson { inner_root: NodeJson; inner_leaves: [number, NodeJson][]; inner_proof_size: number; inner_proof_items: NodeJson[] }
interface MkMapProofJson { master_proof: MkProofJson; sub_proofs: [{ inner_range: { start: number; end: number } }, MkMapProofJson][] }

export interface TransactionsProofResponse {
    certificate_hash: string;
    certified_transactions: { transactions_hashes: string[]; proof: string }[];
    non_certified_transactions: string[];
    latest_block_number: number;
}

export interface TransactionsProof {
    certificateHash: string;
    merkleRoot: string;
    latestBlockNumber: number;
    /** Each certified transaction and the block range [start, end) it is in. */
    certified: Map<string, { start: number; end: number }>;
    /** Transactions the aggregator has not certified (unknown, or newer than its latest snapshot). */
    nonCertified: string[];
}

const node = (j: NodeJson): Node => Uint8Array.from(j.hash);
const eq = (a: Node, b: Node) => a.length === b.length && a.every((x, i) => x === b[i]);
const merge = (l: Node, r: Node) => blake2s256(l, r);

class CorruptedProof extends Error {}

// ---- ckb-merkle-mountain-range 0.6.1, MerkleProof::calculate_root ----
const ALL_ONES = (1n << 64n) - 1n;
const clz64 = (x: bigint) => (x === 0n ? 64 : 64 - x.toString(2).length);
function posHeight(pos: bigint): number {
    if (pos === 0n) return 0;
    let peak = ALL_ONES >> BigInt(clz64(pos));
    while (peak > 0n) { if (pos >= peak) pos -= peak; peak >>= 1n; }
    return Number(pos);
}
const siblingOffset = (h: number) => (2n << BigInt(h)) - 1n;
const parentOffset = (h: number) => 2n << BigInt(h);
function peaksOf(mmrSize: bigint): bigint[] {
    if (mmrSize === 0n) return [];
    let pos = mmrSize, peak = ALL_ONES >> BigInt(clz64(mmrSize)), sum = 0n;
    const out: bigint[] = [];
    while (peak > 0n) { if (pos >= peak) { pos -= peak; out.push(sum + peak - 1n); sum += peak; } peak >>= 1n; }
    return out;
}
function peakRoot(leaves: [bigint, Node][], peakPos: bigint, proof: { next(): Node | undefined }): Node {
    const q: [bigint, Node, number][] = leaves.map(([p, n]) => [p, n, 0]);
    while (q.length) {
        const [pos, item, h] = q.shift()!;
        if (pos === peakPos) { if (!q.length) return item; throw new CorruptedProof("queue not empty at the peak"); }
        const sibling = (want: bigint) => (q.length && q[0]![0] === want ? q.shift()![1] : proof.next() ?? (() => { throw new CorruptedProof("proof too short"); })());
        let parentPos: bigint, parent: Node;
        if (posHeight(pos + 1n) > h) { parentPos = pos + 1n; parent = merge(sibling(pos - siblingOffset(h)), item); } // right child
        else { parentPos = pos + parentOffset(h); parent = merge(item, sibling(pos + siblingOffset(h))); } // left child
        if (parentPos > peakPos) throw new CorruptedProof("parent beyond the peak");
        q.push([parentPos, parent, h + 1]);
    }
    throw new CorruptedProof("empty queue");
}
export function mmrRoot(leavesIn: [bigint, Node][], mmrSize: bigint, items: Node[]): Node {
    if (leavesIn.some(([p]) => posHeight(p) > 0)) throw new CorruptedProof("only leaf proofs are supported");
    let i = 0;
    const proof = { next: () => items[i++] };
    let peaks: Node[];
    if (mmrSize === 1n && leavesIn.length === 1 && leavesIn[0]![0] === 0n) peaks = [leavesIn[0]![1]];
    else {
        let leaves = [...leavesIn].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).filter((x, k, arr) => k === 0 || arr[k - 1]![0] !== x[0]);
        peaks = [];
        for (const peakPos of peaksOf(mmrSize)) {
            let n = 0;
            while (n < leaves.length && leaves[n]![0] <= peakPos) n++;
            const mine = leaves.slice(0, n);
            leaves = leaves.slice(n);
            if (mine.length === 1 && mine[0]![0] === peakPos) peaks.push(mine[0]![1]);
            else if (!mine.length) { const p = proof.next(); if (!p) break; peaks.push(p); }
            else peaks.push(peakRoot(mine, peakPos, proof));
        }
        if (leaves.length) throw new CorruptedProof("leaves beyond the last peak");
        const rhs = proof.next();
        if (rhs) peaks.push(rhs); // the right-hand peaks, already bagged
        if (proof.next()) throw new CorruptedProof("proof items left over");
    }
    while (peaks.length > 1) { const r = peaks.pop()!, l = peaks.pop()!; peaks.push(merge(r, l)); }
    if (!peaks.length) throw new CorruptedProof("no peaks");
    return peaks[0]!;
}

// ---- MKProof / MKMapProof<BlockRange> ----
function verifyMkProof(p: MkProofJson): void {
    const root = mmrRoot(p.inner_leaves.map(([pos, n]) => [BigInt(pos), node(n)]), BigInt(p.inner_proof_size), p.inner_proof_items.map(node));
    if (!eq(root, node(p.inner_root))) throw new CorruptedProof("Merkle proof does not reach its root");
}
function verifyMapProof(p: MkMapProofJson): void {
    for (const [, sp] of p.sub_proofs) verifyMapProof(sp);
    verifyMkProof(p.master_proof);
    for (const [k, sp] of p.sub_proofs) {
        const leaf = merge(utf8(`${k.inner_range.start}-${k.inner_range.end}`), node(sp.master_proof.inner_root));
        if (!p.master_proof.inner_leaves.some(([, n]) => eq(node(n), leaf))) throw new CorruptedProof(`master proof lacks block range ${k.inner_range.start}-${k.inner_range.end}`);
    }
}
/** The block range a transaction's leaf is under (null: not in this proof). */
function rangeOf(p: MkMapProofJson, leaf: Node): { start: number; end: number } | null {
    for (const [k, sp] of p.sub_proofs) {
        if (sp.master_proof.inner_leaves.some(([, n]) => eq(node(n), leaf))) return { ...k.inner_range };
        const deeper = rangeOf(sp, leaf);
        if (deeper) return deeper;
    }
    return null;
}

const hexToText = (hex: string) => new TextDecoder().decode(Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16)));

/** Check a proof response against its certificate (whose chain the caller verifies). Throws on any mismatch. */
export function verifyTransactionsProof(res: TransactionsProofResponse, cert: Certificate): TransactionsProof {
    if (cert.hash !== res.certificate_hash) throw new Error("the proof names another certificate");
    const set = cert.signature.kind === "multi" ? cert.signature.signedEntityType : null;
    if (!set || set.type !== "CardanoTransactions") throw new Error("the certificate does not certify transactions");
    let root: string | null = null;
    const certified = new Map<string, { start: number; end: number }>();
    for (const group of res.certified_transactions) {
        const p = JSON.parse(hexToText(group.proof)) as MkMapProofJson;
        verifyMapProof(p);
        const r = bytesToHex(node(p.master_proof.inner_root));
        if (root && root !== r) throw new CorruptedProof("proofs with different roots");
        root = r;
        for (const h of group.transactions_hashes) {
            const range = rangeOf(p, utf8(h));
            if (!range) throw new CorruptedProof(`the proof does not contain ${h}`);
            certified.set(h, range);
        }
    }
    if (!root) throw new Error("no certified transaction in the proof");
    const pm: ProtocolMessage = new Map(cert.protocolMessage);
    pm.set("cardano_transactions_merkle_root", root);
    pm.set("latest_block_number", String(res.latest_block_number));
    if (protocolMessageHash(pm) !== cert.signedMessage) throw new Error("the certificate does not sign this proof's root and block number");
    return { certificateHash: cert.hash, merkleRoot: root, latestBlockNumber: res.latest_block_number, certified, nonCertified: [...res.non_certified_transactions] };
}

export interface MithrilTxProofOptions {
    network: string;
    txHashes: string[];
    aggregator?: string;
    genesisVkey?: string;
    store?: CertificateStore | null;
    fetch?: FetchLike;
    log?: (l: string) => void;
}

const hasOpfs = (): boolean => typeof (globalThis as { navigator?: { storage?: { getDirectory?: unknown } } }).navigator?.storage?.getDirectory === "function";

/** Ask the aggregator to prove transactions are on the chain and check everything, the certificate chain included. */
export async function mithrilTxProof(opts: MithrilTxProofOptions): Promise<TransactionsProof> {
    const hashes = [...new Set(opts.txHashes.map((h) => h.toLowerCase()))];
    if (!hashes.length || hashes.length > 100 || hashes.some((h) => !/^[0-9a-f]{64}$/.test(h))) throw new Error("1 to 100 transaction hashes of 64 hex digits");
    const cfg = mithrilNetworkConfig(opts.network);
    const base = (opts.aggregator ?? cfg.aggregator).replace(/\/$/, "");
    const fetchImpl: FetchLike = opts.fetch ?? ((u) => fetch(u));
    const r = await fetchImpl(`${base}/proof/cardano-transaction?transaction_hashes=${hashes.join(",")}`);
    if (!r.ok) throw new Error(`Mithril: transaction proof HTTP ${r.status}`);
    const res = JSON.parse(await r.text()) as TransactionsProofResponse;
    if (!res.certified_transactions?.length) {
        return { certificateHash: res.certificate_hash, merkleRoot: "", latestBlockNumber: res.latest_block_number, certified: new Map(), nonCertified: res.non_certified_transactions ?? hashes };
    }
    const store = opts.store === undefined ? (hasOpfs() ? OpfsCertificateStore.forNetwork(cfg.network) : undefined) : (opts.store ?? undefined);
    const retrieve = cachingRetriever(new AggregatorClient(base, opts.fetch), store);
    const cert = await retrieve(res.certificate_hash);
    if (cert.hash !== res.certificate_hash) throw new CertificateError("CertificateRetrieve", `asked ${res.certificate_hash}, got ${cert.hash}`);
    const proof = verifyTransactionsProof(res, cert);
    const walk = await verifyChainCached(cert, decodeGenesisVerificationKey(opts.genesisVkey ?? cfg.genesisVkey), retrieve);
    await retrieve.persist();
    opts.log?.(`Mithril: ${proof.certified.size} transaction(s) proven by certificate ${cert.hash.slice(0, 16)}… (chain: ${walk.hops} certificate(s) checked${walk.cached ? ", the rest verified earlier" : ""})`);
    return proof;
}
