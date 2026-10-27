/**
 * Client side of a cardano-database v2 restore, as mithril-client does it
 * (`InternalArtifactProver::download_and_verify_digests` and `verify_cardano_database`):
 *
 * 1. Download the snapshot's digests list (from any of its locations: the zstd tar archive or the
 *    aggregator route), keep the files numbered <= the certified beacon, build the MKTree root and
 *    check that the (already chain-verified) certificate signed it.
 * 2. Hash the downloaded immutable files and compare each one with its certified digest.
 *
 * Stricter than mithril-client on one point: every immutable file found in the directory is
 * checked, not only the requested range, because the whole directory may become a node's block
 * store. A file the certified digests do not cover is reported as non-verifiable; the ancillary
 * archive's last trio is covered by its signed manifest instead (pass it as `extraDigests`).
 */

import type { Certificate } from "../certificate";
import { cardanoDatabaseMessageMatches } from "../certificate";
import { cardanoDatabaseMerkleRoot, certifiedDigests, type ImmutableFileDigest } from "../mkTree";
import { readTar } from "../tar";
import { immutableTrio, listImmutableFiles } from "./digests";
import { sha256File, zstdDecompress } from "./files";
import { locationUri, type CardanoDatabaseSnapshotMessage, type MithrilLocation } from "./snapshot";

/** What the digests download needs from `fetch` (the global `fetch` fits). */
export type DigestsFetch = (url: string) => Promise<{ ok: boolean; status: number; text(): Promise<string>; arrayBuffer(): Promise<ArrayBuffer> }>;

export type VerifiedDigests = {
    /** File name to lowercase hex digest, for files numbered 0..=beacon. */
    digests: Map<string, string>;
    merkleRoot: string;
    beacon: number;
    /** The location type the list came from. */
    source: string;
};

/** A digests list document (`[{ immutable_file_name, digest }]`), validated. */
export function parseDigestList(doc: unknown): ImmutableFileDigest[] {
    if (!Array.isArray(doc)) throw new Error("digests: not a list");
    return doc.map((d, i) => {
        if (!d || typeof d.immutable_file_name !== "string" || typeof d.digest !== "string") throw new Error(`digests[${i}]: bad entry`);
        return { immutable_file_name: d.immutable_file_name, digest: d.digest };
    });
}

/** Download a digests list from one location. */
export async function fetchDigestList(loc: MithrilLocation, fetchImpl: DigestsFetch = (u) => fetch(u)): Promise<ImmutableFileDigest[]> {
    const uri = locationUri(loc);
    if (!uri) throw new Error("digests location without uri");
    const res = await fetchImpl(uri);
    if (!res.ok) throw new Error(`GET ${uri}: HTTP ${res.status}`);
    if (loc.type === "aggregator") return parseDigestList(JSON.parse(await res.text()));
    const bytes = new Uint8Array(await res.arrayBuffer());
    const tar = loc.compression_algorithm === "zstandard" || /\.zst$/.test(uri) ? zstdDecompress(bytes) : bytes;
    const json = readTar(tar).find((e) => e.name.endsWith(".json"));
    if (!json) throw new Error(`${uri}: no .json digests file in the archive`);
    return parseDigestList(JSON.parse(new TextDecoder().decode(json.data)));
}

/** Step 1: digests whose Merkle root the certificate signed. Throws when no location gives one. */
export async function fetchVerifiedDigests(snapshot: CardanoDatabaseSnapshotMessage, certificate: Certificate, opts: { fetch?: DigestsFetch; log?: (m: string) => void } = {}): Promise<VerifiedDigests> {
    const set = certificate.signature.kind === "multi" ? certificate.signature.signedEntityType : null;
    if (!set || set.type !== "CardanoDatabase") throw new Error(`certificate ${certificate.hash} does not sign a cardano database snapshot`);
    const beacon = Number(set.immutableFileNumber);
    if (snapshot.beacon?.immutable_file_number !== beacon) throw new Error(`snapshot beacon ${snapshot.beacon?.immutable_file_number} differs from the certified beacon ${beacon}`);
    const errors: string[] = [];
    for (const loc of snapshot.digests?.locations ?? []) {
        try {
            const list = certifiedDigests(await fetchDigestList(loc, opts.fetch), beacon);
            const merkleRoot = cardanoDatabaseMerkleRoot(list, beacon);
            if (!cardanoDatabaseMessageMatches(certificate, merkleRoot)) throw new Error(`digests root ${merkleRoot} is not signed by certificate ${certificate.hash}`);
            opts.log?.(`digests verified: ${list.length} files, merkle root ${merkleRoot} signed by ${certificate.hash}`);
            return { digests: new Map(list.map((d) => [d.immutable_file_name, d.digest.toLowerCase()])), merkleRoot, beacon, source: loc.type };
        } catch (e) {
            errors.push(`${loc.type}: ${(e as Error).message}`);
        }
    }
    throw new Error(`no certified digests list: ${errors.join("; ") || "snapshot lists no digests location"}`);
}

export type ImmutableVerification = { checked: number; missing: string[]; tampered: string[]; nonVerifiable: string[] };

/**
 * Step 2: every immutable file of the directory against the certified digests; the range
 * `from..=to` must be complete. `extraDigests` covers files verified another way (the ancillary
 * archive's last immutable trio, checked against its signed manifest).
 */
export async function verifyImmutableFiles(immutableDir: string, range: { from: number; to: number }, verified: Pick<VerifiedDigests, "digests">, extraDigests: Map<string, string> = new Map()): Promise<ImmutableVerification> {
    const files = listImmutableFiles(immutableDir);
    const present = new Set(files.map((f) => f.name));
    const missing: string[] = [];
    for (let n = range.from; n <= range.to; n++) for (const name of immutableTrio(n)) if (!present.has(name)) missing.push(name);
    const tampered: string[] = [];
    const nonVerifiable: string[] = [];
    for (const f of files) {
        const want = verified.digests.get(f.name) ?? extraDigests.get(f.name);
        if (want === undefined) {
            nonVerifiable.push(f.name);
            continue;
        }
        if ((await sha256File(f.path)) !== want.toLowerCase()) tampered.push(f.name);
    }
    return { checked: files.length, missing, tampered, nonVerifiable };
}

/** A one-line account of what failed, or null when everything verified. */
export function describeVerification(v: ImmutableVerification): string | null {
    const parts: string[] = [];
    if (v.missing.length) parts.push(`${v.missing.length} missing (${v.missing.slice(0, 5).join(", ")})`);
    if (v.tampered.length) parts.push(`${v.tampered.length} tampered (${v.tampered.slice(0, 5).join(", ")})`);
    if (v.nonVerifiable.length) parts.push(`${v.nonVerifiable.length} not covered by the certified digests (${v.nonVerifiable.slice(0, 5).join(", ")})`);
    return parts.length ? parts.join("; ") : null;
}
