/**
 * Cardano database v2 snapshot messages as the aggregator serves them, read through the core
 * `AggregatorClient`, and verification keys given as a key, a file or a URL.
 *
 * `GET /artifact/cardano-database/{hash}` returns a `CardanoDatabaseSnapshotMessage`
 * (mithril-common `messages/cardano_database.rs`): the list item fields plus where to download the
 * digests list, the immutable archives and the ancillary archive. Locations are tagged
 * (`LocationTemplate`/`DigestLocation`/`AncillaryLocation` in mithril-common `entities`):
 *
 *   { "type": "cloud_storage", "uri": { "Template": "https://.../{immutable_file_number}.tar.zst" }, "compression_algorithm": "zstandard" }
 *   { "type": "cloud_storage", "uri": "https://.../preview-e10-i2.digests.tar.zst", "compression_algorithm": "zstandard" }
 *   { "type": "aggregator", "uri": "https://.../artifact/cardano-database/digests" }
 *
 * Every number in these messages fits a double (sizes are bytes, at most a few hundred GB), so the
 * core client's plain JSON parsing is exact here.
 */

import { readFile } from "node:fs/promises";

import type { AggregatorClient, CardanoDatabaseListItem, FetchLike } from "../aggregator";

/** A download location of a cardano-database artifact. */
export type MithrilLocation = {
    type: string;
    /** A plain URL, or a URL template (`{ "Template": ... }`) for the immutable archives. */
    uri: string | { Template?: string; template?: string };
    compression_algorithm?: string;
};

export type CardanoDatabaseSnapshotListItem = CardanoDatabaseListItem & {
    total_db_size_uncompressed?: number;
    cardano_node_version?: string;
    created_at?: string;
};

/** `CardanoDatabaseSnapshotMessage`. */
export type CardanoDatabaseSnapshotMessage = CardanoDatabaseSnapshotListItem & {
    network: string;
    digests?: { size_uncompressed?: number; locations: MithrilLocation[] };
    immutables?: { average_size_uncompressed?: number; locations: MithrilLocation[] };
    ancillary?: { size_uncompressed?: number; locations: MithrilLocation[] };
};

/** The URL (or URL template) of a location. */
export function locationUri(loc: MithrilLocation): string | null {
    const u = loc.uri;
    if (typeof u === "string") return u;
    if (u && typeof u === "object") {
        const t = u.Template ?? u.template;
        if (typeof t === "string") return t;
    }
    return null;
}

/** The immutable archives' URL template (contains `{immutable_file_number}`), or throw. */
export function immutableUrlTemplate(snapshot: CardanoDatabaseSnapshotMessage): string {
    for (const loc of snapshot.immutables?.locations ?? []) {
        const t = locationUri(loc);
        if (t && t.includes("{immutable_file_number}") && /^https?:\/\//.test(t)) return t;
    }
    throw new Error(`snapshot ${snapshot.hash}: no immutable files location with an {immutable_file_number} template`);
}

/** The ancillary archive's URL (a plain URL), or null when the snapshot has none. */
export function ancillaryUrl(snapshot: CardanoDatabaseSnapshotMessage): string | null {
    for (const loc of snapshot.ancillary?.locations ?? []) {
        const t = locationUri(loc);
        if (t && /^https?:\/\//.test(t)) return t;
    }
    return null;
}

/** A list item by hash, or the newest one for "latest" (the list is newest first). */
export function selectSnapshot<T extends { hash: string }>(list: readonly T[], hashOrLatest = "latest"): T {
    if (!list.length) throw new Error("the aggregator lists no cardano-database snapshots");
    if (hashOrLatest.toLowerCase() === "latest") return list[0]!;
    const found = list.find((s) => s.hash === hashOrLatest.toLowerCase());
    if (!found) throw new Error(`snapshot ${hashOrLatest} is not listed by the aggregator (use "latest" or a listed hash)`);
    return found;
}

/** `GET /artifact/cardano-database`, with the fields the core list item type leaves out. */
export async function listCardanoDatabaseSnapshots(client: AggregatorClient): Promise<CardanoDatabaseSnapshotListItem[]> {
    const list = await client.listCardanoDatabase();
    if (!Array.isArray(list)) throw new Error(`${client.base}/artifact/cardano-database: not a list`);
    return list as CardanoDatabaseSnapshotListItem[];
}

/** `GET /artifact/cardano-database/{hash}`: the snapshot message with its download locations. */
export async function getCardanoDatabaseSnapshot(client: AggregatorClient, hash: string): Promise<CardanoDatabaseSnapshotMessage> {
    const detail = (await client.cardanoDatabase(hash)) as CardanoDatabaseSnapshotMessage;
    if (!detail || typeof detail !== "object" || detail.hash !== hash) throw new Error(`${client.base}/artifact/cardano-database/${hash}: not that snapshot`);
    if (!detail.beacon || typeof detail.beacon.immutable_file_number !== "number") throw new Error(`snapshot ${hash}: no beacon`);
    return detail;
}

const defaultFetch: FetchLike = (url) => fetch(url);

/**
 * A verification key file's content (genesis.vkey, ancillary.vkey: hex of a JSON byte array) from
 * an http(s) URL or a local file path.
 */
export async function fetchGenesisVkey(pathOrUrl: string, fetchImpl: FetchLike = defaultFetch): Promise<string> {
    if (/^https?:\/\//.test(pathOrUrl)) {
        const r = await fetchImpl(pathOrUrl);
        if (!r.ok) throw new Error(`GET ${pathOrUrl}: HTTP ${r.status}`);
        return (await r.text()).trim();
    }
    return (await readFile(pathOrUrl, "utf8")).trim();
}

/** A verification key given as the key itself (hex), a URL or a file path. */
export async function resolveVerificationKey(keyPathOrUrl: string, fetchImpl: FetchLike = defaultFetch): Promise<string> {
    const v = keyPathOrUrl.trim();
    if (/^[0-9a-fA-F]+$/.test(v) && v.length >= 64) return v;
    return fetchGenesisVkey(v, fetchImpl);
}
