/**
 * Mithril aggregator endpoints per network and HTTP access with `fetch` (the aggregator sends
 * `access-control-allow-origin: *`, so a page or extension can call it directly).
 *
 * The genesis verification keys are the trust roots of the certificate chains. They are compiled
 * in (the files published under mithril-infra/configuration/<run mode>/genesis.vkey, checked
 * 2026-10-16) rather than fetched, so a compromised download path cannot swap them; a caller can
 * still pass another key or fetch one from `genesisVkeyUrl`.
 */

import { parseCertificate, CertificateError, type Certificate } from "./certificate";
import type { CertificateStore } from "./certStore";
import type { CertificateRetriever } from "./verifier";

export type MithrilNetwork = "preview" | "preprod" | "mainnet";

export type MithrilNetworkConfig = {
    network: MithrilNetwork;
    aggregator: string;
    genesisVkey: string;
    genesisVkeyUrl: string;
    runMode: string;
};

const VKEY_PREVIEW_PREPROD =
    "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d";
const VKEY_MAINNET =
    "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d";

const VKEY_URL = (runMode: string) => `https://raw.githubusercontent.com/input-output-hk/mithril/main/mithril-infra/configuration/${runMode}/genesis.vkey`;

export function mithrilNetworkConfig(network: string): MithrilNetworkConfig {
    switch (network.toLowerCase()) {
        case "mainnet":
            return { network: "mainnet", aggregator: "https://aggregator.release-mainnet.api.mithril.network/aggregator", genesisVkey: VKEY_MAINNET, genesisVkeyUrl: VKEY_URL("release-mainnet"), runMode: "release-mainnet" };
        case "preprod":
            return { network: "preprod", aggregator: "https://aggregator.release-preprod.api.mithril.network/aggregator", genesisVkey: VKEY_PREVIEW_PREPROD, genesisVkeyUrl: VKEY_URL("release-preprod"), runMode: "release-preprod" };
        case "preview":
            return { network: "preview", aggregator: "https://aggregator.pre-release-preview.api.mithril.network/aggregator", genesisVkey: VKEY_PREVIEW_PREPROD, genesisVkeyUrl: VKEY_URL("pre-release-preview"), runMode: "pre-release-preview" };
        default:
            throw new Error(`Mithril: unknown network ${JSON.stringify(network)} (preview, preprod or mainnet)`);
    }
}

export type FetchLike = (url: string) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

const defaultFetch: FetchLike = (url) => fetch(url);

async function getText(fetchImpl: FetchLike, url: string): Promise<string> {
    const r = await fetchImpl(url);
    if (!r.ok) throw new Error(`GET ${url}: HTTP ${r.status}`);
    return r.text();
}

export async function fetchGenesisVkey(url: string, fetchImpl: FetchLike = defaultFetch): Promise<string> {
    return (await getText(fetchImpl, url)).trim();
}

export type CardanoDatabaseListItem = {
    hash: string;
    merkle_root: string;
    beacon: { epoch: number; immutable_file_number: number };
    certificate_hash: string;
};

export type CardanoDatabaseSnapshot = CardanoDatabaseListItem & { network: string };

/** A small client for the aggregator routes the anchor needs. */
export class AggregatorClient {
    readonly base: string;
    constructor(baseUrl: string, private readonly fetchImpl: FetchLike = defaultFetch) {
        this.base = baseUrl.replace(/\/$/, "");
    }

    private async json<T>(path: string): Promise<T> {
        return JSON.parse(await getText(this.fetchImpl, `${this.base}${path}`)) as T;
    }

    listCardanoDatabase(): Promise<CardanoDatabaseListItem[]> {
        return this.json("/artifact/cardano-database");
    }

    cardanoDatabase(hash: string): Promise<CardanoDatabaseSnapshot> {
        if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`bad snapshot hash ${JSON.stringify(hash)}`);
        return this.json(`/artifact/cardano-database/${hash}`);
    }

    cardanoDatabaseDigests(): Promise<{ immutable_file_name: string; digest: string }[]> {
        return this.json("/artifact/cardano-database/digests");
    }

    /** The raw JSON text of a certificate. */
    async certificateText(hash: string): Promise<string> {
        if (!/^[0-9a-f]{64}$/.test(hash)) throw new CertificateError("CertificateRetrieve", `bad certificate hash ${JSON.stringify(hash)}`);
        try {
            return await getText(this.fetchImpl, `${this.base}/certificate/${hash}`);
        } catch (e) {
            throw new CertificateError("CertificateRetrieve", (e as Error).message);
        }
    }

    /** The newest certificate's hash (`/certificates` lists newest first). */
    async latestCertificateHash(): Promise<string> {
        const list = await this.json<{ hash: string }[]>("/certificates");
        if (!Array.isArray(list) || !list[0]?.hash) throw new Error("aggregator lists no certificates");
        return list[0].hash;
    }
}

export type CachingRetriever = CertificateRetriever & {
    stats: { hits: number; misses: number };
    /** Store the certificates downloaded so far (call after the chain verified). */
    persist(): Promise<void>;
};

/**
 * A certificate retriever over the aggregator, reading through `store` first. Downloads are kept in
 * memory and written to the store only by `persist()`, which the caller runs once the chain they
 * came in has verified, so a bad download is never cached. Cached certificates are still verified
 * on every walk: the cache saves downloads, not checks.
 */
export function cachingRetriever(client: AggregatorClient, store?: CertificateStore): CachingRetriever {
    const fresh = new Map<string, string>();
    const stats = { hits: 0, misses: 0 };
    const retrieve = (async (hash: string): Promise<Certificate> => {
        if (store) {
            let text: string | null = null;
            try {
                text = await store.get(hash);
            } catch {
                text = null;
            }
            if (text !== null) {
                try {
                    const c = parseCertificate(text);
                    if (c.hash === hash) {
                        stats.hits++;
                        return c;
                    }
                } catch {
                    /* unreadable cache entry: download again */
                }
            }
        }
        stats.misses++;
        const text = await client.certificateText(hash);
        const c = parseCertificate(text);
        fresh.set(hash, text);
        return c;
    }) as CachingRetriever;
    retrieve.stats = stats;
    retrieve.persist = async () => {
        if (!store) return;
        for (const [hash, text] of fresh) {
            try {
                await store.put(hash, text);
            } catch {
                /* cache only */
            }
        }
        fresh.clear();
    };
    return retrieve;
}
