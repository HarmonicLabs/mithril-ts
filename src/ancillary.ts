/**
 * Mithril ancillary files (`ancillary_manifest.json`): the ledger state files and the last immutable file are not
 * covered by the STM multi-signature; the aggregator signs their SHA-256 manifest with an Ed25519 key published per
 * network (`ancillary.vkey`, the same hex-of-JSON-byte-array format as the genesis key).
 *
 * Mirrors mithril-client `AncillaryVerifier`: every listed file's SHA-256 must equal the manifest entry, and the
 * signature must verify (strict Ed25519, as for genesis certificates) over `compute_hash` = SHA-256 of the
 * concatenation, in path order (BTreeMap), of each path's bytes followed by its hex hash's bytes. Hashing the files
 * themselves needs file access: `verifyAncillaryDir` in the node entry point.
 */
import { hexToBytes } from "./bytes";
import { ed25519VerifyStrict } from "./ed25519";
import { sha256Hasher } from "./hash";
import { decodeGenesisVerificationKey } from "./verifier";

export interface AncillaryManifest { data: Record<string, string>; signature: string | null }

/** Published ancillary verification keys (mithril-infra/configuration/<run mode>/ancillary.vkey, checked 2026-09). */
export const ANCILLARY_VKEYS: Record<string, string> = {
    mainnet: "5b32332c37312c39362c3133332c34372c3235332c3232362c3133362c3233352c35372c3136342c3130362c3138362c322c32312c32392c3132302c3136332c38392c3132312c3137372c3133382c3230382c3133382c3231342c39392c35382c32322c302c35382c332c36395d",
    preprod: "5b3138392c3139322c3231362c3135302c3131342c3231362c3233372c3231302c34352c31382c32312c3139362c3230382c3234362c3134362c322c3235322c3234332c3235312c3139372c32382c3135372c3230342c3134352c33302c31342c3232382c3136382c3132392c38332c3133362c33365d",
    preview: "5b3138392c3139322c3231362c3135302c3131342c3231362c3233372c3231302c34352c31382c32312c3139362c3230382c3234362c3134362c322c3235322c3234332c3235312c3139372c32382c3135372c3230342c3134352c33302c31342c3232382c3136382c3132392c38332c3133362c33365d",
};

export function parseAncillaryManifest(json: string): AncillaryManifest {
    const o = JSON.parse(json);
    if (!o || typeof o !== "object" || !o.data || typeof o.data !== "object") throw new Error("ancillary manifest: no data map");
    const data: Record<string, string> = {};
    for (const [k, v] of Object.entries(o.data)) {
        if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) throw new Error(`ancillary manifest: bad hash for ${k}`);
        data[k] = v;
    }
    return { data, signature: typeof o.signature === "string" ? o.signature : null };
}

/** mithril `AncillaryFilesManifest::compute_hash`: paths in byte order (Rust BTreeMap of PathBuf). */
export function ancillaryManifestHash(m: AncillaryManifest): Uint8Array {
    const h = sha256Hasher();
    const keys = Object.keys(m.data).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const k of keys) h.update(k).update(m.data[k]!);
    return h.digest();
}

/** The manifest signature against a network's ancillary key (`ANCILLARY_VKEYS[network]` or the published file). */
export function verifyAncillaryManifestSignature(m: AncillaryManifest, vkeyRaw: string): boolean {
    if (!m.signature || !/^[0-9a-f]{128}$/i.test(m.signature)) return false;
    return ed25519VerifyStrict(hexToBytes(m.signature), ancillaryManifestHash(m), decodeGenesisVerificationKey(vkeyRaw));
}
