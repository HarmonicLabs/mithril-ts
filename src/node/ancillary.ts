/**
 * Verification of an unpacked Mithril ancillary archive (mithril-client `AncillaryVerifier`):
 * `<dir>/ancillary_manifest.json` lists every ancillary file (the ledger state files and the
 * snapshot's last immutable trio, which the STM multi-signature does not cover) with its SHA-256;
 * each file must hash to its entry, and the manifest's Ed25519 signature must verify against the
 * network's ancillary key (core `verifyAncillaryManifestSignature`, strict Ed25519).
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { parseAncillaryManifest, verifyAncillaryManifestSignature, type AncillaryManifest } from "../ancillary";
import { tarEntryPath } from "./extract";
import { isFile, sha256File } from "./files";

export const ANCILLARY_MANIFEST_FILE = "ancillary_manifest.json";

export interface AncillaryVerification {
    ok: boolean;
    /** Files hashed. */
    files: number;
    signatureOk: boolean;
    errors: string[];
    /** The manifest, when it could be read. */
    manifest: AncillaryManifest | null;
}

/** Verify every file the manifest lists under `baseDir`, and the manifest signature against `vkeyRaw`. */
export async function verifyAncillaryDir(baseDir: string, vkeyRaw: string, log?: (m: string) => void): Promise<AncillaryVerification> {
    const path = join(baseDir, ANCILLARY_MANIFEST_FILE);
    let text: string;
    try {
        text = await readFile(path, "utf8");
    } catch {
        return { ok: false, files: 0, signatureOk: false, errors: [`no ${path}`], manifest: null };
    }
    let m: AncillaryManifest;
    try {
        m = parseAncillaryManifest(text);
    } catch (e) {
        return { ok: false, files: 0, signatureOk: false, errors: [(e as Error).message], manifest: null };
    }
    const errors: string[] = [];
    let files = 0;
    for (const [rel, expected] of Object.entries(m.data)) {
        let p: string;
        try {
            p = tarEntryPath(baseDir, rel).path; // listed paths stay inside the directory
        } catch (e) {
            errors.push((e as Error).message);
            continue;
        }
        if (!(await isFile(p))) {
            errors.push(`missing ${rel}`);
            continue;
        }
        const actual = await sha256File(p);
        if (actual !== expected) errors.push(`${rel}: sha256 ${actual} differs from the manifest's ${expected}`);
        files++;
    }
    const signatureOk = verifyAncillaryManifestSignature(m, vkeyRaw);
    if (!signatureOk) errors.push("manifest signature does not verify against the ancillary verification key");
    log?.(`ancillary: ${files} file(s) hashed, signature ${signatureOk ? "OK" : "FAILED"}${errors.length ? `, ${errors.length} error(s)` : ""}`);
    return { ok: errors.length === 0, files, signatureOk, errors, manifest: m };
}

/** The immutable files a manifest covers (`immutable/NNNNN.ext` entries), keyed by file name: `extraDigests` for `verifyImmutableFiles`. */
export function ancillaryImmutableDigests(m: AncillaryManifest): Map<string, string> {
    const out = new Map<string, string>();
    for (const [rel, h] of Object.entries(m.data)) {
        const match = /^immutable\/(\d{5,}\.(?:chunk|primary|secondary))$/.exec(rel);
        if (match) out.set(match[1]!, h);
    }
    return out;
}
