import { describe, expect, test } from "bun:test";
import { ANCILLARY_VKEYS, ancillaryManifestHash, parseAncillaryManifest, verifyAncillaryManifestSignature } from "../src/ancillary";

// The preview ancillary manifest of snapshot d2bd116c… (epoch 1415, 2026-09-09), signed by the aggregator.
const MANIFEST = `{"data":{"immutable/28314.chunk":"f1a3700d0c86c09e454f1bc19fcee7bdba49b0cfcf327a87c9244edc88007073","immutable/28314.primary":"ef734a4fb7d82109ff1063a9b648451d73c58f25f0fdcffb14a0bb6cc035b308","immutable/28314.secondary":"0cfcc258205dbde80e5f0f2b9aeca905d71fa6ef4a9508c07a50d96120575886","ledger/122316253/meta":"70615191c5db875189e506b5667fe88f102d8999b72d7fc0e822c38e7650d275","ledger/122316253/state":"47b86e73fda4bc76457d2215d01dce2793e8c48c145f98fadf2adae53bdd8e8b","ledger/122316253/tables":"86615f416820320b8e3379858b23ef984f668c34ce91bf9c5ff1982c36a5ad84"},"signature":"fe5b0265d560172e518256b452624764b88cbcc95b6a2b6e95bbede25395c6fb46041dd3b4078999f4a2994a78d07b2621175457da618fdddfa50d024dd3cd0e"}`;

describe("ancillary manifest", () => {
    test("the preview aggregator's signature verifies (strict Ed25519) over the manifest hash with the published key", () => {
        const m = parseAncillaryManifest(MANIFEST);
        expect(Object.keys(m.data)).toHaveLength(6);
        expect(ancillaryManifestHash(m)).toHaveLength(32);
        expect(verifyAncillaryManifestSignature(m, ANCILLARY_VKEYS.preview!)).toBe(true);
    });

    test("a changed file hash, another network's key or a malformed signature fails", () => {
        const m = parseAncillaryManifest(MANIFEST);
        expect(verifyAncillaryManifestSignature(m, ANCILLARY_VKEYS.mainnet!)).toBe(false);
        expect(verifyAncillaryManifestSignature({ ...m, signature: "zz" }, ANCILLARY_VKEYS.preview!)).toBe(false);
        m.data["ledger/122316253/state"] = "00".repeat(32);
        expect(verifyAncillaryManifestSignature(m, ANCILLARY_VKEYS.preview!)).toBe(false);
    });

    test("a signature with S + L (malleable) is refused, as cardano-node's strict check does", () => {
        const m = parseAncillaryManifest(MANIFEST);
        const sig = Uint8Array.from(m.signature!.match(/../g)!, (h) => parseInt(h, 16));
        // S is the second half, little-endian; add the group order L
        const L = (1n << 252n) + 27742317777372353535851937790883648493n;
        let s = 0n;
        for (let i = 63; i >= 32; i--) s = (s << 8n) + BigInt(sig[i]!);
        let t = s + L;
        for (let i = 32; i < 64; i++) { sig[i] = Number(t & 0xffn); t >>= 8n; }
        const malleable = { ...m, signature: Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("") };
        expect(verifyAncillaryManifestSignature(malleable, ANCILLARY_VKEYS.preview!)).toBe(false);
    });
});
