import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import { pointFromBytes, verifyEd25519Signature_sync } from "@harmoniclabs/crypto";

import { AggregatorClient, cachingRetriever, mithrilNetworkConfig, type FetchLike } from "../src/aggregator";
import { hexToBytes } from "../src/bytes";
import { MemoryCertificateStore } from "../src/certStore";
import {
    cardanoDatabaseMessageMatches,
    computeCertificateHash,
    parseCertificate,
    phiFFixed,
    protocolMessageHash,
    rfc3339Nanos,
    type Certificate,
} from "../src/certificate";
import { decodePointStrict, ed25519VerifyStrict } from "../src/ed25519";
import { parseJsonLossless } from "../src/json";
import {
    decodeGenesisVerificationKey,
    verifyCertificateChain,
    verifyGenesisCertificate,
    verifyStandardCertificate,
    verifyStandardCertificateIntegrity,
} from "../src/verifier";

const FIX = join(import.meta.dir, "fixtures");
const text = (rel: string) => Bun.file(join(FIX, "certs", rel)).text();
const cert = async (rel: string) => parseCertificate(await text(rel));
const edited = async (rel: string, edit: (c: Record<string, any>) => void): Promise<Certificate> => {
    const c = parseJsonLossless(await text(rel)) as Record<string, any>;
    edit(c);
    return parseCertificate(c);
};
const flipHex = (s: string, at: number): string => s.slice(0, at) + (parseInt(s[at]!, 16) ^ 1).toString(16) + s.slice(at + 1);

const previewKey = decodeGenesisVerificationKey(await text("preview/genesis.vkey"));
const mainnetKey = decodeGenesisVerificationKey(await text("mainnet/genesis.vkey"));
const chain = JSON.parse(new TextDecoder().decode(Bun.gunzipSync(await Bun.file(join(FIX, "chains/preview.json.gz")).bytes()))) as {
    tip: string;
    snapshot: { merkle_root: string; certificate_hash: string; beacon: { epoch: number; immutable_file_number: number } };
    certificates: Record<string, string>;
};
const fromChain = (h: string) => parseCertificate(chain.certificates[h]!);
const g = parseJsonLossless(await text("preview/genesis.json")) as Record<string, any>;

describe("certificate hashing", () => {
    test("content hash and protocol message hash of every fixture and every chain certificate", async () => {
        const all = [
            ...(await Promise.all(["preview/genesis.json", "preview/hop1.json", "preview/hop2.json", "preview/cdb.json", "preview/cdb-previous.json", "mainnet/multi.json", "mainnet/multi-previous.json"].map(cert))),
            ...Object.keys(chain.certificates).map(fromChain),
        ];
        for (const c of all) {
            expect(computeCertificateHash(c)).toBe(c.hash);
            expect(protocolMessageHash(c.protocolMessage)).toBe(c.signedMessage);
        }
    });

    test("U8F24 rounding (ties to even) and RFC 3339 nanoseconds", () => {
        expect(phiFFixed(0.7)).toBe(Math.round(0.7 * 2 ** 24));
        expect(phiFFixed(0.5 / 2 ** 24)).toBe(0);
        expect(phiFFixed(1.5 / 2 ** 24)).toBe(2);
        expect(rfc3339Nanos("1970-01-01T00:00:01.000000001Z")).toBe(1_000_000_001n);
        expect(rfc3339Nanos("1970-01-01T01:00:00+01:00")).toBe(0n);
    });

    test("unknown protocol message parts, other hash schemes and SNARK fields are rejected", async () => {
        await expect(edited("preview/cdb.json", (c) => void (c.protocol_message.message_parts.extra = "x"))).rejects.toThrow(/unknown part/);
        await expect(edited("preview/cdb.json", (c) => void (c.protocol_message.hash_scheme = "rigid"))).rejects.toThrow(/hash_scheme/);
        await expect(edited("preview/cdb.json", (c) => void (c.ancillary_verifier_data = "00"))).rejects.toThrow(/SNARK/);
    });

    test("u64 values above 2^53 survive parsing (JSON source text) and hashing", async () => {
        const doc = parseJsonLossless('{"stake":18446744073709551615,"small":5,"f":0.65}') as Record<string, unknown>;
        expect(doc.stake).toBe(18446744073709551615n);
        expect(doc.small).toBe(5);
        expect(doc.f).toBe(0.65);
        const c = await edited("mainnet/multi.json", (c) => void (c.metadata.signers[0].stake = 9007199254740993n));
        expect(c.metadata.signers[0]!.stake).toBe(9007199254740993n);
        expect(computeCertificateHash(c)).not.toBe(c.hash);
    });

    test("the snapshot certificate binds the snapshot's Merkle root (and no other)", () => {
        const c = fromChain(chain.snapshot.certificate_hash);
        expect(cardanoDatabaseMessageMatches(c, chain.snapshot.merkle_root)).toBe(true);
        expect(cardanoDatabaseMessageMatches(c, flipHex(chain.snapshot.merkle_root, 0))).toBe(false);
        expect(c.signature.kind === "multi" && c.signature.signedEntityType).toEqual({
            type: "CardanoDatabase",
            epoch: BigInt(chain.snapshot.beacon.epoch),
            immutableFileNumber: BigInt(chain.snapshot.beacon.immutable_file_number),
        });
    });
});

describe("certificate verification (port of MithrilCertificateVerifier)", () => {
    test("standard certificates against their predecessors: same epoch, new epoch, after genesis", async () => {
        verifyStandardCertificate(await cert("preview/cdb.json"), await cert("preview/cdb-previous.json"));
        verifyStandardCertificate(await cert("mainnet/multi.json"), await cert("mainnet/multi-previous.json"));
        verifyStandardCertificate(await cert("preview/hop2.json"), await cert("preview/hop1.json"));
        verifyStandardCertificate(await cert("preview/hop1.json"), await cert("preview/genesis.json"));
    });

    test("genesis certificate verifies under the preview key only", async () => {
        const g = await cert("preview/genesis.json");
        verifyGenesisCertificate(g, previewKey);
        expect(() => verifyGenesisCertificate(g, mainnetKey)).toThrow(/CertificateGenesis/);
        expect(mithrilNetworkConfig("preview").genesisVkey).toBe((await text("preview/genesis.vkey")).trim());
        expect(mithrilNetworkConfig("mainnet").genesisVkey).toBe((await text("mainnet/genesis.vkey")).trim());
    });

    test("short walk hop2 -> hop1 -> genesis; a verified-cache hit stops early", async () => {
        const store = new Map<string, Certificate>();
        for (const rel of ["preview/genesis.json", "preview/hop1.json"]) {
            const c = await cert(rel);
            store.set(c.hash, c);
        }
        const retrieve = async (h: string) => store.get(h) ?? Promise.reject(new Error(`missing ${h}`));
        const tip = await cert("preview/hop2.json");
        const r = await verifyCertificateChain(tip, { genesisVkey: previewKey, retrieve });
        expect(r.hops.map((h) => h.kind)).toEqual(["standard", "standard", "genesis"]);
        expect(r.genesisHash).toBe((await cert("preview/genesis.json")).hash);
        const hop1 = await cert("preview/hop1.json");
        const r2 = await verifyCertificateChain(tip, { genesisVkey: previewKey, retrieve, verifiedCache: new Set([hop1.hash]) });
        expect(r2.stoppedAtCache).toBe(true);
        expect(r2.hops.length).toBe(1);
    });

    test(`full offline walk of the live preview chain (${Object.keys(chain.certificates).length} certificates) to genesis`, async () => {
        const r = await verifyCertificateChain(fromChain(chain.tip), { genesisVkey: previewKey, retrieve: async (h) => fromChain(h) });
        expect(r.genesisHash).toBe(g.hash); // the same genesis certificate as the published fixture
        expect(r.hops.length).toBe(Object.keys(chain.certificates).length);
        expect(r.hops.at(-1)!.kind).toBe("genesis");
        const ms = r.hops.map((h) => h.ms).sort((a, b) => a - b);
        console.log(
            `preview chain walk: ${r.hops.length} certificates in ${(r.ms / 1000).toFixed(2)} s (verify ${(r.verifyMs / 1000).toFixed(2)} s), median ${ms[ms.length >> 1]!.toFixed(1)} ms, max ${ms.at(-1)!.toFixed(1)} ms per certificate`,
        );
        // Under the mainnet key the same walk fails at the genesis certificate.
        await expect(verifyCertificateChain(fromChain(chain.tip), { genesisVkey: mainnetKey, retrieve: async (h) => fromChain(h), maxHops: 1000 })).rejects.toThrow(/CertificateGenesis/);
    }, 120_000);

    describe("tampered", () => {
        const rejects = async (f: () => Promise<unknown>, code: RegExp) => expect(f()).rejects.toThrow(code);
        test("flipped multi-signature hex digit", () =>
            rejects(async () => verifyStandardCertificateIntegrity(await edited("preview/cdb.json", (c) => void (c.multi_signature = flipHex(c.multi_signature, 120)))), /CertificateHashUnmatch|CertificateDecode/));
        test("flipped signed_message", () => rejects(async () => verifyStandardCertificateIntegrity(await edited("preview/cdb.json", (c) => void (c.signed_message = flipHex(c.signed_message, 5)))), /CertificateHashUnmatch/));
        test("altered signer stake (metadata)", () => rejects(async () => verifyStandardCertificateIntegrity(await edited("mainnet/multi.json", (c) => void (c.metadata.signers[0].stake += 1))), /CertificateHashUnmatch/));
        test("altered protocol message with recomputed signed_message and hash: STM rejects", () =>
            rejects(async () => {
                const c = await edited("preview/cdb.json", (c) => void (c.protocol_message.message_parts.cardano_database_merkle_root = "00".repeat(32)));
                c.signedMessage = protocolMessageHash(c.protocolMessage);
                c.hash = computeCertificateHash(c);
                return verifyStandardCertificateIntegrity(c);
            }, /VerifyMultiSignature/));
        test("epoch differs from the current_epoch part", () =>
            rejects(async () => {
                const c = await edited("preview/cdb.json", (c) => void (c.epoch += 1));
                c.hash = computeCertificateHash(c);
                return verifyStandardCertificateIntegrity(c);
            }, /CertificateEpochUnmatch/));
        test("self-chaining certificate", () =>
            rejects(async () => {
                const c = await cert("preview/cdb.json");
                c.previousHash = c.hash;
                return verifyStandardCertificateIntegrity(c);
            }, /CertificateChainInfiniteLoop/));
        test("wrong predecessor", () => rejects(async () => verifyStandardCertificate(await cert("preview/cdb.json"), await cert("preview/hop1.json")), /CertificateChain/));
        test("flipped genesis signature", () =>
            rejects(async () => verifyGenesisCertificate(await edited("preview/genesis.json", (c) => void (c.genesis_signature = flipHex(c.genesis_signature, 7))), previewKey), /CertificateHashUnmatch|CertificateGenesis/));
        test("a standard certificate presented as genesis and vice versa", async () => {
            expect(() => verifyGenesisCertificate(parseCertificate(chain.certificates[chain.tip]!), previewKey)).toThrow(/InvalidGenesisCertificateProvided/);
            await expect((async () => verifyStandardCertificateIntegrity(await cert("preview/genesis.json")))()).rejects.toThrow(/InvalidStandardCertificateProvided/);
        });
        test("a retriever returning another certificate than asked", async () => {
            const other = await cert("preview/hop1.json");
            await expect(verifyCertificateChain(await cert("preview/hop2.json"), { genesisVkey: previewKey, retrieve: async () => (other.hash === "x" ? other : await cert("preview/cdb.json")) })).rejects.toThrow(
                /CertificateChainPreviousHashUnmatch/,
            );
        });
    });
});

describe("Ed25519 strict (dalek verify_strict) on HL primitives", () => {
    const sig = parseCertificate(g).signature as { kind: "genesis"; signature: Uint8Array };
    const msg = new TextEncoder().encode(g.signed_message);
    const L = (1n << 252n) + 27742317777372353535851937790883648493n;
    const le = (b: Uint8Array) => b.reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
    const leBytes = (n: bigint) => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));

    test("the genesis signature verifies (strict and HL plain agree)", () => {
        expect(ed25519VerifyStrict(sig.signature, msg, previewKey)).toBe(true);
        expect(verifyEd25519Signature_sync(sig.signature, msg, previewKey)).toBe(true);
        expect(ed25519VerifyStrict(sig.signature, msg, mainnetKey)).toBe(false);
    });

    test("HL gap: S + L (malleated signature) is accepted by HL, rejected here", () => {
        const S = le(sig.signature.subarray(32));
        const mall = new Uint8Array(64);
        mall.set(sig.signature.subarray(0, 32));
        mall.set(leBytes(S + L), 32);
        expect(verifyEd25519Signature_sync(mall, msg, previewKey)).toBe(true);
        expect(ed25519VerifyStrict(mall, msg, previewKey)).toBe(false);
    });

    test("HL gap: the identity key with R = identity and S = 0 verifies ANY message under HL, rejected here (small order)", () => {
        const identity = new Uint8Array(32);
        identity[0] = 1;
        const forged = new Uint8Array(64);
        forged.set(identity, 0);
        for (const m of [msg, new TextEncoder().encode("anything at all")]) {
            expect(verifyEd25519Signature_sync(forged, m, identity)).toBe(true);
            expect(ed25519VerifyStrict(forged, m, identity)).toBe(false);
        }
    });

    test("HL gap: non-canonical encodings (y >= p) decode under HL, rejected here", () => {
        const p = (1n << 255n) - 19n;
        const nonCanonical = leBytes(1n + p); // y = 1 + p, the identity's y written non-canonically
        expect(() => pointFromBytes(nonCanonical)).not.toThrow();
        expect(decodePointStrict(nonCanonical)).toBeNull();
    });

    test("bad lengths return false (HL throws)", () => {
        expect(() => verifyEd25519Signature_sync(sig.signature.subarray(0, 63), msg, previewKey)).toThrow();
        expect(ed25519VerifyStrict(sig.signature.subarray(0, 63), msg, previewKey)).toBe(false);
        expect(ed25519VerifyStrict(sig.signature, msg, previewKey.subarray(0, 31))).toBe(false);
    });
});

describe("certificate cache (caching retriever over an injected store)", () => {
    test("downloads are stored only by persist(); the next walk reads from the store and still verifies", async () => {
        let downloads = 0;
        const fakeFetch: FetchLike = async (url) => {
            const h = url.split("/").pop()!;
            const t = chain.certificates[h];
            downloads++;
            return { ok: t !== undefined, status: t ? 200 : 404, text: async () => t ?? "" };
        };
        const client = new AggregatorClient("https://aggregator.invalid/aggregator", fakeFetch);
        const store = new MemoryCertificateStore();
        const r1 = cachingRetriever(client, store);
        const w1 = await verifyCertificateChain(await r1(chain.tip), { genesisVkey: previewKey, retrieve: r1 });
        expect(store.map.size).toBe(0);
        await r1.persist();
        expect(store.map.size).toBe(w1.hops.length);
        expect(r1.stats.misses).toBe(w1.hops.length);

        const before = downloads;
        const r2 = cachingRetriever(client, store);
        const w2 = await verifyCertificateChain(await r2(chain.tip), { genesisVkey: previewKey, retrieve: r2 });
        expect(downloads).toBe(before);
        expect(r2.stats.hits).toBe(w2.hops.length);

        // A corrupted cache entry is not trusted: verification fails (hash) rather than accepting it.
        const victim = w2.hops[5]!.hash;
        store.map.set(victim, store.map.get(victim)!.replace(/"signed_message":"[0-9a-f]/, (m) => m.slice(0, -1) + (m.at(-1) === "0" ? "1" : "0")));
        const r3 = cachingRetriever(client, store);
        await expect(verifyCertificateChain(await r3(chain.tip), { genesisVkey: previewKey, retrieve: r3 })).rejects.toThrow(/CertificateHashUnmatch/);
    }, 120_000);

    test("aggregator certificate requests reject malformed hashes", async () => {
        const client = new AggregatorClient("https://aggregator.invalid/aggregator", async () => ({ ok: true, status: 200, text: async () => "" }));
        await expect(client.certificateText("../etc")).rejects.toThrow(/CertificateRetrieve/);
        expect(hexToBytes("00ff")).toEqual(new Uint8Array([0, 255]));
    });
});
