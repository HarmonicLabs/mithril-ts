import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { parseCertificate } from "../src/certificate";
import { parseStakeArtifact, poolIdHex, stakeDistributionMerkleRoot, stakeMessageMatches } from "../src/stake";

const dir = `${import.meta.dir}/fixtures`;
const artifact = parseStakeArtifact(readFileSync(`${dir}/preview-csd-1458.json`, "utf8"));
const cert = parseCertificate(readFileSync(`${dir}/preview-csd-1458-cert.json`, "utf8"));

describe("phase 4: Mithril-certified stake distribution", () => {
    test("the artifact's Merkle root is the one the certificate signs (preview, epoch 1458)", () => {
        expect(artifact.stake.size).toBe(647);
        const root = stakeDistributionMerkleRoot(artifact.stake);
        expect(root).toBe("deac11a90c7c5735d270c839753f683d0423e09fae648ed967d343972c7a879b");
        expect(cert.protocolMessage.get("cardano_stake_distribution_merkle_root")).toBe(root);
        expect(stakeMessageMatches(cert, 1458, root)).toBe(true);
    });

    test("one lovelace changed, or the wrong epoch, no longer matches", () => {
        const [pool, amount] = [...artifact.stake][0]!;
        const tampered = new Map(artifact.stake).set(pool, amount + 1n);
        expect(stakeMessageMatches(cert, 1458, stakeDistributionMerkleRoot(tampered))).toBe(false);
        expect(stakeMessageMatches(cert, 1457, stakeDistributionMerkleRoot(artifact.stake))).toBe(false);
    });

    test("pool ids decode to 28-byte hex", () => {
        expect(poolIdHex("pool12yrhvezsrqxlafahf02ka28a4a3qxgcgkylku4vqjg385jh60wa")).toMatch(/^[0-9a-f]{56}$/);
        expect(() => poolIdHex("addr_test1wz54prcptnaullpa3zkyc8ynfddc954m9qw5v3nj7mzf2wggs2uld")).toThrow();
    });
});
