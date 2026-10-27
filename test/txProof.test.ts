import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { parseCertificate } from "../src/certificate";
import { verifyTransactionsProof, type TransactionsProofResponse } from "../src/txProof";

const dir = `${import.meta.dir}/fixtures`;
const res = JSON.parse(readFileSync(`${dir}/preview-ctx-proof.json`, "utf8")) as TransactionsProofResponse;
const cert = parseCertificate(readFileSync(`${dir}/preview-ctx-proof-cert.json`, "utf8"));
const flip = (hex: string, at: number) => hex.slice(0, at) + (hex[at] === "0" ? "1" : "0") + hex.slice(at + 1);

describe("phase 5: Mithril transaction proofs", () => {
    test("three preview transactions are proven in block range [4785195, 4785210) by the certificate", () => {
        const p = verifyTransactionsProof(res, cert);
        expect(p.merkleRoot).toBe("597b0e639dbad5ceffb83217360e203f44244b764de83423bf8424956e81144e");
        expect(p.latestBlockNumber).toBe(4785239);
        expect(p.certified.size).toBe(3);
        expect(p.certified.get("bbe0d151bdfcf3ba4f6008ddfaed9030fae26861dedb108c258c335803727640")).toEqual({ start: 4785195, end: 4785210 });
        expect(p.nonCertified).toEqual(["0".repeat(64)]);
    });

    test("a changed proof byte, block number or claimed transaction is rejected", () => {
        const g = res.certified_transactions[0]!;
        // the proof is JSON in hex: change a digit inside the first number of a node hash
        const text = new TextDecoder().decode(Uint8Array.from(g.proof.match(/../g)!, (b) => parseInt(b, 16)));
        const i = text.indexOf('"inner_proof_items":[{"hash":[') + 29;
        const bad = text.slice(0, i) + (text[i] === "1" ? "2" : "1") + text.slice(i + 1);
        const badHex = [...new TextEncoder().encode(bad)].map((b) => b.toString(16).padStart(2, "0")).join("");
        expect(() => verifyTransactionsProof({ ...res, certified_transactions: [{ ...g, proof: badHex }] }, cert)).toThrow();
        expect(() => verifyTransactionsProof({ ...res, latest_block_number: res.latest_block_number + 1 }, cert)).toThrow(/does not sign/);
        expect(() => verifyTransactionsProof({ ...res, certified_transactions: [{ ...g, transactions_hashes: [...g.transactions_hashes, flip(g.transactions_hashes[0]!, 5)] }] }, cert)).toThrow(/does not contain/);
    });
});
