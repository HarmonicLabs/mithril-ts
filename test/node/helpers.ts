import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { immutableStem } from "../../src/node";

/** Deterministic pseudo-random bytes. */
export function bytes(seed: number, n: number): Uint8Array {
    const out = new Uint8Array(n);
    let x = seed >>> 0 || 1;
    for (let i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >>> 17;
        x ^= x << 5;
        out[i] = x & 0xff;
    }
    return out;
}

/** Write a fake but well-formed immutable trio `n` into `dir`. */
export function writeTrio(dir: string, n: number): void {
    writeFileSync(join(dir, `${immutableStem(n)}.chunk`), bytes(n * 3 + 1, 20_000 + n * 777));
    writeFileSync(join(dir, `${immutableStem(n)}.primary`), bytes(n * 3 + 2, 1_000 + n));
    writeFileSync(join(dir, `${immutableStem(n)}.secondary`), bytes(n * 3 + 3, 3_000 + n * 5));
}

export const FIXTURES = join(import.meta.dir, "..", "fixtures", "cdb");
