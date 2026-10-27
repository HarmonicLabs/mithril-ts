/**
 * Runs the cross-check against Gerolamo's verifier when the sibling checkout is present and
 * MITHRIL_CROSSCHECK=1 (it takes about a minute):
 *   MITHRIL_CROSSCHECK=1 bun test test/mithril/crossCheck.test.ts
 */
import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { DEFAULT_GEROLAMO, runCrossCheck } from "./crossCheck";

const enabled = process.env.MITHRIL_CROSSCHECK === "1" && existsSync(join(DEFAULT_GEROLAMO, "src/mithril/verify/verifier.ts"));

test.skipIf(!enabled)("Gerolamo (noble) and Gerolamino (@harmoniclabs/crypto) agree on every case, tampered ones included", async () => {
    const r = await runCrossCheck({ fuzz: 100 });
    const bad = r.cases.filter((c) => !c.agree);
    if (bad.length) console.log(bad.slice(0, 20));
    expect(bad.length).toBe(0);
    expect(r.chain.bothReachedGenesis).toBe(true);
    expect(r.rejected).toBeGreaterThan(500);
}, 600_000);
