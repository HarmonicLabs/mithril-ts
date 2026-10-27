/**
 * Hash functions for the Mithril verifier, all from @harmoniclabs/crypto except Blake2s
 * (pure TS here, see blake2s.ts).
 *
 * HL's sha2_256_sync and blake2b are one-shot, so the streaming hasher below buffers the parts and
 * hashes once at digest time; every input it sees is small (certificate fields, Merkle nodes).
 * Large inputs (chunk files) go through `sha256Async`, which is WebCrypto when the runtime has it.
 */

import { blake2b, sha2_256, sha2_256_sync } from "./hl";

import { blake2s256 } from "./blake2s";
import { bytesToHex, concatBytes, utf8 } from "./bytes";

export { blake2s, blake2s256 } from "./blake2s";

export const sha256 = (data: Uint8Array): Uint8Array => sha2_256_sync(data);

/** SHA-256 via @harmoniclabs/crypto's async entry point (WebCrypto when available, pure TS otherwise). */
export async function sha256Async(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await sha2_256(data));
}

export const blake2b128 = (...parts: Uint8Array[]): Uint8Array => blake2b(concatBytes(...parts), 16);
export const blake2b256 = (...parts: Uint8Array[]): Uint8Array => blake2b(concatBytes(...parts), 32);
export const blake2b512 = (...parts: Uint8Array[]): Uint8Array => blake2b(concatBytes(...parts), 64);

export interface Hasher {
    update(data: Uint8Array | string): Hasher;
    digest(): Uint8Array;
    hex(): string;
}

/** SHA-256 with update(string | bytes); strings are hashed as UTF-8 (Rust `hasher.update(s.as_bytes())`). */
export function sha256Hasher(): Hasher {
    const parts: Uint8Array[] = [];
    const self: Hasher = {
        update(d) {
            parts.push(typeof d === "string" ? utf8(d) : d);
            return self;
        },
        digest: () => sha256(concatBytes(...parts)),
        hex: () => bytesToHex(sha256(concatBytes(...parts))),
    };
    return self;
}

