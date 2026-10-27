/**
 * JSON helpers for Mithril messages.
 *
 * Mithril encodes keys and signatures as "JSON hex": the hex of a serde_json document. Stakes are
 * u64 and can exceed 2^53 (mainnet total stake is about 4e15 today), so integers are parsed without
 * precision loss: integers outside the safe range come back as bigint. This uses the JSON.parse
 * reviver's source-text argument (Bun, Chrome 114+, Firefox 135+). Where a runtime lacks it, an
 * unsafe integer is an error rather than a silently rounded number.
 */

import { bytesToHex, hexToBytes, utf8 } from "./bytes";

type ReviverContext = { source?: string };

/** Parse JSON text; integers that do not fit a double exactly come back as bigint. */
export function parseJsonLossless(text: string): unknown {
    return JSON.parse(text, function (this: unknown, _key: string, value: unknown, ctx?: ReviverContext) {
        if (typeof value === "number" && Number.isInteger(value) && !Number.isSafeInteger(value)) {
            const src = ctx?.source;
            if (src === undefined) throw new Error("JSON: integer beyond 2^53 and this runtime has no JSON.parse source-text access");
            if (/^-?\d+$/.test(src)) return BigInt(src);
        }
        return value;
    } as (key: string, value: unknown) => unknown);
}

/** JSON.stringify that writes bigint values as plain JSON numbers (inverse of parseJsonLossless). */
export function stringifyJsonLossless(value: unknown, space?: number): string {
    const raw = (JSON as unknown as { rawJSON?: (s: string) => unknown }).rawJSON;
    if (raw) return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? raw(v.toString()) : v), space);
    // Fallback without JSON.rawJSON: mark bigints, then strip the quotes around the marks.
    const MARK = "\u0000big:";
    const s = JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? MARK + v.toString() : v), space);
    return s.replace(/"\\u0000big:(-?\d+)"/g, "$1");
}

/** Decode a "JSON hex" string (hex of a UTF-8 JSON document). */
export function decodeJsonHex(hex: string): unknown {
    return parseJsonLossless(new TextDecoder("utf-8", { fatal: true }).decode(hexToBytes(hex)));
}

/** Encode a canonical JSON document (already serialized) as "JSON hex". */
export function encodeJsonHex(json: string): string {
    return bytesToHex(utf8(json));
}

/** A u64 from a JSON value (number or bigint), or throw. */
export function asU64(v: unknown, label: string): bigint {
    if (typeof v === "bigint") {
        if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new Error(`${label}: out of u64 range`);
        return v;
    }
    if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
    throw new Error(`${label}: not an unsigned integer`);
}

/** A JSON array of bytes (serde's Vec<u8>/[u8; N] form) of the given length, or throw. */
export function asByteArray(v: unknown, len: number | null, label: string): Uint8Array {
    if (!Array.isArray(v)) throw new Error(`${label}: not a byte array`);
    if (len != null && v.length !== len) throw new Error(`${label}: ${v.length} bytes, want ${len}`);
    const out = new Uint8Array(v.length);
    for (let i = 0; i < v.length; i++) {
        const n = v[i];
        if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 255) throw new Error(`${label}[${i}]: not a byte`);
        out[i] = n;
    }
    return out;
}

/** serde_json form of a byte array: `[1,2,3]`. */
export function byteArrayJson(b: Uint8Array): string {
    return `[${Array.from(b).join(",")}]`;
}

export function isObject(v: unknown): v is Record<string, unknown> {
    return v != null && typeof v === "object" && !Array.isArray(v);
}
