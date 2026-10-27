/**
 * POSIX ustar, enough for Mithril archives: a deterministic writer (regular files only, mode 0644, owner 0/0,
 * mtime 0, no user or group names, so two runs over the same files give the same bytes), a reader for a whole
 * archive in memory, and a streaming reader for archives too large to hold (snapshots are gigabytes).
 */

const BLOCK = 512;
const enc = new TextEncoder();
const dec = new TextDecoder();

function octal(value: number, width: number): string {
    // width - 1 octal digits followed by NUL
    const s = value.toString(8);
    if (s.length > width - 1) throw new Error(`tar: value ${value} does not fit ${width} bytes`);
    return s.padStart(width - 1, "0") + "\0";
}

function header(name: string, size: number): Uint8Array {
    let nameField = name;
    let prefix = "";
    if (enc.encode(name).length > 100) {
        const cut = name.lastIndexOf("/", 155);
        if (cut <= 0 || enc.encode(name.slice(cut + 1)).length > 100) throw new Error(`tar: name too long: ${name}`);
        prefix = name.slice(0, cut);
        nameField = name.slice(cut + 1);
    }
    const h = new Uint8Array(BLOCK);
    const put = (off: number, s: string) => h.set(enc.encode(s), off);
    put(0, nameField);
    put(100, octal(0o644, 8));
    put(108, octal(0, 8));
    put(116, octal(0, 8));
    put(124, octal(size, 12));
    put(136, octal(0, 12));
    put(148, "        "); // checksum placeholder
    put(156, "0");
    put(257, "ustar\0");
    put(263, "00");
    put(345, prefix);
    let sum = 0;
    for (const b of h) sum += b;
    put(148, sum.toString(8).padStart(6, "0") + "\0 ");
    return h;
}

export type TarEntry = { name: string; data: Uint8Array };

/** A complete tar archive (entries in the given order, then two zero blocks). */
export function buildTar(entries: TarEntry[]): Uint8Array {
    let total = 2 * BLOCK;
    for (const e of entries) total += BLOCK + Math.ceil(e.data.length / BLOCK) * BLOCK;
    const out = new Uint8Array(total);
    let o = 0;
    for (const e of entries) {
        out.set(header(e.name, e.data.length), o);
        o += BLOCK;
        out.set(e.data, o);
        o += Math.ceil(e.data.length / BLOCK) * BLOCK;
    }
    return out;
}

function field(b: Uint8Array, off: number, len: number): string {
    const s = b.subarray(off, off + len);
    const z = s.indexOf(0);
    return dec.decode(z >= 0 ? s.subarray(0, z) : s);
}

/** A parsed header block; null at the end-of-archive marker. */
interface Header { name: string; size: number; type: string }
function parseHeader(h: Uint8Array): Header | null {
    if (h.every((b) => b === 0)) return null;
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 32 : h[i]!;
    const stored = parseInt(field(h, 148, 8).trim() || "0", 8);
    if (stored !== sum) throw new Error("tar: header checksum mismatch");
    const name = field(h, 0, 100);
    const prefix = field(h, 345, 155);
    // sizes above 8 GiB use the GNU base-256 form (high bit of the first byte set)
    const sizeField = h.subarray(124, 136);
    let size: number;
    if (sizeField[0]! & 0x80) { size = 0; for (let i = 1; i < 12; i++) size = size * 256 + sizeField[i]!; }
    else size = parseInt(field(h, 124, 12).trim() || "0", 8);
    return { name: prefix ? `${prefix}/${name}` : name, size, type: String.fromCharCode(h[156]!) };
}

/** Entries of an uncompressed tar archive held in memory (regular files only). */
export function readTar(tar: Uint8Array): TarEntry[] {
    const out: TarEntry[] = [];
    let o = 0;
    let longName: string | null = null;
    while (o + BLOCK <= tar.length) {
        const h = parseHeader(tar.subarray(o, o + BLOCK));
        if (!h) break;
        o += BLOCK;
        const data = tar.subarray(o, o + h.size);
        if (h.type === "L") longName = field(data, 0, data.length); // GNU long name for the next entry
        else if (h.type === "0" || h.type === "\0") { out.push({ name: longName ?? h.name, data: data.slice() }); longName = null; }
        else longName = null;
        o += Math.ceil(h.size / BLOCK) * BLOCK;
    }
    return out;
}

export interface TarStreamEvents {
    /** A regular file starts; return false to skip its bytes. */
    entry(name: string, size: number): boolean | void;
    /** The next bytes of the current file. */
    data(chunk: Uint8Array): void;
    /** The current file is complete. */
    end(name: string): void;
}

/**
 * Streaming tar reader: push decompressed bytes in any chunk sizes with `push`, then call `finish`. Only regular
 * files reach the callbacks; directories and other entries are skipped. Holds at most one 512-byte block.
 */
export class TarStreamReader {
    private buf = new Uint8Array(BLOCK);
    private bufLen = 0;
    private state: "header" | "data" | "pad" | "done" = "header";
    private remaining = 0;
    private padding = 0;
    private current: { name: string; keep: boolean; regular: boolean; longName: boolean } | null = null;
    private longNameBytes: Uint8Array[] = [];
    private pendingLongName: string | null = null;

    constructor(private readonly on: TarStreamEvents) {}

    push(chunk: Uint8Array): void {
        let i = 0;
        while (i < chunk.length && this.state !== "done") {
            if (this.state === "header") {
                const take = Math.min(BLOCK - this.bufLen, chunk.length - i);
                this.buf.set(chunk.subarray(i, i + take), this.bufLen);
                this.bufLen += take;
                i += take;
                if (this.bufLen < BLOCK) return;
                this.bufLen = 0;
                const h = parseHeader(this.buf);
                if (!h) { this.state = "done"; return; }
                const regular = h.type === "0" || h.type === "\0";
                const isLongName = h.type === "L";
                const name = this.pendingLongName ?? h.name;
                if (!isLongName) this.pendingLongName = null;
                const keep = regular ? this.on.entry(name, h.size) !== false : false;
                this.current = { name, keep, regular, longName: isLongName };
                this.remaining = h.size;
                this.padding = (BLOCK - (h.size % BLOCK)) % BLOCK;
                this.state = h.size > 0 ? "data" : this.padding > 0 ? "pad" : "header";
                if (h.size === 0) this.finishEntry();
            } else if (this.state === "data") {
                const take = Math.min(this.remaining, chunk.length - i);
                const part = chunk.subarray(i, i + take);
                if (this.current!.longName) this.longNameBytes.push(part.slice());
                else if (this.current!.keep) this.on.data(part);
                this.remaining -= take;
                i += take;
                if (this.remaining === 0) { this.finishEntry(); this.state = this.padding > 0 ? "pad" : "header"; }
            } else {
                const take = Math.min(this.padding, chunk.length - i);
                this.padding -= take;
                i += take;
                if (this.padding === 0) this.state = "header";
            }
        }
    }

    private finishEntry(): void {
        const c = this.current!;
        if (c.longName) {
            const all = new Uint8Array(this.longNameBytes.reduce((n, b) => n + b.length, 0));
            let o = 0;
            for (const b of this.longNameBytes) { all.set(b, o); o += b.length; }
            this.pendingLongName = field(all, 0, all.length);
            this.longNameBytes = [];
        } else if (c.regular && c.keep) this.on.end(c.name);
        this.current = null;
    }

    /** True once the end-of-archive marker was read; throws when the stream stopped inside an entry. */
    finish(): boolean {
        if (this.state === "data" || this.state === "pad" || this.bufLen > 0) throw new Error("tar: archive ends inside an entry");
        return this.state === "done";
    }
}
