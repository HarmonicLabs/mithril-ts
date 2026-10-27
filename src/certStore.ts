/**
 * Certificate cache storage, injected into the anchor: OPFS in the extension, memory in tests.
 * Values are the certificate JSON exactly as the aggregator served it.
 */

export interface CertificateStore {
    get(hash: string): Promise<string | null>;
    put(hash: string, json: string): Promise<void>;
}

export class MemoryCertificateStore implements CertificateStore {
    readonly map = new Map<string, string>();
    async get(hash: string): Promise<string | null> {
        return this.map.get(hash) ?? null;
    }
    async put(hash: string, json: string): Promise<void> {
        this.map.set(hash, json);
    }
}

type Dir = FileSystemDirectoryHandle;

/**
 * Certificates in the Origin Private File System, one file per certificate:
 * `<path...>/<hash>.json` (default path `mithril-ts/certs/<network>`; pass another root to keep an existing cache).
 * Writes use `createWritable` (window and worker contexts; Chrome has it everywhere).
 */
export class OpfsCertificateStore implements CertificateStore {
    private dir: Promise<Dir | null> | null = null;
    constructor(private readonly path: string[]) {}

    static forNetwork(network: string, root: string[] = ["mithril-ts", "certs"]): OpfsCertificateStore {
        return new OpfsCertificateStore([...root, network]);
    }

    private root(): Promise<Dir | null> {
        return (this.dir ??= (async () => {
            try {
                const storage = (globalThis as { navigator?: { storage?: { getDirectory?: () => Promise<Dir> } } }).navigator?.storage;
                if (!storage?.getDirectory) return null;
                let d = await storage.getDirectory();
                for (const part of this.path) d = await d.getDirectoryHandle(part, { create: true });
                return d;
            } catch {
                return null;
            }
        })());
    }

    async get(hash: string): Promise<string | null> {
        const d = await this.root();
        if (!d) return null;
        try {
            return await (await (await d.getFileHandle(`${hash}.json`)).getFile()).text();
        } catch {
            return null;
        }
    }

    async put(hash: string, json: string): Promise<void> {
        const d = await this.root();
        if (!d) return;
        const fh = await d.getFileHandle(`${hash}.json`, { create: true });
        const w = await (fh as FileSystemFileHandle & { createWritable(): Promise<FileSystemWritableFileStream> }).createWritable();
        await w.write(json);
        await w.close();
    }
}
