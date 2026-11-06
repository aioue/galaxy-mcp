import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import type { BaseUrl, LoginMethod, LoginSummary, StorageKind } from "./types";

/** One host's entry in `hosts.yml`. `token` is present only when `storage` is `file`. */
export interface HostRecord extends LoginSummary {
  token?: string;
}

/**
 * `hosts.yml`: per-host login metadata, plus the token itself when the system keyring is
 * not used. The directory is 0700 and the file 0600, enforced on every write (and repaired,
 * with a warning, when an existing one is looser). Writes go to a temp file in the same
 * directory, are fsynced, then renamed over the target, so a crash never leaves a half file.
 *
 * Read-modify-write is not locked across processes: two simultaneous logins can lose one
 * update. Logins are rare and interactive, so that is accepted.
 */
export class FileStore {
  constructor(
    readonly dir: string,
    readonly path: string = join(dir, "hosts.yml"),
    private readonly warn: (message: string) => void = () => {},
  ) {}

  async get(baseUrl: BaseUrl): Promise<HostRecord | null> {
    return (await this.readAll())[baseUrl] ?? null;
  }

  async list(): Promise<HostRecord[]> {
    const all = await this.readAll();
    return Object.keys(all).sort().map((k) => all[k as BaseUrl]!);
  }

  async put(record: HostRecord): Promise<void> {
    const all = await this.readAll();
    all[record.baseUrl] = record;
    await this.writeAll(all);
  }

  async delete(baseUrl: BaseUrl): Promise<boolean> {
    const all = await this.readAll();
    if (!(baseUrl in all)) return false;
    delete all[baseUrl];
    await this.writeAll(all);
    return true;
  }

  private async readAll(): Promise<Record<BaseUrl, HostRecord>> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw e;
    }
    await this.repairFileMode();
    if (!text.trim()) return {};
    let doc: unknown;
    try {
      doc = parseYaml(text);
    } catch (e) {
      throw this.corrupt(e instanceof Error ? e.message : String(e));
    }
    if (doc === null || doc === undefined) return {};
    const hosts = isObject(doc) ? doc.hosts : undefined;
    if (hosts === null || hosts === undefined) {
      if (isObject(doc)) return {};
      throw this.corrupt("expected a mapping");
    }
    if (!isObject(hosts)) throw this.corrupt("`hosts` is not a mapping");
    const out: Record<string, HostRecord> = {};
    for (const [url, raw] of Object.entries(hosts)) {
      out[url] = this.decode(url, raw);
    }
    return out as Record<BaseUrl, HostRecord>;
  }

  private decode(url: string, raw: unknown): HostRecord {
    if (!isObject(raw)) throw this.corrupt(`entry for ${url} is not a mapping`);
    const str = (k: string): string => {
      const v = raw[k];
      if (typeof v !== "string" || !v) throw this.corrupt(`entry for ${url} has no \`${k}\``);
      return v;
    };
    const storage = str("storage");
    if (storage !== "keyring" && storage !== "file") throw this.corrupt(`entry for ${url} has unknown storage`);
    const method = str("method");
    if (method !== "device" && method !== "pasted") throw this.corrupt(`entry for ${url} has unknown method`);
    const scopes = raw.scopes ?? [];
    if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== "string")) {
      throw this.corrupt(`entry for ${url} has invalid scopes`);
    }
    const expires = raw.expires_at;
    if (expires !== null && expires !== undefined && typeof expires !== "string") {
      throw this.corrupt(`entry for ${url} has invalid expires_at`);
    }
    const rec: HostRecord = {
      baseUrl: url as BaseUrl,
      username: str("username"),
      method: method as LoginMethod,
      scopes: scopes as string[],
      expiresAt: expires ?? null,
      obtainedAt: str("obtained_at"),
      storage: storage as StorageKind,
    };
    if (typeof raw.email === "string") rec.email = raw.email;
    if (storage === "file") rec.token = str("token");
    return rec;
  }

  private corrupt(why: string): Error {
    return new Error(
      `${this.path} is not valid (${why}). Fix or delete it, then log in again; it has not been modified.`,
    );
  }

  private encode(all: Record<BaseUrl, HostRecord>): string {
    const hosts: Record<string, unknown> = {};
    for (const [url, r] of Object.entries(all)) {
      hosts[url] = {
        username: r.username,
        ...(r.email !== undefined ? { email: r.email } : {}),
        method: r.method,
        scopes: r.scopes,
        expires_at: r.expiresAt,
        obtained_at: r.obtainedAt,
        storage: r.storage,
        ...(r.storage === "file" && r.token !== undefined ? { token: r.token } : {}),
      };
    }
    return stringifyYaml({ hosts });
  }

  private async writeAll(all: Record<BaseUrl, HostRecord>): Promise<void> {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const dirMode = (await stat(this.dir)).mode & 0o777;
    if (dirMode & 0o077) {
      await chmod(this.dir, 0o700);
      this.warn(`${this.dir} was accessible to others (${dirMode.toString(8)}); changed it to 700.`);
    }
    const tmp = join(dirname(this.path), `.hosts.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    // 'wx' + 0600 so the secret is never briefly readable under a looser umask.
    const fh = await open(tmp, "wx", 0o600);
    try {
      await fh.writeFile(this.encode(all), "utf8");
      await fh.chmod(0o600);
      await fh.sync();
    } catch (e) {
      await fh.close().catch(() => {});
      await unlink(tmp).catch(() => {});
      throw e;
    }
    await fh.close();
    try {
      await rename(tmp, this.path);
    } catch (e) {
      await unlink(tmp).catch(() => {});
      throw e;
    }
  }

  private async repairFileMode(): Promise<void> {
    try {
      const mode = (await stat(this.path)).mode & 0o777;
      if (mode & 0o077) {
        await chmod(this.path, 0o600);
        this.warn(`${this.path} was readable by others (${mode.toString(8)}); changed it to 600.`);
      }
    } catch {
      // Not ours to fix (read-only mount, another owner): reading still works.
    }
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
