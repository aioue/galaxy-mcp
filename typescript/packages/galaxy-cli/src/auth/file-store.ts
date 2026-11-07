import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readdir, rename, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import type { BaseUrl, LoginMethod, LoginSummary, StorageKind } from "./types";

const STALE_TEMP_MS = 60 * 60 * 1000;

/** One host's entry in `hosts.yml`. `token` is present only when `storage` is `file`. */
export interface HostRecord extends LoginSummary {
  token?: string;
}

/**
 * `hosts.yml`: per-host login metadata, plus the token itself when the system keyring is
 * not used. The name, the keying by host and the plaintext fallback are gh's; the key here is
 * the whole base URL (see `normalizeBaseUrl`) because a Galaxy can live under a path prefix.
 *
 * The directory is 0700 and the file 0600, enforced on every write (and repaired, with a
 * warning, when an existing one is looser), because the file can hold a bearer token that
 * anyone able to read it could use as the user. Writes go to a temp file in the same directory
 * (a rename is only atomic within one filesystem), are fsynced, then renamed over the target,
 * so a crash never leaves a half file.
 *
 * Before every read or write the directory and `hosts.yml` are `lstat`ed and refused if they
 * are symlinks or belong to another user: a link planted by someone else in a shared or
 * misconfigured home could redirect our write (and a later chmod) to a file of their choosing,
 * or make us trust content they wrote. The temp file is created exclusively (`wx`, so a
 * planted file or link at that name makes `open` fail rather than being written through) with
 * mode 0600 and then `fchmod`ed, because the umask can mask the creation mode but not the
 * chmod: under a restrictive umask the file would otherwise get a mode narrower than 0600,
 * and the rename carries the temp file's mode over.
 *
 * Read-modify-write is not locked across processes: two simultaneous logins can lose one
 * update. There are no refresh tokens, so this file is only written at login and logout, which
 * are rare and interactive; that is why it is accepted. (gh serialises login, logout and
 * refresh with a lock file.)
 */
export class FileStore {
  constructor(
    readonly dir: string,
    readonly path: string = join(dir, "hosts.yml"),
    private readonly warn: (message: string) => void = () => {},
    /** Who must own the directory and file; undefined (Windows) skips the check. Injectable for tests. */
    private readonly uid: number | undefined = process.getuid?.(),
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
    await this.assertSafe();
    // Mode first, content second: once the file is 0600 nobody else can change it between here
    // and the parse. Whatever they wrote before is still in it, which is why a file owned by
    // another user is refused outright by `assertSafe` and only a loose mode is repaired.
    await this.repairFileMode();
    let text: string;
    try {
      // O_NOFOLLOW closes the gap between the lstat above and this open.
      const fh = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        text = await fh.readFile("utf8");
      } finally {
        await fh.close();
      }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw e;
    }
    if (!text.trim()) return {};
    // A file that cannot be understood is an error, never an empty list: `put` starts from this
    // read, so reading it as empty would overwrite it and lose every other login in it.
    let doc: unknown;
    try {
      doc = parseYaml(text);
    } catch (e) {
      // Not the parser's message: it quotes the offending source line, and in this file that
      // line can be the token. Only where the fault is.
      const pos = (e as { linePos?: { line: number; col: number }[] }).linePos?.[0];
      throw this.corrupt(pos ? `YAML syntax error at line ${pos.line}, column ${pos.col}` : "YAML syntax error");
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

  /**
   * Check every field rather than cast: a hand-edited or truncated file must fail naming the
   * entry, not surface later as a `TypeError`, or as a file login with no token. An `expires_at`
   * that is a string but not a date is let through here and judged by `checkExpiry`, which
   * treats it as expired.
   */
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

  /** The messages built here carry the path and a position, never file content: it holds tokens. */
  private corrupt(why: string): Error {
    return new Error(
      `${this.path} is not valid (${why}). Fix or delete it, then log in again; it has not been modified.`,
    );
  }

  /**
   * The token is written only for `storage: file`, so a record that points at the keyring can
   * never leave a stale plaintext copy behind when a login moves there.
   */
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
    await this.assertSafe();
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    // Again, because the first pass skips what does not exist yet: this one checks the
    // directory `mkdir` just made, or found.
    await this.assertSafe();
    const dirMode = (await stat(this.dir)).mode & 0o777;
    if (dirMode & 0o077) {
      await chmod(this.dir, 0o700);
      this.warn(`${this.dir} was accessible to others (${dirMode.toString(8)}); changed it to 700.`);
    }
    await this.removeStaleTemps();
    const tmp = join(dirname(this.path), `.hosts.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    // 'wx' + 0600 so the secret is never briefly readable under a looser umask. The pid and the
    // random part keep two writers off each other's temp file; `removeStaleTemps` matches the name.
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
    // Make the rename itself durable. Best effort: not every platform can open a directory.
    try {
      const dh = await open(this.dir, "r");
      try {
        await dh.sync();
      } finally {
        await dh.close();
      }
    } catch {
      // Ignored on purpose.
    }
  }

  /**
   * Refuse a config directory or `hosts.yml` that is a symlink, the wrong kind, or someone
   * else's. Only the last component of each path is looked at, so a symlinked parent of the
   * directory is accepted. A loose mode is repaired elsewhere with a warning; ownership is
   * refused here, because a file that belongs to another user is not ours to fix.
   */
  private async assertSafe(): Promise<void> {
    for (const [what, p, kind] of [
      ["directory", this.dir, "dir"],
      ["file", this.path, "file"],
    ] as const) {
      let st;
      try {
        st = await lstat(p);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw e;
      }
      const problem = st.isSymbolicLink()
        ? "is a symbolic link"
        : (kind === "dir" ? !st.isDirectory() : !st.isFile())
          ? `is not a regular ${what}`
          : this.uid !== undefined && st.uid !== this.uid
            ? "belongs to another user"
            : undefined;
      if (problem) {
        throw new Error(`Refusing to use ${p}: it ${problem}. It would hold your login tokens, so it must be a plain ${what} you own. Remove it or point GXY_CONFIG_DIR somewhere else.`);
      }
    }
  }

  /**
   * A write killed between creating its temp file and the rename leaves `.hosts.*.tmp`, which
   * may hold a token. Remove the ones old enough that no live write can own them. Best effort.
   */
  private async removeStaleTemps(): Promise<void> {
    try {
      const cutoff = Date.now() - STALE_TEMP_MS;
      for (const name of await readdir(this.dir)) {
        if (!/^\.hosts\..+\.tmp$/.test(name)) continue;
        const p = join(this.dir, name);
        const st = await lstat(p);
        if (st.isFile() && st.mtimeMs < cutoff) await unlink(p);
      }
    } catch {
      // Cleaning up is never worth failing a login for.
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
