import { chmod, mkdir, readdir, readFile, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileStore, type HostRecord } from "../../src/auth/file-store";
import { HOST, OTHER, fakeLogin, useTempDir } from "./harness";

const tmp = useTempDir("gxy-fs-");
const dirOf = () => join(tmp.path, "cfg");

function rec(over: Partial<HostRecord> = {}): HostRecord {
  const { token, ...rest } = fakeLogin();
  return { ...rest, storage: "file", token, ...over };
}
const mode = async (p: string) => (await stat(p)).mode & 0o777;

describe("reading and writing", () => {
  it("treats a missing or empty file as no logins", async () => {
    const s = new FileStore(dirOf());
    expect(await s.list()).toEqual([]);
    await mkdir(s.dir);
    await writeFile(s.path, "");
    expect(await s.list()).toEqual([]);
  });

  it("round-trips a record, with its optional fields", async () => {
    const s = new FileStore(dirOf());
    const r = rec({ email: "a@example.org", expiresAt: "2030-01-01T00:00:00.000Z" });
    await s.put(r);
    expect(await s.get(HOST)).toEqual(r);
  });

  it("round-trips a record with no expiry", async () => {
    const s = new FileStore(dirOf());
    await s.put(rec({ expiresAt: null }));
    expect((await s.get(HOST))?.expiresAt).toBeNull();
  });

  it("omits the token from the file for keyring storage", async () => {
    const s = new FileStore(dirOf());
    await s.put({ ...rec(), storage: "keyring", token: undefined });
    expect(await readFile(s.path, "utf8")).not.toMatch(/token/);
  });

  it("deletes, and lists sorted by URL", async () => {
    const s = new FileStore(dirOf());
    await s.put(rec({ baseUrl: OTHER }));
    await s.put(rec());
    expect((await s.list()).map((r) => r.baseUrl)).toEqual([HOST, OTHER]);
    expect(await s.delete(OTHER)).toBe(true);
    expect(await s.delete(OTHER)).toBe(false);
    expect((await s.list()).map((r) => r.baseUrl)).toEqual([HOST]);
  });
});

describe("permissions", () => {
  it("creates a 0700 directory and a 0600 file, and leaves no temp file", async () => {
    const s = new FileStore(dirOf());
    await s.put(rec());
    await s.put(rec({ username: "bob" }));
    expect(await mode(s.dir)).toBe(0o700);
    expect(await mode(s.path)).toBe(0o600);
    expect(await readdir(s.dir)).toEqual(["hosts.yml"]);
  });

  it("still creates the directory 0700 under a umask of 000", async () => {
    const s = new FileStore(dirOf());
    const old = process.umask(0o000);
    try {
      await s.put(rec());
    } finally {
      process.umask(old);
    }
    expect(await mode(s.dir)).toBe(0o700);
  });

  // Under 0277 a new file would be 0400, so only the explicit chmod brings it to 0600 (under 000
  // the creation mode alone would already be right). The directory exists first: 0277 would
  // otherwise make it unwritable.
  it("still writes the file 0600 under a restrictive umask", async () => {
    const s = new FileStore(dirOf());
    await mkdir(s.dir, { mode: 0o700 });
    const old = process.umask(0o277);
    try {
      await s.put(rec());
    } finally {
      process.umask(old);
    }
    expect(await mode(s.path)).toBe(0o600);
  });

  it("repairs a looser file on read and a looser directory on write, warning each time", async () => {
    const warnings: string[] = [];
    const s = new FileStore(dirOf(), undefined, (m) => warnings.push(m));
    await s.put(rec());
    await chmod(s.path, 0o644);
    await chmod(s.dir, 0o755);
    await s.list();
    expect(await mode(s.path)).toBe(0o600);
    await s.put(rec());
    expect(await mode(s.dir)).toBe(0o700);
    expect(warnings.some((w) => /readable by others.*600/.test(w))).toBe(true);
    expect(warnings.some((w) => /accessible to others.*700/.test(w))).toBe(true);
  });

  it("repairs a loose file mode before parsing, even when the content then fails to parse", async () => {
    await mkdir(dirOf(), { mode: 0o700 });
    const warnings: string[] = [];
    const s = new FileStore(dirOf(), undefined, (m) => warnings.push(m));
    await writeFile(s.path, "hosts: [unclosed");
    await chmod(s.path, 0o666);
    await expect(s.list()).rejects.toThrow(/not valid/);
    expect(await mode(s.path)).toBe(0o600);
    expect(warnings.join()).toMatch(/changed it to 600/);
  });
});

describe("refusing what is not a plain file or directory of ours", () => {
  it("refuses a hosts.yml that is a symlink, reading or writing, and does not touch the target", async () => {
    const s = new FileStore(dirOf());
    await mkdir(s.dir, { mode: 0o700 });
    const target = join(tmp.path, "elsewhere.yml");
    await writeFile(target, "hosts: {}\n");
    await symlink(target, s.path);
    await expect(s.list()).rejects.toThrow(/is a symbolic link/);
    await expect(s.put(rec())).rejects.toThrow(/is a symbolic link/);
    expect(await readFile(target, "utf8")).toBe("hosts: {}\n");
    expect(await readdir(s.dir)).toEqual(["hosts.yml"]);
  });

  it("refuses a config directory that is a symlink", async () => {
    const real = join(tmp.path, "real");
    await mkdir(real, { mode: 0o700 });
    const link = join(tmp.path, "link");
    await symlink(real, link);
    const s = new FileStore(link);
    await expect(s.list()).rejects.toThrow(/is a symbolic link/);
    await expect(s.put(rec())).rejects.toThrow(/is a symbolic link/);
    expect(await readdir(real)).toEqual([]);
  });

  it("refuses a directory or file owned by someone else", async () => {
    // chown needs root, so the owner the store expects is the thing that differs.
    const mine = process.getuid!();
    const s = new FileStore(dirOf(), undefined, undefined, mine + 1);
    await mkdir(s.dir, { mode: 0o700 });
    await expect(s.list()).rejects.toThrow(/belongs to another user/);
    await expect(s.put(rec())).rejects.toThrow(/belongs to another user/);
    // The same directory is fine for its real owner, and a file of someone else is refused on its own.
    await new FileStore(s.dir, undefined, undefined, mine).put(rec());
    await expect(new FileStore(s.dir, undefined, undefined, mine + 1).list()).rejects.toThrow(/belongs to another user/);
  });

  it("refuses a hosts.yml that is a directory", async () => {
    const s = new FileStore(dirOf());
    await mkdir(s.path, { recursive: true });
    await expect(s.list()).rejects.toThrow(/not a regular file/);
  });

  it("skips the ownership check when there is no uid to compare (Windows)", async () => {
    const s = new FileStore(dirOf(), undefined, undefined, undefined);
    await s.put(rec());
    expect(await s.list()).toHaveLength(1);
  });
});

describe("a corrupt hosts.yml", () => {
  // Each of these holds the token in a field the parser may quote, so an error that repeated
  // the file's text would repeat the token.
  const SECRET = "FAKE-SECRET-TOKEN-123";
  const entry = (over: Record<string, string> = {}) => {
    const fields: Record<string, string> = {
      username: "aioue",
      method: "device",
      scopes: "[]",
      expires_at: "null",
      obtained_at: '"2026-11-06T10:44:00.000Z"',
      storage: "file",
      token: SECRET,
      ...over,
    };
    return `hosts:\n  ${HOST}:\n${Object.entries(fields).map(([k, v]) => `    ${k}: ${v}\n`).join("")}`;
  };

  async function readError(text: string): Promise<{ s: FileStore; message: string }> {
    await mkdir(dirOf(), { recursive: true });
    const s = new FileStore(dirOf());
    await writeFile(s.path, text, { mode: 0o600 });
    const e = await s.list().then(
      () => undefined,
      (x: unknown) => x as Error,
    );
    if (!e) throw new Error("expected the corrupt file to be refused");
    return { s, message: e.message };
  }

  it("names the file and the line and column of a syntax error, and nothing from its content", async () => {
    const { s, message } = await readError(`hosts:\n  https://a.example:\n    token: ${SECRET} : bad\n    username: [unclosed\n`);
    expect(message).toContain(s.path);
    expect(message).toMatch(/line \d+, column \d+/);
    expect(message).not.toContain(SECRET);
    expect(message).not.toContain("unclosed");
  });

  it.each([
    ["the top level is a list", `- ${SECRET}\n`],
    ["the top level is text", `${SECRET}\n`],
    ["hosts is not a mapping", `hosts: ${SECRET}\n`],
    ["an entry is not a mapping", `hosts:\n  ${HOST}: ${SECRET}\n`],
    ["scopes is not a list", entry({ scopes: "5" })],
    ["scopes holds a non-string", entry({ scopes: "[1]" })],
    ["expires_at is not a string", entry({ expires_at: "5" })],
    ["a required field is missing", entry({ username: '""' })],
    ["the storage is unknown", entry({ storage: SECRET })],
    ["the method is unknown", entry({ method: SECRET })],
    ["a file-stored entry has no token", entry({ token: '""' })],
  ])("names only the file when %s", async (_what, text) => {
    const { s, message } = await readError(text);
    expect(message).toContain(s.path);
    expect(message).toMatch(/not valid/);
    expect(message).not.toContain(SECRET);
  });

  it("does not overwrite it on a put, and a put names it too", async () => {
    const text = "hosts: [unclosed\n  : :";
    const { s } = await readError(text);
    await expect(s.put(rec())).rejects.toThrow(s.path);
    expect(await readFile(s.path, "utf8")).toBe(text);
  });

  it("reads a file with no hosts key as no logins", async () => {
    await mkdir(dirOf(), { recursive: true });
    const s = new FileStore(dirOf());
    await writeFile(s.path, "other: 1\n", { mode: 0o600 });
    expect(await s.list()).toEqual([]);
  });
});

describe("stale temp files", () => {
  it("removes .hosts.*.tmp files older than an hour on a write, and only those", async () => {
    await mkdir(dirOf(), { mode: 0o700 });
    const old = join(dirOf(), ".hosts.123.abc.tmp");
    const fresh = join(dirOf(), ".hosts.456.def.tmp");
    const other = join(dirOf(), "notes.tmp");
    for (const f of [old, fresh, other]) await writeFile(f, "x");
    const twoHoursAgo = new Date(Date.now() - 2 * 3600_000);
    await utimes(old, twoHoursAgo, twoHoursAgo);
    await utimes(other, twoHoursAgo, twoHoursAgo);
    await new FileStore(dirOf()).put(rec());
    expect((await readdir(dirOf())).sort()).toEqual([".hosts.456.def.tmp", "hosts.yml", "notes.tmp"]);
  });
});
