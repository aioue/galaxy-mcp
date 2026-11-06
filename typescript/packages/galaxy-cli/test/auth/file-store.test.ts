import { mkdtemp, readdir, readFile, rm, stat, writeFile, chmod, mkdir, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileStore, type HostRecord } from "../../src/auth/file-store";
import { fakeLogin } from "./support";

let root: string;
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "gxy-fs-")); });
afterEach(async () => { await rm(root, { recursive: true, force: true }); });

function rec(over: Partial<HostRecord> = {}): HostRecord {
  const { token, ...rest } = fakeLogin();
  return { ...rest, storage: "file", token, ...over };
}
const mode = async (p: string) => (await stat(p)).mode & 0o777;

describe("FileStore", () => {
  it("treats a missing or empty file as no logins", async () => {
    const s = new FileStore(join(root, "cfg"));
    expect(await s.list()).toEqual([]);
    await mkdir(join(root, "cfg"));
    await writeFile(s.path, "");
    expect(await s.list()).toEqual([]);
  });

  it("round-trips a record and creates 0700 dir and 0600 file", async () => {
    const s = new FileStore(join(root, "cfg"));
    await s.put(rec({ email: "a@example.org", expiresAt: "2030-01-01T00:00:00.000Z" }));
    expect(await s.get(fakeLogin().baseUrl)).toEqual(rec({ email: "a@example.org", expiresAt: "2030-01-01T00:00:00.000Z" }));
    expect(await mode(s.dir)).toBe(0o700);
    expect(await mode(s.path)).toBe(0o600);
  });

  it("leaves no temp files behind", async () => {
    const s = new FileStore(join(root, "cfg"));
    await s.put(rec());
    await s.put(rec({ username: "bob" }));
    expect(await readdir(s.dir)).toEqual(["hosts.yml"]);
  });

  it("omits the token for keyring storage", async () => {
    const s = new FileStore(join(root, "cfg"));
    await s.put({ ...rec(), storage: "keyring", token: undefined });
    expect(await readFile(s.path, "utf8")).not.toMatch(/token/);
  });

  it("repairs looser permissions with a warning", async () => {
    const warnings: string[] = [];
    const s = new FileStore(join(root, "cfg"), undefined, (m) => warnings.push(m));
    await s.put(rec());
    await chmod(s.path, 0o644);
    await chmod(s.dir, 0o755);
    await s.list();
    expect(await mode(s.path)).toBe(0o600);
    await s.put(rec());
    expect(await mode(s.dir)).toBe(0o700);
    expect(warnings).toHaveLength(2);
  });

  it("fails on a corrupt file, naming it, without overwriting", async () => {
    const s = new FileStore(join(root, "cfg"));
    await mkdir(s.dir);
    await writeFile(s.path, "hosts: [unclosed\n  : :");
    await expect(s.put(rec())).rejects.toThrow(s.path);
    expect(await readFile(s.path, "utf8")).toBe("hosts: [unclosed\n  : :");
    await writeFile(s.path, "hosts:\n  https://x.example:\n    username: 5\n");
    await expect(s.list()).rejects.toThrow(/hosts\.yml is not valid/);
  });

  it("deletes and lists sorted", async () => {
    const s = new FileStore(join(root, "cfg"));
    const b = fakeLogin({ baseUrl: "https://b.example" as never });
    await s.put(rec({ baseUrl: b.baseUrl }));
    await s.put(rec());
    expect((await s.list()).map((r) => r.baseUrl)).toEqual(["https://b.example", "https://galaxy.example.org"]);
    expect(await s.delete(b.baseUrl)).toBe(true);
    expect(await s.delete(b.baseUrl)).toBe(false);
  });
});

describe("FileStore hardening", () => {
  it("writes a 0600 file even under a umask of 000", async () => {
    const s = new FileStore(join(root, "cfg"));
    const old = process.umask(0o000);
    try {
      await s.put(rec());
    } finally {
      process.umask(old);
    }
    expect(await mode(s.path)).toBe(0o600);
    expect(await mode(s.dir)).toBe(0o700);
    expect(await readdir(s.dir)).toEqual(["hosts.yml"]);
  });

  it("replaces a pre-existing 0644 file with a 0600 one and warns", async () => {
    const warnings: string[] = [];
    const s = new FileStore(join(root, "cfg"), undefined, (m) => warnings.push(m));
    await s.put(rec());
    await chmod(s.path, 0o644);
    await s.put(rec({ username: "bob" }));
    expect(await mode(s.path)).toBe(0o600);
    expect((await s.get(fakeLogin().baseUrl))?.username).toBe("bob");
    expect(warnings).toHaveLength(1);
  });

  it("refuses a hosts.yml that is a symlink, reading or writing, and does not touch the target", async () => {
    const s = new FileStore(join(root, "cfg"));
    await mkdir(s.dir, { mode: 0o700 });
    const target = join(root, "elsewhere.yml");
    await writeFile(target, "hosts: {}\n");
    await symlink(target, s.path);
    await expect(s.list()).rejects.toThrow(/is a symbolic link/);
    await expect(s.put(rec())).rejects.toThrow(/is a symbolic link/);
    expect(await readFile(target, "utf8")).toBe("hosts: {}\n");
    expect(await readdir(s.dir)).toEqual(["hosts.yml"]);
  });

  it("refuses a config directory that is a symlink", async () => {
    const real = join(root, "real");
    await mkdir(real, { mode: 0o700 });
    const link = join(root, "cfg");
    await symlink(real, link);
    const s = new FileStore(link);
    await expect(s.list()).rejects.toThrow(/is a symbolic link/);
    await expect(s.put(rec())).rejects.toThrow(/is a symbolic link/);
    expect(await readdir(real)).toEqual([]);
  });

  it("refuses a directory or file owned by someone else", async () => {
    const mine = process.getuid!();
    const s = new FileStore(join(root, "cfg"), undefined, undefined, mine + 1);
    await mkdir(s.dir, { mode: 0o700 });
    await expect(s.list()).rejects.toThrow(/belongs to another user/);
    await expect(s.put(rec())).rejects.toThrow(/belongs to another user/);
    // The same directory is fine for its real owner, and a file of someone else is refused on its own.
    const owner = new FileStore(s.dir, undefined, undefined, mine);
    await owner.put(rec());
    await expect(new FileStore(s.dir, undefined, undefined, mine + 1).list()).rejects.toThrow(/belongs to another user/);
  });

  it("refuses a hosts.yml that is a directory", async () => {
    const s = new FileStore(join(root, "cfg"));
    await mkdir(s.path, { recursive: true });
    await expect(s.list()).rejects.toThrow(/not a regular file/);
  });
});

