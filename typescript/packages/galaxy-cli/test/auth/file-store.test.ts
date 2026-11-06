import { mkdtemp, readdir, readFile, rm, stat, writeFile, chmod, mkdir } from "node:fs/promises";
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
