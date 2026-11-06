import { chmod, mkdir, mkdtemp, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FileStore, type HostRecord } from "../../src/auth/file-store";
import { KeyringStore } from "../../src/auth/keyring-store";
import { CombinedStore, createCredentialStore } from "../../src/auth/store";
import { FakeKeyring, fakeLogin } from "./support";

let root: string;
let kr: FakeKeyring;
let file: FileStore;
let store: CombinedStore;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "gxy-sh-"));
  kr = new FakeKeyring();
  file = new FileStore(join(root, "cfg"));
  store = new CombinedStore(file, new KeyringStore(kr, 30));
});
afterEach(async () => { await rm(root, { recursive: true, force: true }); });
const { baseUrl } = fakeLogin();

describe("CombinedStore.get", () => {
  it("says so when the record points at the keyring and the secret is gone (not 'no login')", async () => {
    await store.put(fakeLogin());
    kr.data.clear();
    await expect(store.get(baseUrl)).rejects.toMatchObject({ kind: "not_logged_in", message: expect.stringContaining("keyring has none") });
  });
  it("delete and list work without reading the secret", async () => {
    await store.put(fakeLogin());
    kr.mode = "throw";
    expect((await store.list()).map((s) => s.baseUrl)).toEqual([baseUrl]);
    await expect(store.delete(baseUrl)).rejects.toThrow(/may remain/);
    expect(await store.list()).toEqual([]);
  });
});

describe("CombinedStore.put", () => {
  it("takes the new keyring entry back out when the file write fails", async () => {
    vi.spyOn(file, "put").mockRejectedValueOnce(new Error("disk full"));
    await expect(store.put(fakeLogin())).rejects.toThrow("disk full");
    expect(kr.data.size).toBe(0);
  });
  it("leaves the keyring alone when the file write fails and a record already points at that entry", async () => {
    await store.put(fakeLogin());
    vi.spyOn(file, "put").mockRejectedValueOnce(new Error("disk full"));
    await expect(store.put(fakeLogin({ token: "FAKE-TOKEN-2" }))).rejects.toThrow("disk full");
    expect(kr.data.size).toBe(1);
  });
});

describe("createCredentialStore honours GXY_NO_KEYRING (the one factory)", () => {
  const env = (extra: Record<string, string> = {}) => ({ GXY_CONFIG_DIR: join(root, "env-cfg"), ...extra });
  it("stores in the file, with a warning, when GXY_NO_KEYRING=1", async () => {
    const s = createCredentialStore(env({ GXY_NO_KEYRING: "1" }), root, () => {});
    const res = await s.put(fakeLogin());
    expect(res.storage).toBe("file");
    expect(res.warning).toMatch(/No system keyring/);
    expect((await s.get(baseUrl))?.token).toBe(fakeLogin().token);
  });
  it("GXY_NO_KEYRING=0 does not turn the keyring off", async () => {
    // With the keyring on, a put reaches for the native backend; in a test it is unreachable or
    // absent, and either way the store, not the env var, decides. We only check it is not the disabled one.
    const s = createCredentialStore(env({ GXY_NO_KEYRING: "0" }), root, () => {});
    const res = await s.put(fakeLogin(), { requireKeyring: true }).catch((e: Error) => e.message);
    expect(String(typeof res === "string" ? res : "")).not.toContain("disabled by GXY_NO_KEYRING");
  });
});

describe("FileStore hardening", () => {
  const rec = (): HostRecord => { const { token, ...r } = fakeLogin(); return { ...r, storage: "file", token }; };

  it("repairs a loose file mode before parsing, even when the content then fails to parse", async () => {
    const dir = join(root, "cfg");
    await mkdir(dir, { mode: 0o700 });
    const p = join(dir, "hosts.yml");
    await writeFile(p, "hosts: [unclosed", { mode: 0o666 });
    await chmod(p, 0o666);
    const warnings: string[] = [];
    const s = new FileStore(dir, p, (m) => warnings.push(m));
    await expect(s.list()).rejects.toThrow(/not valid/);
    expect((await stat(p)).mode & 0o777).toBe(0o600);
    expect(warnings.join()).toMatch(/changed it to 600/);
  });

  it("removes stale .hosts.*.tmp files older than an hour, and only those", async () => {
    const dir = join(root, "cfg");
    await mkdir(dir, { mode: 0o700 });
    const old = join(dir, ".hosts.123.abc.tmp");
    const fresh = join(dir, ".hosts.456.def.tmp");
    const other = join(dir, "notes.tmp");
    for (const f of [old, fresh, other]) await writeFile(f, "x");
    const twoHoursAgo = new Date(Date.now() - 2 * 3600_000);
    await utimes(old, twoHoursAgo, twoHoursAgo);
    await utimes(other, twoHoursAgo, twoHoursAgo);
    await new FileStore(dir).put(rec());
    expect((await readdir(dir)).sort()).toEqual([".hosts.456.def.tmp", "hosts.yml", "notes.tmp"]);
  });
});
