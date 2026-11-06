import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileStore } from "../../src/auth/file-store";
import { KeyringStore } from "../../src/auth/keyring-store";
import { CombinedStore } from "../../src/auth/store";
import { FakeKeyring, fakeLogin } from "./support";

let root: string;
let kr: FakeKeyring;
let file: FileStore;
let store: CombinedStore;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "gxy-st-"));
  kr = new FakeKeyring();
  file = new FileStore(join(root, "cfg"));
  store = new CombinedStore(file, new KeyringStore(kr, 50));
});
afterEach(async () => { await rm(root, { recursive: true, force: true }); });

const { baseUrl } = fakeLogin();

describe("CombinedStore", () => {
  it("puts the token in the keyring, not the file", async () => {
    expect(await store.put(fakeLogin())).toEqual({ storage: "keyring" });
    expect(await readFile(file.path, "utf8")).not.toContain("FAKE-TOKEN-1");
    expect(kr.data.get(`gxy:${baseUrl}|alice`)).toBe("FAKE-TOKEN-1");
    expect(await store.get(baseUrl)).toEqual({ ...fakeLogin(), storage: "keyring" });
    expect(JSON.stringify(await store.list())).not.toContain("FAKE-TOKEN-1");
  });

  it.each(["throw", "hang", "lossy"] as const)("falls back to the file with a warning when the keyring is %s", async (mode) => {
    kr.mode = mode;
    const res = await store.put(fakeLogin());
    expect(res.storage).toBe("file");
    expect(res.warning).toBe(`No system keyring available; token saved in plain text at ${file.path} (readable only by you)`);
    expect(await store.get(baseUrl)).toEqual({ ...fakeLogin(), storage: "file" });
  });

  it("insecureStorage forces the file without a warning and never touches the keyring", async () => {
    expect(await store.put(fakeLogin(), { insecureStorage: true })).toEqual({ storage: "file" });
    expect(kr.data.size).toBe(0);
  });

  it("removes the plaintext token when a later put uses the keyring", async () => {
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(await readFile(file.path, "utf8")).toContain("FAKE-TOKEN-1");
    await store.put(fakeLogin({ token: "FAKE-TOKEN-2" }));
    expect(await readFile(file.path, "utf8")).not.toMatch(/FAKE-TOKEN|token:/);
    expect((await store.get(baseUrl))?.token).toBe("FAKE-TOKEN-2");
  });

  it("removes the keyring entry when a later put goes to the file", async () => {
    await store.put(fakeLogin());
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(kr.data.size).toBe(0);
  });

  it("delete removes from both places", async () => {
    await store.put(fakeLogin());
    expect(await store.delete(baseUrl)).toBe(true);
    expect(kr.data.size).toBe(0);
    expect(await store.get(baseUrl)).toBeNull();
    expect(await store.delete(baseUrl)).toBe(false);
  });

  it("delete still removes the metadata when the keyring is down, and says the secret may remain", async () => {
    await store.put(fakeLogin());
    kr.mode = "throw";
    await expect(store.delete(baseUrl)).rejects.toThrow(/may remain/);
    expect(await file.list()).toEqual([]);
  });

  it("delete does not trust a keyring that says it deleted but still holds the secret", async () => {
    await store.put(fakeLogin());
    kr.mode = "undeletable";
    await expect(store.delete(baseUrl)).rejects.toThrow(/may remain/);
    expect(await file.list()).toEqual([]);
  });

  it("with requireKeyring and no keyring, stores nothing and says how to opt in", async () => {
    kr.mode = "throw";
    await expect(store.put(fakeLogin(), { requireKeyring: true })).rejects.toThrow(/--insecure-storage.*hosts\.yml.*GALAXY_API_KEY/s);
    expect(await file.list()).toEqual([]);
    // Without the requirement the file fallback still works, with its warning.
    const put = await store.put(fakeLogin());
    expect(put.storage).toBe("file");
    expect(put.warning).toBeDefined();
  });

  it("with requireKeyring and --insecure-storage, the file is used by choice", async () => {
    kr.mode = "throw";
    expect((await store.put(fakeLogin(), { requireKeyring: true, insecureStorage: true })).storage).toBe("file");
  });

  it("get explains an unreachable keyring instead of returning a login without a token", async () => {
    await store.put(fakeLogin());
    kr.mode = "throw";
    await expect(store.get(baseUrl)).rejects.toMatchObject({ kind: "not_logged_in" });
  });
});
