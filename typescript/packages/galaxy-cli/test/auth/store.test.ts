import { readFile } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FileStore } from "../../src/auth/file-store";
import type { CombinedStore } from "../../src/auth/store";
import { FAKE_TOKEN, HOST, FakeKeyring, fakeLogin, realStore, useTempDir } from "./harness";

const SECOND_TOKEN = "fake-token-second-0123456789";
const entryKey = `gxy:${HOST}|aioue`;

const tmp = useTempDir("gxy-st-");
let kr: FakeKeyring;
let file: FileStore;
let store: CombinedStore;
beforeEach(() => {
  kr = new FakeKeyring();
  ({ file, store } = realStore(tmp.path, kr));
});

describe("storing a login", () => {
  it("puts the token in the keyring, not the file", async () => {
    expect(await store.put(fakeLogin())).toEqual({ storage: "keyring" });
    expect(await readFile(file.path, "utf8")).not.toContain(FAKE_TOKEN);
    expect(kr.data.get(entryKey)).toBe(FAKE_TOKEN);
    expect(await store.get(HOST)).toEqual({ ...fakeLogin(), storage: "keyring" });
    expect(JSON.stringify(await store.list())).not.toContain(FAKE_TOKEN);
  });

  it.each(["throw", "hang", "lossy", "wrong"] as const)("falls back to the file with a warning when the keyring is %s", async (mode) => {
    kr.mode = mode;
    const res = await store.put(fakeLogin());
    expect(res.storage).toBe("file");
    expect(res.warning).toMatch(/No system keyring.*plain text/);
    expect(res.warning).toContain(file.path);
    expect(await store.get(HOST)).toEqual({ ...fakeLogin(), storage: "file" });
  });

  it("with insecureStorage, uses the file without a warning and never touches the keyring", async () => {
    kr.mode = "throw";
    expect(await store.put(fakeLogin(), { insecureStorage: true })).toEqual({ storage: "file" });
    expect(kr.data.size).toBe(0);
  });

  it("with requireKeyring and no keyring, stores nothing and says how to opt in", async () => {
    kr.mode = "throw";
    await expect(store.put(fakeLogin(), { requireKeyring: true })).rejects.toMatchObject({ kind: "denied", message: expect.stringMatching(/--insecure-storage.*hosts\.yml.*GALAXY_API_KEY/s) });
    expect(await file.list()).toEqual([]);
  });

  it("with requireKeyring and insecureStorage, the file is used by choice", async () => {
    kr.mode = "throw";
    expect((await store.put(fakeLogin(), { requireKeyring: true, insecureStorage: true })).storage).toBe("file");
  });
});

describe("replacing a login", () => {
  it("removes the plaintext token when the new one goes to the keyring", async () => {
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(await readFile(file.path, "utf8")).toContain(FAKE_TOKEN);
    await store.put(fakeLogin({ token: SECOND_TOKEN }));
    expect(await readFile(file.path, "utf8")).not.toMatch(/fake-token|token:/);
    expect((await store.get(HOST))?.token).toBe(SECOND_TOKEN);
  });

  it("removes the keyring entry when the new one goes to the file", async () => {
    await store.put(fakeLogin());
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(kr.data.size).toBe(0);
  });

  it("removes the old keyring entry when the username changes", async () => {
    await store.put(fakeLogin());
    await store.put(fakeLogin({ username: "bob" }));
    expect([...kr.data.keys()]).toEqual([`gxy:${HOST}|bob`]);
  });
});

describe("a keyring write that cannot be kept", () => {
  it("takes the new entry back out when the file write fails", async () => {
    vi.spyOn(file, "put").mockRejectedValueOnce(new Error("disk full"));
    await expect(store.put(fakeLogin())).rejects.toThrow("disk full");
    expect(kr.data.size).toBe(0);
  });

  it("leaves the entry alone when the file write fails and a record already points at it", async () => {
    await store.put(fakeLogin());
    vi.spyOn(file, "put").mockRejectedValueOnce(new Error("disk full"));
    await expect(store.put(fakeLogin({ token: SECOND_TOKEN }))).rejects.toThrow("disk full");
    expect(kr.data.size).toBe(1);
  });

  it("deletes an entry that reads back wrong before falling back to the file", async () => {
    kr.mode = "wrong";
    const r = await store.put(fakeLogin());
    expect(r.storage).toBe("file");
    kr.mode = "ok";
    expect(kr.data.size).toBe(0);
  });

  it("leaves the entry alone when an existing record points at it, even if it then refuses (requireKeyring)", async () => {
    await store.put(fakeLogin());
    kr.mode = "wrong";
    await expect(store.put(fakeLogin(), { requireKeyring: true })).rejects.toMatchObject({ kind: "denied" });
    expect(kr.data.size).toBe(1);
  });
});

describe("reading a login", () => {
  it("says the keyring has no secret when the record points at it ('no login' would be wrong)", async () => {
    await store.put(fakeLogin());
    kr.data.clear();
    await expect(store.get(HOST)).rejects.toMatchObject({ kind: "not_logged_in", message: expect.stringContaining("keyring has none") });
  });

  it("explains an unreachable keyring instead of returning a login without a token", async () => {
    await store.put(fakeLogin());
    kr.mode = "throw";
    await expect(store.get(HOST)).rejects.toMatchObject({ kind: "not_logged_in" });
  });

  it("returns null for a host it has no record for", async () => {
    expect(await store.get(HOST)).toBeNull();
  });
});

describe("deleting and listing", () => {
  it("delete removes the keyring entry and the record, and is false the second time", async () => {
    await store.put(fakeLogin());
    expect(await store.delete(HOST)).toBe(true);
    expect(kr.data.size).toBe(0);
    expect(await store.get(HOST)).toBeNull();
    expect(await store.delete(HOST)).toBe(false);
  });

  it.each(["throw", "undeletable"] as const)("delete still removes the record when the keyring is %s, and says the secret may remain", async (mode) => {
    await store.put(fakeLogin());
    kr.mode = mode;
    await expect(store.delete(HOST)).rejects.toThrow(/may remain/);
    expect(await file.list()).toEqual([]);
  });

  it("list works without reading any secret", async () => {
    await store.put(fakeLogin());
    kr.mode = "throw";
    expect((await store.list()).map((s) => s.baseUrl)).toEqual([HOST]);
  });
});
