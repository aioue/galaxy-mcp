import { readFile } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FileStore } from "../../src/auth/file-store";
import type { CombinedStore } from "../../src/auth/store";
import { FAKE_TOKEN, HOST, FakeKeyring, fakeLogin, realStore, useTempDir } from "./harness";

// The real `CombinedStore` over a real `hosts.yml` in a temp directory, with only the keyring
// faked (`FakeKeyring`, which can also fail, lose writes or read back wrong). What is being
// tested is how the two stores are kept in step, so the assertions look at what is actually in each
// (`kr.data` and the text of the file) and not at which calls were made.
const SECOND_TOKEN = "fake-token-second-0123456789";
// The entry's key, written out rather than built by `keyringService`, as in the keyring-store tests.
const entryKey = `gxy:${HOST}|aioue`;

const tmp = useTempDir("gxy-st-");
let kr: FakeKeyring;
let file: FileStore;
let store: CombinedStore;
// New fakes and a new directory for every test, because tests change `kr.mode` and write the file.
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

  // The four ways a keyring can fail: it throws, it never answers, it accepts a write and then
  // serves nothing ("lossy"), or it serves something other than what was written ("wrong"). The
  // last two raise no error at all; only reading the token back after writing it catches them.
  it.each(["throw", "hang", "lossy", "wrong"] as const)("falls back to the file with a warning when the keyring is %s", async (mode) => {
    kr.mode = mode;
    const res = await store.put(fakeLogin());
    expect(res.storage).toBe("file");
    expect(res.warning).toMatch(/No system keyring.*plain text/);
    expect(res.warning).toContain(file.path);
    expect(await store.get(HOST)).toEqual({ ...fakeLogin(), storage: "file" });
  });

  // The keyring is set to throw so that a put that did try it would fall back and carry a warning.
  // The result having none is what shows it was never asked.
  it("with insecureStorage, uses the file without a warning and never touches the keyring", async () => {
    kr.mode = "throw";
    expect(await store.put(fakeLogin(), { insecureStorage: true })).toEqual({ storage: "file" });
    expect(kr.data.size).toBe(0);
  });

  // `requireKeyring` is for a token that must not sit in a plaintext file (an admin key). The refusal
  // has to name the way out (`--insecure-storage`), what that would do (write `hosts.yml`) and the
  // alternative that stores nothing (`GALAXY_API_KEY`), and the file must hold no login after it.
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

// A login that moves between the two stores, or changes user, must not leave a copy of the old
// token behind: a secret that no record points at is one `logout` can never find.
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

// The keyring is written before the record that points at it, so a failure in between can leave an
// entry nothing refers to. The file's own failure paths are tested in its own file; here the file
// write is made to fail with a spy so that what the store does about the entry it already made
// can be seen.
describe("a keyring write that cannot be kept", () => {
  it("takes the new entry back out when the file write fails", async () => {
    vi.spyOn(file, "put").mockRejectedValueOnce(new Error("disk full"));
    await expect(store.put(fakeLogin())).rejects.toThrow("disk full");
    expect(kr.data.size).toBe(0);
  });

  // Same host and user, so the new write replaced the entry the existing record uses. Deleting it
  // would turn a failed re-login into the loss of a login that worked.
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

  // The refusal path cleans up too, and it must make the same exception for an existing record.
  it("leaves the entry alone when an existing record points at it, even if it then refuses (requireKeyring)", async () => {
    await store.put(fakeLogin());
    kr.mode = "wrong";
    await expect(store.put(fakeLogin(), { requireKeyring: true })).rejects.toMatchObject({ kind: "denied" });
    expect(kr.data.size).toBe(1);
  });
});

// A record that says the token is in the keyring, with no token there, is a login that cannot be
// used. It must be reported as one, and never come back as `null`, which callers would take for a
// clean slate.
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

// `delete` removes the record whatever the keyring does: a login that cannot be found cannot be
// used by mistake. It then says so when the keyring could not confirm that the secret is gone.
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

  // The keyring is broken here, so a `list` that reached for a token would fail.
  it("list works without reading any secret", async () => {
    await store.put(fakeLogin());
    kr.mode = "throw";
    expect((await store.list()).map((s) => s.baseUrl)).toEqual([HOST]);
  });
});
