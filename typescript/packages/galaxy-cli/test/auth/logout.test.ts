import { readFile } from "node:fs/promises";
import { beforeEach, describe, expect, it } from "vitest";
import { logoutCommand } from "../../src/auth/commands/logout";
import type { FileStore } from "../../src/auth/file-store";
import type { CombinedStore } from "../../src/auth/store";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, FakeKeyring, fakeLogin, harness, makeTokenUnreadable, realStore, useTempDir } from "./harness";

describe("auth logout", () => {
  it("revokes the device token while the login is still stored, then deletes the login", async () => {
    const h = harness({ stored: [fakeLogin()] });
    const revoke = h.server.revoke.bind(h.server);
    h.server.revoke = async (token) => {
      // The token can only be revoked if it has not been deleted yet.
      expect(await h.store.get(HOST)).not.toBeNull();
      await revoke(token);
    };
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(h.server.revoked).toEqual([FAKE_TOKEN]);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("Revoked the token on dev.galaxy.example.org");
    expect(h.cap.out).toBe("");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  // Local removal does not wait on the server: a Galaxy that is down is when a person most needs
  // the stored login gone. The token then stays valid until it expires, and the message says so.
  it.each([
    ["revocation fails", (h: ReturnType<typeof harness>) => void (h.server.revokeError = new AuthError("network", "connection refused")), "connection refused"],
    ["discovery fails", (h: ReturnType<typeof harness>) => void (h.knobs.discoverError = new AuthError("network", "no route")), "no route"],
  ])("still deletes locally when %s, and says the token stays valid until expiry", async (_when, breakIt, why) => {
    const h = harness({ stored: [fakeLogin()] });
    breakIt(h);
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("Could not revoke the token on the server");
    expect(h.cap.err).toContain(why);
    expect(h.cap.err).toMatch(/stays valid until it expires/);
  });

  it("says so when the server has no revocation endpoint", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.server.supportsRevocation = false;
    await logoutCommand({}, h.deps);
    expect(h.cap.err).toContain("does not offer token revocation");
    expect(await h.store.get(HOST)).toBeNull();
  });

  it("deletes a pasted key without contacting the server and says it was not revoked", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
    // Only a device token is revoked. A pasted key is not an OAuth token, and logout says to manage
    // it in Galaxy's user preferences instead.
    // Discovery succeeds here, and its calls are counted. An earlier version made discovery throw,
    // and that could not fail: logout treats a throw as "could not revoke", never prints that for a
    // pasted key, and nothing is revoked when discovery throws. So a logout that did try to revoke
    // a pasted key passed it. Counting the calls to a discovery that works is what can fail.
    let discovered = 0;
    const discover = h.deps.discover;
    h.deps.discover = async (...args) => (discovered++, discover(...args));
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(discovered).toBe(0);
    expect(h.server.revoked).toEqual([]);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("not revoked");
    expect(h.cap.err).toContain("user preferences");
  });

  it("reports an unreadable store as an unexpected error, exit 70", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.store.list = async () => {
      throw new Error("store is broken");
    };
    expect(await logoutCommand({}, h.deps)).toBe(70);
    expect(h.cap.err).toContain("store is broken");
  });

  // Reading the token is only needed to revoke it, and must not stand between the person and
  // removing the record: the keyring may be down or the secret gone, which is when cleaning up matters most.
  describe("when the token cannot be read", () => {
    it.each(["throw", "null"] as const)("skips revocation, removes the record and says what happened (%s)", async (how) => {
      const h = harness({ stored: [fakeLogin()] });
      makeTokenUnreadable(h, [HOST], how);
      expect(await logoutCommand({}, h.deps)).toBe(0);
      expect(h.server.revoked).toEqual([]);
      expect(await h.store.list()).toEqual([]);
      expect(h.cap.err).toContain("Removed the stored login for dev.galaxy.example.org");
      expect(h.cap.err).toMatch(/Could not revoke the token on the server.*could not be read/);
      expect(h.cap.err).toContain("stays valid until it expires (2026-11-06 18:42 UTC)");
      expect(h.cap.err).not.toContain(FAKE_TOKEN);
    });

    it("removes a pasted key's record too, noting that it was not revoked", async () => {
      const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
      makeTokenUnreadable(h, [HOST]);
      expect(await logoutCommand({}, h.deps)).toBe(0);
      expect(h.cap.err).toContain("not revoked");
      expect(await h.store.list()).toEqual([]);
    });
  });

  it("is a no-op with a note when nothing is stored for the host", async () => {
    const h = harness();
    expect(await logoutCommand({ host: HOST }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("nothing to remove");
  });
});

// The real store over a real `hosts.yml` and a fake keyring, because what logout must leave behind
// (no token in the keyring, none in the file) is what the real store does, not what a fake store says.
describe("logout with the Galaxy down, over the real store", () => {
  const tmp = useTempDir("gxy-lo-");
  let keyring: FakeKeyring;
  let file: FileStore;
  let store: CombinedStore;
  beforeEach(() => {
    keyring = new FakeKeyring();
    ({ file, store } = realStore(tmp.path, keyring));
  });

  function logoutHarness() {
    const h = harness();
    h.deps.store = store;
    h.deps.resolveHost = async () => HOST;
    h.knobs.discoverError = new AuthError("network", "connection refused");
    return h;
  }

  it("deletes the keyring secret and the record, and reports the failed revoke", async () => {
    await store.put(fakeLogin());
    const h = logoutHarness();
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(keyring.data.size).toBe(0);
    expect(await file.list()).toEqual([]);
    expect(h.cap.err).toContain("Could not revoke the token on the server");
    expect(h.cap.err).toContain("connection refused");
  });

  it("deletes a file-stored token too, leaving no copy in hosts.yml", async () => {
    keyring.mode = "throw";
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(await readFile(file.path, "utf8")).toContain(fakeLogin().token);
    expect(await logoutCommand({}, logoutHarness().deps)).toBe(0);
    expect(await readFile(file.path, "utf8")).not.toContain(fakeLogin().token);
  });

  // The record goes either way, and the failure is reported rather than swallowed: a secret that
  // may remain in the keyring is something the person must know, so the exit is not 0.
  it("says the secret may remain, and exits 1, when the keyring will not confirm the delete", async () => {
    await store.put(fakeLogin());
    keyring.mode = "undeletable";
    const h = logoutHarness();
    expect(await logoutCommand({}, h.deps)).toBe(1);
    expect(await file.list()).toEqual([]);
    expect(h.cap.err).toContain("may remain");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });
});
