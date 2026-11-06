import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { logoutCommand } from "../../src/auth/commands/logout";
import { FileStore } from "../../src/auth/file-store";
import { KeyringStore } from "../../src/auth/keyring-store";
import { CombinedStore } from "../../src/auth/store";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, fakeLogin, harness } from "./harness";
import { FakeKeyring } from "./support";

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

  it.each([
    ["revocation fails", (h: ReturnType<typeof harness>) => void (h.server.revokeError = new AuthError("network", "connection refused")), "connection refused"],
    ["discovery fails", (h: ReturnType<typeof harness>) => void (h.knobs.discoverError = new AuthError("network", "no route")), "no route"],
  ])("still deletes locally when %s, and says the token stays valid until expiry", async (_when, breakIt, why) => {
    const h = harness({ stored: [fakeLogin()] });
    breakIt(h);
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain(`Could not revoke the token on the server (${why})`);
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
    h.knobs.discoverError = new AuthError("network", "should not be called");
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(h.server.revoked).toEqual([]);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("not revoked");
    expect(h.cap.err).toContain("user preferences");
    expect(h.cap.err).not.toContain("should not be called");
  });

  it("reports an unreadable store as an unexpected error, exit 70", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.store.list = async () => {
      throw new Error("store is broken");
    };
    expect(await logoutCommand({}, h.deps)).toBe(70);
    expect(h.cap.err).toContain("store is broken");
  });

  it("is a no-op with a note when nothing is stored for the host", async () => {
    const h = harness();
    expect(await logoutCommand({ host: HOST }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("nothing to remove");
  });
});

describe("logout with the Galaxy down, over the real store", () => {
  let root: string;
  let keyring: FakeKeyring;
  let file: FileStore;
  let store: CombinedStore;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "gxy-lo-"));
    keyring = new FakeKeyring();
    file = new FileStore(join(root, "cfg"));
    store = new CombinedStore(file, new KeyringStore(keyring, 50));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
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
    expect(h.cap.err).toContain("Could not revoke the token on the server (connection refused)");
  });

  it("deletes a file-stored token too, leaving no copy in hosts.yml", async () => {
    keyring.mode = "throw";
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(await readFile(file.path, "utf8")).toContain(fakeLogin().token);
    expect(await logoutCommand({}, logoutHarness().deps)).toBe(0);
    expect(await readFile(file.path, "utf8")).not.toContain(fakeLogin().token);
  });

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
