import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loginCommand } from "../../src/auth/commands/login";
import { FileStore } from "../../src/auth/file-store";
import { discover } from "../../src/auth/oauth";
import { KeyringStore } from "../../src/auth/keyring-store";
import { CombinedStore } from "../../src/auth/store";
import { createWhoami } from "../../src/auth/whoami";
import type { AuthDeps, BaseUrl } from "../../src/auth/types";
import { loadSourcesAsync, resolveConnection } from "../../src/config";
import { startFakeGalaxy, type FakeGalaxy } from "../support/fake-galaxy";
import { Capture } from "./harness";
import { FakeKeyring, fakeLogin } from "./support";
import { PassThrough } from "node:stream";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "gxy-la-"));
});
afterEach(() => rm(root, { recursive: true, force: true }));

describe("S2: a corrupt hosts.yml never leaks its contents", () => {
  const SECRET = "FAKE-SECRET-TOKEN-123";
  async function corrupt() {
    const dir = join(root, "cfg");
    await mkdir(dir, { recursive: true });
    const store = new FileStore(dir);
    await writeFile(store.path, `hosts:\n  https://a.example:\n    token: ${SECRET} : bad\n    username: [unclosed\n`);
    return store;
  }
  it("names the path and line/column only", async () => {
    const store = await corrupt();
    const e = (await store.list().catch((x) => x)) as Error;
    expect(e.message).toContain(store.path);
    expect(e.message).toMatch(/line \d+, column \d+/);
    expect(e.message).not.toContain(SECRET);
    expect(e.message).not.toContain("unclosed");
  });
  it("an operation does not print the token either", async () => {
    const store = await corrupt();
    const src = await loadSourcesAsync({}, { store, base: { env: {}, dotenv: {}, profiles: {} } });
    expect(src.storeProblem).toBeDefined();
    expect(src.storeProblem).not.toContain(SECRET);
    let shown = "";
    try {
      resolveConnection({}, src);
    } catch (e) {
      shown = (e as Error).message;
    }
    expect(shown).toContain(store.path);
    expect(shown).not.toContain(SECRET);
  });
});

describe("C1: a token the server issued is revoked when it cannot be kept", () => {
  let galaxy: FakeGalaxy;
  beforeEach(async () => {
    galaxy = await startFakeGalaxy();
  });
  afterEach(() => galaxy.close());

  function depsFor(store: CombinedStore, cap: Capture, whoami = createWhoami()): AuthDeps {
    return {
      store,
      discover: (u, signal) => discover(u, { signal }),
      whoami,
      resolveHost: async () => galaxy.baseUrl as BaseUrl,
      openBrowser: async () => false,
      canOpenBrowser: () => false,
      now: () => new Date(),
      env: {},
      io: { stdin: new PassThrough(), stdout: cap.stdout, stderr: cap.stderr, interactive: false },
      commandName: "gxy",
    };
  }
  /** Approve the first code that appears, as an admin or not. */
  function approveSoon(admin: boolean) {
    const t = setInterval(() => {
      const code = galaxy.pendingCodes()[0];
      if (code) {
        galaxy.approve(code, { expiresIn: 3600, admin });
        clearInterval(t);
      }
    }, 5);
    return t;
  }
  const mkStore = (kr: FakeKeyring) => new CombinedStore(new FileStore(join(root, "cfg")), new KeyringStore(kr, 30));

  it("revokes after an admin's requireKeyring refusal", async () => {
    const kr = new FakeKeyring();
    kr.mode = "throw";
    const cap = new Capture();
    const t = approveSoon(true);
    const code = await loginCommand({ host: galaxy.baseUrl }, depsFor(mkStore(kr), cap));
    clearInterval(t);
    expect(code).not.toBe(0);
    const [token] = galaxy.issuedTokens();
    expect(token).toBeDefined();
    expect(galaxy.isTokenValid(token!)).toBe(false);
    expect(cap.err).toContain("so it was revoked");
    expect(cap.err).not.toContain(token!);
  });

  it("revokes after a whoami failure", async () => {
    const cap = new Capture();
    const t = approveSoon(false);
    const whoami = async () => {
      throw new Error("whoami exploded");
    };
    const code = await loginCommand({ host: galaxy.baseUrl }, depsFor(mkStore(new FakeKeyring()), cap, whoami));
    clearInterval(t);
    expect(code).not.toBe(0);
    const [token] = galaxy.issuedTokens();
    expect(galaxy.isTokenValid(token!)).toBe(false);
    expect(cap.err).toContain("so it was revoked");
  });

  it("says so when the server cannot revoke", async () => {
    galaxy.close();
    galaxy = await startFakeGalaxy({ revocationEndpoint: false });
    const cap = new Capture();
    const t = approveSoon(false);
    const whoami = async () => {
      throw new Error("whoami exploded");
    };
    await loginCommand({ host: galaxy.baseUrl }, depsFor(mkStore(new FakeKeyring()), cap, whoami));
    clearInterval(t);
    expect(cap.err).toContain("cannot be revoked from here");
  });

  it("keeps the token after a good login", async () => {
    const cap = new Capture();
    const t = approveSoon(false);
    const code = await loginCommand({ host: galaxy.baseUrl }, depsFor(mkStore(new FakeKeyring()), cap));
    clearInterval(t);
    expect(code).toBe(0);
    expect(galaxy.isTokenValid(galaxy.issuedTokens()[0]!)).toBe(true);
  });
});

describe("K1: a keyring write that reads back wrong is cleaned up", () => {
  /** Accepts writes, then serves something else. */
  class WrongReadback extends FakeKeyring {
    wrong = true;
    async get(service: string, account: string) {
      const v = await super.get(service, account);
      return this.wrong && v !== null ? "something-else" : v;
    }
  }
  it("deletes the entry before falling back to the file", async () => {
    const kr = new WrongReadback();
    const store = new CombinedStore(new FileStore(join(root, "cfg")), new KeyringStore(kr, 30));
    const r = await store.put(fakeLogin());
    expect(r.storage).toBe("file");
    expect(kr.data.size).toBe(0);
  });
  it("leaves the entry alone when an existing record points at it (requireKeyring refusal)", async () => {
    const kr = new WrongReadback();
    kr.wrong = false;
    const store = new CombinedStore(new FileStore(join(root, "cfg")), new KeyringStore(kr, 30));
    await store.put(fakeLogin());
    expect(kr.data.size).toBe(1);
    kr.wrong = true;
    await expect(store.put(fakeLogin(), { requireKeyring: true })).rejects.toMatchObject({ kind: "denied" });
    expect(kr.data.size).toBe(1);
  });
});
