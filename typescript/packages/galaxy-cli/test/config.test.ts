import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, it, expect, vi } from "vitest";
import { loadSources, loadSourcesAsync, resolveConnection, type Sources } from "../src/config";
import { normalizeBaseUrl } from "../src/auth/base-url";
import type { StoredLogin } from "../src/auth/types";
import { DAY, FAKE_TOKEN, FakeStore, fakeLogin, useTempDir } from "./auth/harness";

describe("resolveConnection", () => {
  it("prefers explicit flags over env", () => {
    const conn = resolveConnection(
      { url: "https://flag.example", apiKey: "FLAGKEY" },
      { env: { GALAXY_URL: "https://env.example", GALAXY_API_KEY: "ENVKEY" }, dotenv: {}, profiles: {} },
    );
    expect(conn).toEqual({ baseUrl: "https://flag.example", apiKey: "FLAGKEY" });
  });
  it("falls back to env, then dotenv, then profile", () => {
    const conn = resolveConnection(
      { profile: "prod" },
      { env: {}, dotenv: { GALAXY_URL: "https://dot.example" }, profiles: { prod: { galaxy_url: "https://prof.example", galaxy_user_key: "PK" } } },
    );
    expect(conn.baseUrl).toBe("https://dot.example"); // dotenv URL wins over profile
    expect(conn.apiKey).toBe("PK"); // key only in profile
  });
  it("throws a clear error when no credentials resolve", () => {
    expect(() => resolveConnection({}, { env: {}, dotenv: {}, profiles: {} })).toThrow(/GALAXY_URL|GALAXY_API_KEY/);
  });
});

const tmp = useTempDir("gxy-cfg-");

describe("resolveConnection with stored logins", () => {
  const url = normalizeBaseUrl("https://galaxy.example.org");
  const login = (over: Partial<StoredLogin> = {}): StoredLogin => fakeLogin({ baseUrl: url, token: "STORED", expiresAt: "2030-01-01T00:00:00.000Z", ...over });
  const now = new Date("2026-06-01T00:00:00.000Z");
  const src = (over: Partial<Sources> = {}): Sources => ({
    env: {}, dotenv: {}, profiles: {}, storedBaseUrls: [url], storedLogin: login(), now, ...over,
  });
  const at = (ms: number) => new Date(now.getTime() + ms).toISOString();

  it("uses the only stored login when nothing names a host", () => {
    expect(resolveConnection({}, src())).toEqual({ baseUrl: url, apiKey: "STORED" });
  });
  it("lets --api-key and GALAXY_API_KEY win", () => {
    expect(resolveConnection({ apiKey: "FLAG" }, src()).apiKey).toBe("FLAG");
    expect(resolveConnection({}, src({ env: { GALAXY_API_KEY: "ENV" } })).apiKey).toBe("ENV");
  });
  it("prefers the stored login over .env and profile keys", () => {
    expect(resolveConnection({}, src({ dotenv: { GALAXY_API_KEY: "DOT" } })).apiKey).toBe("STORED");
  });
  it("ignores a stored login for a different Galaxy", () => {
    const conn = resolveConnection({ url: "https://other.example" }, src({ dotenv: { GALAXY_API_KEY: "DOT" } }));
    expect(conn).toEqual({ baseUrl: "https://other.example", apiKey: "DOT" });
  });
  it("matches the URL after normalisation, and sends the key to the normalised URL", () => {
    const conn = resolveConnection({ url: "https://GALAXY.example.org/?x=1" }, src());
    expect(conn).toEqual({ baseUrl: url, apiKey: "STORED" });
  });
  it("keeps the raw URL when an explicit key is used", () => {
    expect(resolveConnection({ url: "https://x.example.org/?q", apiKey: "K" }, { env: {}, dotenv: {}, profiles: {} }).baseUrl).toBe("https://x.example.org/?q");
  });
  it("fails with ambiguous_host when several are stored and none named", () => {
    expect(() => resolveConnection({}, src({ storedBaseUrls: [url, normalizeBaseUrl("https://b.example")], storedLogin: undefined })))
      .toThrow(expect.objectContaining({ kind: "ambiguous_host", message: expect.stringMatching(/several Galaxies/) }));
  });
  it("reports a store problem when it leaves no credentials", () => {
    expect(() => resolveConnection({}, { env: {}, dotenv: {}, profiles: {}, storeProblem: "hosts.yml is not valid" }))
      .toThrow(/hosts\.yml is not valid/);
  });

  describe("an expired login", () => {
    it("fails when there is no other key, naming the time and how to renew", () => {
      const s = src({ storedLogin: login({ expiresAt: "2026-05-01T00:00:00.000Z" }) });
      expect(() => resolveConnection({}, s)).toThrow(expect.objectContaining({ kind: "not_logged_in", message: expect.stringMatching(/expired at 2026-05-01.*gxy auth login --host https:\/\/galaxy\.example\.org/) }));
    });
    it("is used up to the margin: 30 s left counts as about to expire, two minutes does not", () => {
      expect(() => resolveConnection({}, src({ storedLogin: login({ expiresAt: at(30_000) }) }))).toThrow(/about to expire/);
      expect(resolveConnection({}, src({ storedLogin: login({ expiresAt: at(120_000) }) })).apiKey).toBe("STORED");
    });
    it("hands over to another key with a warning", () => {
      const s = src({ storedLogin: login({ expiresAt: "2026-05-01T00:00:00.000Z" }), dotenv: { GALAXY_API_KEY: "DOT" } });
      const conn = resolveConnection({}, s);
      expect(conn.apiKey).toBe("DOT");
      expect(conn.warning).toMatch(/expired/);
    });
  });

  describe("an unreadable expiry", () => {
    it("is not read as non-expiring", () => {
      expect(() => resolveConnection({}, src({ storedLogin: login({ expiresAt: "tomorrow" }) }))).toThrow(/unreadable expiry/);
    });
    it("hands over to another key with a warning", () => {
      const conn = resolveConnection({}, src({ storedLogin: login({ expiresAt: "tomorrow" }), dotenv: { GALAXY_API_KEY: "OTHER" } }));
      expect(conn.apiKey).toBe("OTHER");
      expect(conn.warning).toMatch(/unreadable expiry/);
    });
  });
});

describe("loadSourcesAsync", () => {
  const url = normalizeBaseUrl("https://galaxy.example.org");
  const base = (over: Partial<Sources> = {}): Sources => ({ env: {}, dotenv: {}, profiles: {}, ...over });
  const seeded = () => new FakeStore().seed(fakeLogin({ baseUrl: url, token: "STORED", method: "pasted", scopes: [], expiresAt: null }), "file");

  it("loads the login for the only stored host", async () => {
    const s = await loadSourcesAsync({}, { store: seeded(), base: base() });
    expect(s.storedLogin?.token).toBe("STORED");
    expect(resolveConnection({}, s).apiKey).toBe("STORED");
  });
  it("does not touch the store when a key is explicit", async () => {
    const boom = seeded();
    boom.list = async () => { throw new Error("no"); };
    for (const [flags, b] of [[{ apiKey: "K" }, base()], [{}, base({ env: { GALAXY_API_KEY: "K" } })]] as const) {
      const s = await loadSourcesAsync(flags, { store: boom, base: b });
      expect(s.storedLogin).toBeUndefined();
      expect(s.storeProblem).toBeUndefined();
    }
  });
  it("turns store failures into a problem rather than throwing", async () => {
    const boom = seeded();
    boom.list = async () => { throw new Error("hosts.yml is not valid"); };
    expect((await loadSourcesAsync({}, { store: boom, base: base() })).storeProblem).toMatch(/not valid/);
  });
  it("turns an unreadable token into a problem too", async () => {
    const store = seeded();
    store.get = async () => { throw new Error("keyring is down"); };
    const s = await loadSourcesAsync({}, { store, base: base() });
    expect(s.storeProblem).toMatch(/keyring is down/);
    expect(() => resolveConnection({}, s)).toThrow(/keyring is down/);
  });
  it("leaves an unparsable URL with no stored login, which is not an error here", async () => {
    const s = await loadSourcesAsync({}, { store: seeded(), base: base({ env: { GALAXY_URL: "not a url" } }) });
    expect(s.storedLogin).toBeUndefined();
    expect(s.storeProblem).toBeUndefined();
  });
  it("opens the default store from the config dir named in the environment (file storage only)", async () => {
    const dir = join(tmp.path, "cfg");
    await mkdir(dir, { mode: 0o700 });
    await writeFile(join(dir, "hosts.yml"), `hosts:\n  ${url}:\n    username: a\n    method: pasted\n    scopes: []\n    expires_at: null\n    obtained_at: "${DAY}"\n    storage: file\n    token: ${FAKE_TOKEN}\n`, { mode: 0o600 });
    // GXY_NO_KEYRING keeps the real keyring out of it, whatever the host has.
    const s = await loadSourcesAsync({}, { base: base({ env: { GXY_CONFIG_DIR: dir, GXY_NO_KEYRING: "1" } }) });
    expect(s.storedLogin?.token).toBe(FAKE_TOKEN);
  });

  describe("a stored token goes only to the host it was stored for", () => {
    const now = new Date("2026-06-01");
    it("a .env naming another Galaxy never gets it", async () => {
      const store = seeded();
      const get = vi.spyOn(store, "get");
      const b = base({ dotenv: { GALAXY_URL: "https://evil.example" }, now });
      const src = await loadSourcesAsync({}, { store, base: b, now });
      expect(get).not.toHaveBeenCalled();
      expect(() => resolveConnection({}, src)).toThrow(/No Galaxy credentials/);
      // With a .env key too: that key goes to the .env host, the stored token still does not.
      expect(resolveConnection({}, { ...src, dotenv: { ...src.dotenv, GALAXY_API_KEY: "DOTKEY" } })).toEqual({ baseUrl: "https://evil.example", apiKey: "DOTKEY" });
    });
    it("a .env naming the same Galaxy, however spelled, uses it", async () => {
      const b = base({ dotenv: { GALAXY_URL: "https://GALAXY.example.org/" }, now });
      expect(resolveConnection({}, await loadSourcesAsync({}, { store: seeded(), base: b, now }))).toEqual({ baseUrl: url, apiKey: "STORED" });
    });
  });
});

describe("loadSources (the files and environment)", () => {
  async function withFiles(files: Record<string, string>, fn: () => void) {
    for (const [name, text] of Object.entries(files)) await writeFile(join(tmp.path, name), text);
    const cwd = vi.spyOn(process, "cwd").mockReturnValue(tmp.path);
    vi.stubEnv("HOME", tmp.path);
    try {
      fn();
    } finally {
      cwd.mockRestore();
      vi.unstubAllEnvs();
    }
  }

  it("reads GALAXY_* from .env in the working directory, unquoted, ignoring other lines", async () => {
    await withFiles({ ".env": `# a comment\nGALAXY_URL="https://dot.example"\nGALAXY_API_KEY='DOTKEY'\nlower=ignored\n` }, () => {
      const s = loadSources();
      expect(s.dotenv).toMatchObject({ GALAXY_URL: "https://dot.example", GALAXY_API_KEY: "DOTKEY" });
      expect(s.dotenv.lower).toBeUndefined();
    });
  });
  it("reads planemo profiles from ~/.planemo.yml, and a top-level galaxy_url as the default one", async () => {
    await withFiles({ ".planemo.yml": "galaxy_url: https://def.example\ngalaxy_user_key: DEFKEY\nprofiles:\n  prod:\n    galaxy_url: https://prod.example\n    galaxy_user_key: PK\n" }, () => {
      expect(loadSources().profiles).toEqual({
        prod: { galaxy_url: "https://prod.example", galaxy_user_key: "PK" },
        default: { galaxy_url: "https://def.example", galaxy_user_key: "DEFKEY" },
      });
    });
  });
  it("has no .env and no profiles when the files are absent or unparsable", async () => {
    await withFiles({ ".planemo.yml": "{ unclosed" }, () => {
      const s = loadSources();
      expect(s.dotenv).toEqual({});
      expect(s.profiles).toEqual({});
    });
  });
});
