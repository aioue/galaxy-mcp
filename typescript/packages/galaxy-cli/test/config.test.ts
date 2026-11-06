import { describe, it, expect } from "vitest";
import { loadSourcesAsync, resolveConnection, type Sources } from "../src/config";
import { normalizeBaseUrl } from "../src/auth/base-url";
import type { StoredLogin } from "../src/auth/types";

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

describe("resolveConnection with stored logins", () => {
  const url = normalizeBaseUrl("https://galaxy.example.org");
  const login = (over: Partial<StoredLogin> = {}): StoredLogin => ({
    baseUrl: url, username: "alice", token: "STORED", method: "device", scopes: [],
    expiresAt: "2030-01-01T00:00:00.000Z", obtainedAt: "2026-01-01T00:00:00.000Z", ...over,
  });
  const now = new Date("2026-06-01T00:00:00.000Z");
  const src = (over: Partial<Sources> = {}): Sources => ({
    env: {}, dotenv: {}, profiles: {}, storedBaseUrls: [url], storedLogin: login(), now, ...over,
  });

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
  it("matches the URL after normalisation", () => {
    expect(resolveConnection({ url: "Galaxy.example.org/" }, src()).apiKey).toBe("STORED");
  });
  it("fails on an expired login with no other key", () => {
    const s = src({ storedLogin: login({ expiresAt: "2026-05-01T00:00:00.000Z" }) });
    expect(() => resolveConnection({}, s)).toThrow(/expired at 2026-05-01.*gxy auth login --host https:\/\/galaxy\.example\.org/);
  });
  it("uses another key with a warning when the login expired", () => {
    const s = src({ storedLogin: login({ expiresAt: "2026-05-01T00:00:00.000Z" }), dotenv: { GALAXY_API_KEY: "DOT" } });
    const conn = resolveConnection({}, s);
    expect(conn.apiKey).toBe("DOT");
    expect(conn.warning).toMatch(/expired/);
  });
  it("fails with ambiguous_host when several are stored and none named", () => {
    expect(() => resolveConnection({}, src({ storedBaseUrls: [url, "https://b.example" as never], storedLogin: undefined })))
      .toThrow(/several Galaxies/);
  });
  it("reports a store problem when it leaves no credentials", () => {
    expect(() => resolveConnection({}, { env: {}, dotenv: {}, profiles: {}, storeProblem: "hosts.yml is not valid" }))
      .toThrow(/hosts\.yml is not valid/);
  });
});

describe("loadSourcesAsync", () => {
  const url = normalizeBaseUrl("https://galaxy.example.org");
  const stored: StoredLogin = { baseUrl: url, username: "a", token: "STORED", method: "pasted", scopes: [], expiresAt: null, obtainedAt: "2026-01-01T00:00:00.000Z" };
  const store = {
    list: async () => [{ ...stored, storage: "file" as const }],
    get: async () => ({ ...stored, storage: "file" as const }),
    put: async () => ({ storage: "file" as const }),
    delete: async () => true,
  };
  const base: Sources = { env: {}, dotenv: {}, profiles: {} };

  it("loads the login for the only stored host", async () => {
    const s = await loadSourcesAsync({}, { store, base });
    expect(s.storedLogin?.token).toBe("STORED");
    expect(resolveConnection({}, s).apiKey).toBe("STORED");
  });
  it("does not touch the store when a key is explicit", async () => {
    const boom = { ...store, list: async () => { throw new Error("no"); } };
    const s = await loadSourcesAsync({ apiKey: "K" }, { store: boom, base });
    expect(s.storedLogin).toBeUndefined();
    expect(s.storeProblem).toBeUndefined();
  });
  it("turns store failures into a problem rather than throwing", async () => {
    const boom = { ...store, list: async () => { throw new Error("hosts.yml is not valid"); } };
    expect((await loadSourcesAsync({}, { store: boom, base })).storeProblem).toMatch(/not valid/);
  });
});
