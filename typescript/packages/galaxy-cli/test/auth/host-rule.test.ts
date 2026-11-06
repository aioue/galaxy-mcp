import { describe, expect, it, vi } from "vitest";
import { loadSourcesAsync, resolveConnection, type Sources } from "../../src/config";
import { pickHost, resolveHost } from "../../src/auth/host";
import { normalizeBaseUrl } from "../../src/auth/base-url";
import { loginCommand } from "../../src/auth/commands/login";
import { AuthError, type LoginSummary } from "../../src/auth/types";
import { harness, HOST } from "./harness";
import { fakeLogin } from "./support";

const stored = (...urls: string[]) => urls.map((u) => normalizeBaseUrl(u));
const empty = { env: {}, dotenv: {}, storedBaseUrls: [] as never[] };

describe("pickHost: one precedence", () => {
  const all = {
    flag: "https://flag.example",
    env: { GALAXY_URL: "https://env.example" },
    dotenv: { GALAXY_URL: "https://dot.example" },
    profileUrl: "https://prof.example",
    storedBaseUrls: stored("https://stored.example"),
  };
  it("takes flag, then env, then .env, then the profile, then the only stored login", () => {
    expect(pickHost(all)).toEqual({ url: "https://flag.example", source: "flag" });
    expect(pickHost({ ...all, flag: undefined }).source).toBe("env");
    expect(pickHost({ ...all, flag: undefined, env: {} }).source).toBe("dotenv");
    expect(pickHost({ ...all, flag: undefined, env: {}, dotenv: {} }).source).toBe("profile");
    expect(pickHost({ ...all, flag: undefined, env: {}, dotenv: {}, profileUrl: undefined })).toEqual({
      url: "https://stored.example",
      source: "stored",
    });
  });
  it("is ambiguous with several stored logins and none named, and usage with none", () => {
    expect(() => pickHost({ ...empty, storedBaseUrls: stored("https://a.example", "https://b.example") })).toThrow(
      expect.objectContaining({ kind: "ambiguous_host" }),
    );
    expect(() => pickHost(empty)).toThrow(expect.objectContaining({ kind: "usage" }));
  });
  it("login ignores .env and the profile", () => {
    const l = { ...all, flag: undefined, env: {}, forLogin: true };
    expect(pickHost(l).source).toBe("stored");
    expect(() => pickHost({ ...l, storedBaseUrls: [] })).toThrow(expect.objectContaining({ kind: "usage" }));
    expect(pickHost({ ...l, env: { GALAXY_URL: "https://env.example" } }).source).toBe("env");
    expect(pickHost({ ...l, flag: "https://flag.example" }).source).toBe("flag");
  });
});

describe("resolveHost (gxy auth *)", () => {
  const store = (...urls: string[]) => ({ list: async () => stored(...urls).map((baseUrl) => ({ baseUrl }) as LoginSummary) });
  it("uses the profile URL, and the global --url as the flag", async () => {
    expect(await resolveHost({ env: {}, dotenv: {}, profileUrl: "https://prof.example", store: store("https://s.example") })).toBe("https://prof.example");
    expect(await resolveHost({ explicit: "Flag.example", env: {}, dotenv: {}, profileUrl: "https://prof.example", store: store() })).toBe("https://flag.example");
  });
  it("login never takes the host from .env or the profile", async () => {
    const input = { env: {}, dotenv: { GALAXY_URL: "https://evil.example" }, profileUrl: "https://evil.example", forLogin: true };
    await expect(resolveHost({ ...input, store: store() })).rejects.toMatchObject({ kind: "usage" });
    expect(await resolveHost({ ...input, store: store("https://s.example") })).toBe("https://s.example");
    expect(await resolveHost({ ...input, env: { GALAXY_URL: "https://env.example" }, store: store() })).toBe("https://env.example");
  });
});

describe("operations and auth pick the same Galaxy", () => {
  const a = "https://a.example";
  const b = "https://b.example";
  const cases: Record<string, { flags: { url?: string; profile?: string }; env?: Record<string, string>; dotenv?: Record<string, string>; stored: string[] }> = {
    flag: { flags: { url: b }, stored: [a] },
    env: { flags: {}, env: { GALAXY_URL: b }, stored: [a] },
    dotenv: { flags: {}, dotenv: { GALAXY_URL: b }, stored: [a] },
    profile: { flags: { profile: "p" }, stored: [a] },
    stored: { flags: {}, stored: [a] },
  };
  for (const [name, c] of Object.entries(cases)) {
    it(`agree on the ${name} step`, async () => {
      const urls = stored(...c.stored);
      const base: Sources = { env: c.env ?? {}, dotenv: { GALAXY_API_KEY: "K", ...c.dotenv }, profiles: { p: { galaxy_url: b, galaxy_user_key: "K" } }, now: new Date("2026-06-01") };
      const fakeStore = { list: async () => urls.map((baseUrl) => ({ baseUrl }) as LoginSummary), get: async (u: string) => ({ ...fakeLogin({ baseUrl: u as never }), token: "STORED" }) } as never;
      const src = await loadSourcesAsync(c.flags, { store: fakeStore, base: base, now: base.now });
      const op = resolveConnection(c.flags, { ...src, profiles: { p: { galaxy_url: b, galaxy_user_key: "K" } } }).baseUrl;
      const auth = await resolveHost({ explicit: c.flags.url, env: base.env, dotenv: base.dotenv, profileUrl: c.flags.profile ? b : undefined, store: fakeStore });
      expect(normalizeBaseUrl(op)).toBe(auth);
    });
  }
});

describe("a stored token goes only to the host it was stored for", () => {
  it("a .env naming another Galaxy never gets the stored token", async () => {
    const [a] = stored("https://a.example");
    const get = vi.fn(async () => ({ ...fakeLogin({ baseUrl: a! }), token: "STORED-SECRET" }));
    const store = { list: async () => [{ baseUrl: a } as LoginSummary], get } as never;
    const base: Sources = { env: {}, dotenv: { GALAXY_URL: "https://evil.example" }, profiles: {}, now: new Date("2026-06-01") };
    const src = await loadSourcesAsync({}, { store, base, now: base.now });
    expect(get).not.toHaveBeenCalled();
    expect(() => resolveConnection({}, src)).toThrow(/No Galaxy credentials/);
    // With a .env key too: that key goes to the .env host, the stored token still does not.
    const conn = resolveConnection({}, { ...src, dotenv: { ...src.dotenv, GALAXY_API_KEY: "DOTKEY" } });
    expect(conn).toEqual({ baseUrl: "https://evil.example", apiKey: "DOTKEY" });
  });
  it("a .env naming the same Galaxy uses it", async () => {
    const [a] = stored("https://a.example");
    const store = { list: async () => [{ baseUrl: a } as LoginSummary], get: async () => ({ ...fakeLogin({ baseUrl: a! }), token: "STORED" }) } as never;
    const base: Sources = { env: {}, dotenv: { GALAXY_URL: "https://A.example/" }, profiles: {}, now: new Date("2026-06-01") };
    expect(resolveConnection({}, await loadSourcesAsync({}, { store, base, now: base.now }))).toEqual({ baseUrl: a, apiKey: "STORED" });
  });
  it("an unparsable URL has no stored login and is not an error here", async () => {
    const store = { list: async () => [], get: async () => null } as never;
    const base: Sources = { env: { GALAXY_URL: "not a url" }, dotenv: {}, profiles: {} };
    const src = await loadSourcesAsync({}, { store, base });
    expect(src.storedLogin).toBeUndefined();
  });
});

describe("login host rules", () => {
  it("asks resolveHost for a login host, so .env and profiles are never consulted", async () => {
    const h = harness();
    const spy = vi.spyOn(h.deps, "resolveHost");
    await loginCommand({}, h.deps).catch(() => 0);
    await loginCommand({ host: "https://dev.galaxy.example.org" }, h.deps);
    expect(spy.mock.calls.map((c) => c[1])).toEqual(["login", "login"]);
  });
  it("prints 'Logging in to <host>' before a pasted key is read or sent", async () => {
    const h = harness({ stdinText: "FAKE-KEY\n" });
    const seen: string[] = [];
    h.deps.whoami = async (_u, _t) => {
      seen.push(h.cap.err);
      return { username: "aioue" };
    };
    await loginCommand({ host: HOST, withToken: true }, h.deps);
    expect(seen[0]).toContain("Logging in to dev.galaxy.example.org");
  });
  it("prints it before the device flow starts", async () => {
    const h = harness();
    const seen: string[] = [];
    h.deps.discover = async () => {
      seen.push(h.cap.err);
      return h.server;
    };
    await loginCommand({ host: HOST }, h.deps);
    expect(seen[0]).toContain("Logging in to dev.galaxy.example.org");
  });
  it("is an AuthError when the login host cannot be resolved non-interactively", async () => {
    const h = harness();
    h.deps.resolveHost = async () => {
      throw new AuthError("usage", "No Galaxy given");
    };
    expect(await loginCommand({}, h.deps)).toBe(64);
  });
});
