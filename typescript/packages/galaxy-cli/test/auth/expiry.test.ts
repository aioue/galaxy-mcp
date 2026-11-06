import { describe, expect, it } from "vitest";
import { formatExpiry } from "../../src/auth/commands/common";
import { EXPIRY_MARGIN_MS, checkExpiry, describeExpiry, isExpired } from "../../src/auth/expiry";
import { requireLoginAt } from "../../src/auth/commands/common";
import { resolveHost } from "../../src/auth/host";
import { tokenCommand } from "../../src/auth/commands/token";
import { envCommand } from "../../src/auth/commands/env";
import { headersCommand } from "../../src/auth/commands/headers";
import { resolveConnection } from "../../src/config";
import { HOST, fakeLogin, harness, DAY } from "./fakes";

const now = new Date(DAY);
const at = (ms: number) => new Date(now.getTime() + ms).toISOString();

describe("expiry helper", () => {
  it("treats a login as expired 60 s before expiresAt", () => {
    expect(EXPIRY_MARGIN_MS).toBe(60_000);
    expect(isExpired(at(61_000), now)).toBe(false);
    expect(isExpired(at(60_000), now)).toBe(true);
    expect(isExpired(at(30_000), now)).toBe(true);
    expect(isExpired(at(-1), now)).toBe(true);
    expect(isExpired(null, now)).toBe(false);
  });
  it("treats an unparseable expiresAt as expired, never as non-expiring", () => {
    expect(checkExpiry("tomorrow", now)).toEqual({ state: "unreadable" });
    expect(isExpired("tomorrow", now)).toBe(true);
  });
  it("formatExpiry never throws", () => {
    expect(formatExpiry("tomorrow")).toContain("unreadable");
    expect(formatExpiry("\u001b[2Jx")).not.toContain("\u001b");
    expect(formatExpiry("2026-11-06T18:42:00.000Z")).toBe("2026-11-06 18:42 UTC");
  });
  it("describes the three cases", () => {
    expect(describeExpiry(at(-5000), now)).toMatch(/^expired at /);
    expect(describeExpiry(at(20_000), now)).toMatch(/^is about to expire/);
    expect(describeExpiry("tomorrow", now)).toMatch(/unreadable expiry/);
  });
});

describe("token, env, headers and status share it", () => {
  it.each([
    ["token", (h: ReturnType<typeof harness>) => tokenCommand({}, h.deps)],
    ["env", (h: ReturnType<typeof harness>) => envCommand({}, h.deps)],
    ["headers", (h: ReturnType<typeof harness>) => headersCommand({}, h.deps)],
  ])("%s refuses a token with 30 s left (77) and prints nothing on stdout", async (_n, run) => {
    const h = harness({ stored: [fakeLogin({ expiresAt: at(30_000) })] });
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toMatch(/about to expire/);
  });
  it("token refuses a corrupt expiresAt with a clear message", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "tomorrow" })] });
    expect(await tokenCommand({}, h.deps)).toBe(77);
    expect(h.cap.err).toMatch(/unreadable expiry time \(tomorrow\)/);
    expect(h.cap.out).toBe("");
  });
  it("requireLoginAt accepts a token with more than a minute left", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: at(120_000) })] });
    await expect(requireLoginAt(h.deps, HOST)).resolves.toMatchObject({ baseUrl: HOST });
  });
});

describe("existing operations (config.ts)", () => {
  const login = (expiresAt: string | null) => fakeLogin({ expiresAt });
  const src = (expiresAt: string | null, over = {}) => ({
    env: {}, dotenv: {}, profiles: {}, storedBaseUrls: [HOST], storedLogin: login(expiresAt), now, ...over,
  });
  it("treats a login within 60 s of expiry as expired", () => {
    expect(() => resolveConnection({}, src(at(30_000)))).toThrow(/about to expire/);
    expect(resolveConnection({}, src(at(120_000))).apiKey).toBe(fakeLogin().token);
  });
  it("does not treat a corrupt expiresAt as non-expiring", () => {
    expect(() => resolveConnection({}, src("tomorrow"))).toThrow(/unreadable expiry/);
    const conn = resolveConnection({}, src("tomorrow", { dotenv: { GALAXY_API_KEY: "OTHER" } }));
    expect(conn.apiKey).toBe("OTHER");
    expect(conn.warning).toMatch(/unreadable expiry/);
  });
});

describe("nothing stored and none named", () => {
  const real = (h: ReturnType<typeof harness>) => {
    h.deps.resolveHost = (explicit) => resolveHost({ explicit, env: {}, dotenv: {}, store: h.store, commandName: "gxy" });
  };
  it.each([
    ["token", (h: ReturnType<typeof harness>) => tokenCommand({}, h.deps)],
    ["env", (h: ReturnType<typeof harness>) => envCommand({}, h.deps)],
    ["headers", (h: ReturnType<typeof harness>) => headersCommand({}, h.deps)],
  ])("%s exits 77 with how to log in", async (_n, run) => {
    const h = harness();
    real(h);
    expect(await run(h)).toBe(77);
    expect(h.cap.err).toContain("Not logged in; run gxy auth login --host <url>");
    expect(h.cap.out).toBe("");
  });
  it("still exits 64 for an ambiguous host", async () => {
    const h = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: "https://b.example" as never })] });
    real(h);
    expect(await tokenCommand({}, h.deps)).toBe(64);
  });
  it("still exits 64 for a genuinely bad --host", async () => {
    const h = harness();
    real(h);
    expect(await tokenCommand({ host: "http://remote.example" }, h.deps)).toBe(76); // insecure is 76, not 77
  });
  it("leaves resolveHost a usage error for login, which prompts on it", async () => {
    await expect(resolveHost({ env: {}, dotenv: {}, store: { list: async () => [] } })).rejects.toMatchObject({ kind: "usage" });
  });
});
