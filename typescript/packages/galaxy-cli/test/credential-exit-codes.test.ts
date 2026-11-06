import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildProgram } from "../src/program";
import { normalizeBaseUrl } from "../src/auth/base-url";
import { resolveConnection } from "../src/config";

/** The real credential path of an operation (no makeContext), against a temp config dir. */
let root: string;
const saved: Record<string, string | undefined> = {};
const KEYS = ["GXY_CONFIG_DIR", "GXY_NO_KEYRING", "HOME", "GALAXY_URL", "GALAXY_API_KEY"];
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "gxy-exit-"));
  for (const k of KEYS) saved[k] = process.env[k];
  delete process.env.GALAXY_URL;
  delete process.env.GALAXY_API_KEY;
  process.env.HOME = root; // no ~/.planemo.yml
  process.env.GXY_NO_KEYRING = "1";
  process.env.GXY_CONFIG_DIR = join(root, "cfg");
  await mkdir(join(root, "cfg"), { mode: 0o700 });
});
afterEach(async () => {
  for (const k of KEYS) saved[k] === undefined ? delete process.env[k] : (process.env[k] = saved[k]);
  await rm(root, { recursive: true, force: true });
  process.exitCode = 0;
});

const host = (url: string, expires: string | null) =>
  `  ${url}:\n    username: alice\n    method: device\n    scopes: []\n    expires_at: ${expires === null ? "null" : `"${expires}"`}\n    obtained_at: "2026-01-01T00:00:00.000Z"\n    storage: file\n    token: FAKE-TOKEN\n`;

async function run(hosts: string) {
  await writeFile(join(root, "cfg", "hosts.yml"), `hosts:\n${hosts}`, { mode: 0o600 });
  const err = vi.spyOn(console, "error").mockImplementation(() => {});
  process.exitCode = 0;
  try {
    await buildProgram().parseAsync(["node", "gxy", "get_user"]);
    return { exitCode: process.exitCode, stderr: err.mock.calls.flat().join("\n") };
  } finally {
    err.mockRestore();
  }
}

describe("credential errors exit by kind", () => {
  it("an expired login with no other key exits 77 with the spec's message", async () => {
    const r = await run(host("https://galaxy.example.org", "2020-01-01T00:00:00.000Z"));
    expect(r.exitCode).toBe(77);
    expect(r.stderr).toMatch(/Your login to https:\/\/galaxy\.example\.org expired at 2020-01-01 00:00 UTC; run gxy auth login --host https:\/\/galaxy\.example\.org/);
  });
  it("several stored logins and no URL exits 64", async () => {
    const r = await run(host("https://a.example.org", null) + host("https://b.example.org", null));
    expect(r.exitCode).toBe(64);
    expect(r.stderr).toContain("Logged in to several Galaxies");
  });
  it("any other credential problem stays 64", async () => {
    const r = await run("  {}\n");
    expect(r.exitCode).toBe(64);
    expect(r.stderr).toMatch(/No Galaxy credentials/);
  });
});

describe("the stored key goes to the normalised URL", () => {
  it("returns login.baseUrl, not the raw URL it matched", () => {
    const url = normalizeBaseUrl("https://good.example.org");
    const conn = resolveConnection(
      { url: "https://GOOD.example.org/?x=1" },
      {
        env: {}, dotenv: {}, profiles: {}, storedBaseUrls: [url], now: new Date("2026-06-01T00:00:00Z"),
        storedLogin: { baseUrl: url, username: "a", token: "STORED", method: "device", scopes: [], expiresAt: null, obtainedAt: "2026-01-01T00:00:00.000Z" },
      },
    );
    expect(conn.baseUrl).toBe(url);
    expect(conn.apiKey).toBe("STORED");
  });
  it("keeps the raw URL when an explicit key is used", () => {
    const conn = resolveConnection({ url: "https://x.example.org/?q", apiKey: "K" }, { env: {}, dotenv: {}, profiles: {} });
    expect(conn.baseUrl).toBe("https://x.example.org/?q");
  });
});
