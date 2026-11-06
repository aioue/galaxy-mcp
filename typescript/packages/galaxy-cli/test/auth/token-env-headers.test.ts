import { describe, it, expect } from "vitest";
import { tokenCommand } from "../../src/auth/commands/token";
import { envCommand, quoteFor } from "../../src/auth/commands/env";
import { headersCommand } from "../../src/auth/commands/headers";
import { FAKE_TOKEN, HOST, OTHER, fakeLogin, harness } from "./fakes";

const cases = [
  ["token", (h: ReturnType<typeof harness>) => tokenCommand({}, h.deps)],
  ["token --json", (h: ReturnType<typeof harness>) => tokenCommand({ json: true }, h.deps)],
  ["env", (h: ReturnType<typeof harness>) => envCommand({}, h.deps)],
  ["headers", (h: ReturnType<typeof harness>) => headersCommand({}, h.deps)],
] as const;

describe("auth token", () => {
  it("prints only the token and a newline", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await tokenCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe(`${FAKE_TOKEN}\n`);
    expect(h.cap.err).toBe("");
  });

  it("--json prints the versioned object", async () => {
    const h = harness({ stored: [fakeLogin()] });
    await tokenCommand({ json: true }, h.deps);
    expect(h.cap.out.endsWith("\n")).toBe(true);
    expect(JSON.parse(h.cap.out)).toEqual({
      version: 1,
      base_url: HOST,
      token: FAKE_TOKEN,
      token_type: "x-api-key",
      expires_at: "2026-11-06T18:42:00.000Z",
    });
  });

  it("--json has expires_at null for a pasted key", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", expiresAt: null, scopes: [] })] });
    await tokenCommand({ json: true }, h.deps);
    expect(JSON.parse(h.cap.out).expires_at).toBeNull();
  });

  it("makes no live call", async () => {
    const h = harness({ stored: [fakeLogin()] });
    await tokenCommand({}, h.deps);
    expect(h.whoamiCalls).toEqual([]);
  });

  it("picks the named host", async () => {
    const h = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, token: "other-fake-token" })] });
    await tokenCommand({ host: "https://other.example.org" }, h.deps);
    expect(h.cap.out).toBe("other-fake-token\n");
  });

  it("is ambiguous with several logins and no host (64)", async () => {
    const h = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER })] });
    expect(await tokenCommand({}, h.deps)).toBe(64);
    expect(h.cap.out).toBe("");
  });
});

describe.each(cases)("%s failures", (_name, run) => {
  it("exits 77 on stderr, with nothing on stdout, when not logged in", async () => {
    const h = harness();
    // a host is known (env) but nothing is stored for it
    h.deps.resolveHost = async () => HOST;
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("gxy auth login --host https://dev.galaxy.example.org");
  });

  it("exits 77 and names the expiry when the login has expired", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })] });
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("expired at 2026-11-06 09:00 UTC");
    expect(h.cap.err).toContain("gxy auth login --host https://dev.galaxy.example.org");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });
});

describe("auth env", () => {
  it("prints sh exports by default", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await envCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe(`export GALAXY_URL='${HOST}'\nexport GALAXY_API_KEY='${FAKE_TOKEN}'\n`);
  });

  it("prints fish and powershell syntax", async () => {
    const f = harness({ stored: [fakeLogin()] });
    await envCommand({ shell: "fish" }, f.deps);
    expect(f.cap.out).toBe(`set -gx GALAXY_URL '${HOST}'\nset -gx GALAXY_API_KEY '${FAKE_TOKEN}'\n`);
    const p = harness({ stored: [fakeLogin()] });
    await envCommand({ shell: "powershell" }, p.deps);
    expect(p.cap.out).toBe(`$env:GALAXY_URL = '${HOST}'\n$env:GALAXY_API_KEY = '${FAKE_TOKEN}'\n`);
  });

  it("rejects an unknown shell", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await envCommand({ shell: "csh" }, h.deps)).toBe(64);
    expect(h.cap.out).toBe("");
  });

  it("quotes hostile values safely", () => {
    expect(quoteFor("sh", `a'b"c$d\`e\\f`)).toBe(`'a'\\''b"c$d\`e\\f'`);
    expect(quoteFor("fish", `a'b\\c`)).toBe(`'a\\'b\\\\c'`);
    expect(quoteFor("powershell", `a'b"c$d\`e`)).toBe(`'a''b"c$d\`e'`);
  });

  it("round-trips a quoted value through a real sh", async () => {
    const { execFileSync } = await import("node:child_process");
    const value = `it's "x" $HOME \`id\` \\ end`;
    const out = execFileSync("sh", ["-c", `printf %s ${quoteFor("sh", value)}`]).toString();
    expect(out).toBe(value);
  });
});

describe("auth headers", () => {
  it("prints the x-api-key header object", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await headersCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe(`{"x-api-key":"${FAKE_TOKEN}"}\n`);
    expect(h.cap.err).toBe("");
  });
});
