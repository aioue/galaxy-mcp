import { execFileSync } from "node:child_process";
import { describe, it, expect } from "vitest";
import { tokenCommand } from "../../src/auth/commands/token";
import { envCommand, quoteFor } from "../../src/auth/commands/env";
import { headersCommand } from "../../src/auth/commands/headers";
import { DAY, FAKE_TOKEN, HOST, OTHER, fakeLogin, harness } from "./harness";

type H = ReturnType<typeof harness>;
const commands: [string, (h: H) => Promise<number>][] = [
  ["token", (h) => tokenCommand({}, h.deps)],
  ["token --json", (h) => tokenCommand({ json: true }, h.deps)],
  ["env", (h) => envCommand({}, h.deps)],
  ["headers", (h) => headersCommand({}, h.deps)],
];

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
    await tokenCommand({ host: OTHER }, h.deps);
    expect(h.cap.out).toBe("other-fake-token\n");
  });
});

describe.each(commands)("%s when there is nothing to hand out", (_name, run) => {
  it("exits 77 on stderr, with nothing on stdout, when not logged in", async () => {
    const h = harness();
    // a host is known (env) but nothing is stored for it
    h.deps.resolveHost = async () => HOST;
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain(`gxy auth login --host ${HOST}`);
  });

  it("exits 77 with how to log in when nothing is stored and nothing names a host", async () => {
    const h = harness();
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("Not logged in; run gxy auth login --host <url>");
  });

  it("exits 77, as about to expire, for a login with under a minute left", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: new Date(new Date(DAY).getTime() + 30_000).toISOString() })] });
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toMatch(/about to expire/);
  });

  it("exits 77 and says the expiry is unreadable, rather than treating it as none", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "tomorrow" })] });
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toMatch(/unreadable expiry time \(tomorrow\)/);
  });

  it("exits 77 and names the expiry when the login has expired", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })] });
    expect(await run(h)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("expired at 2026-11-06 09:00 UTC");
    expect(h.cap.err).toContain(`gxy auth login --host ${HOST}`);
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });
});

describe("choosing the host", () => {
  it("exits 64, not 77, when several logins are stored and none is named", async () => {
    const h = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER })] });
    expect(await tokenCommand({}, h.deps)).toBe(64);
    expect(h.cap.out).toBe("");
  });

  it("exits 76, not 77, for an insecure --host", async () => {
    const h = harness();
    expect(await tokenCommand({ host: "http://remote.example" }, h.deps)).toBe(76);
  });
});

describe("auth env", () => {
  it("prints sh exports by default", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await envCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe(`export GALAXY_URL='${HOST}'\nexport GALAXY_API_KEY='${FAKE_TOKEN}'\n`);
  });

  it.each([
    ["fish", `set -gx GALAXY_URL '${HOST}'\nset -gx GALAXY_API_KEY '${FAKE_TOKEN}'\n`],
    ["powershell", `$env:GALAXY_URL = '${HOST}'\n$env:GALAXY_API_KEY = '${FAKE_TOKEN}'\n`],
  ])("prints %s syntax", async (shell, expected) => {
    const h = harness({ stored: [fakeLogin()] });
    await envCommand({ shell }, h.deps);
    expect(h.cap.out).toBe(expected);
  });

  it("rejects an unknown shell", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await envCommand({ shell: "csh" }, h.deps)).toBe(64);
    expect(h.cap.out).toBe("");
  });

  describe("quoting", () => {
    it("survives a real sh, whatever the value holds", () => {
      const value = `it's "x" $HOME \`id\` \\ end`;
      expect(execFileSync("sh", ["-c", `printf %s ${quoteFor("sh", value)}`]).toString()).toBe(value);
    });

    // No fish or PowerShell here to run them, so their exact quoting is pinned.
    it("escapes quotes and backslashes for fish", () => {
      expect(quoteFor("fish", `a'b\\c`)).toBe(`'a\\'b\\\\c'`);
    });

    it("doubles single quotes for PowerShell, curly ones included, and leaves double quotes alone", () => {
      expect(quoteFor("powershell", `a'b"c$d\`e`)).toBe(`'a''b"c$d\`e'`);
      for (const q of ["‘", "’", "‚", "‛"]) expect(quoteFor("powershell", `a${q}b`)).toBe(`'a${q}${q}b'`);
      expect(quoteFor("powershell", "a“b")).toBe("'a“b'");
    });
  });
});

describe("auth headers", () => {
  it("prints the x-api-key header object", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await headersCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe(`{"x-api-key":"${FAKE_TOKEN}"}\n`);
    expect(h.cap.err).toBe("");
  });

  // Claude Code names the MCP server it is asking for headers for. A token must only go to
  // the Galaxy that server is.
  describe("when CLAUDE_CODE_MCP_SERVER_URL names the server", () => {
    const MCP = "https://dev.galaxy.example.org/api/mcp";
    const two = (mcpUrl = MCP) =>
      harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, token: "other-fake-token" })], env: { CLAUDE_CODE_MCP_SERVER_URL: mcpUrl } });

    it("picks the stored login for that Galaxy when --host is not given", async () => {
      const h = two();
      expect(await headersCommand({}, h.deps)).toBe(0);
      expect(h.cap.out).toBe(`{"x-api-key":"${FAKE_TOKEN}"}\n`);
    });

    it("works with a path prefix, a trailing slash and a differently cased host", async () => {
      const prefixed = fakeLogin({ baseUrl: "https://dev.galaxy.example.org/galaxy" as never, token: "prefixed-fake-token" });
      const h = harness({ stored: [fakeLogin(), prefixed], env: { CLAUDE_CODE_MCP_SERVER_URL: "https://DEV.galaxy.example.org/galaxy/api/mcp/" } });
      await headersCommand({}, h.deps);
      expect(h.cap.out).toBe('{"x-api-key":"prefixed-fake-token"}\n');
    });

    it.each([
      ["another Galaxy", "https://evil.example/api/mcp"],
      ["a longer path", "https://dev.galaxy.example.org/galaxy/api/mcp"],
      ["a host that only starts the same", "https://dev.galaxy.example.org.evil.example/api/mcp"],
      ["something that is not a URL", "not a url"],
    ])("refuses with 77 and prints nothing for %s", async (_what, serverUrl) => {
      const h = harness({ stored: [fakeLogin()], env: { CLAUDE_CODE_MCP_SERVER_URL: serverUrl } });
      expect(await headersCommand({}, h.deps)).toBe(77);
      expect(h.cap.out).toBe("");
      expect(h.cap.err).not.toContain(FAKE_TOKEN);
    });

    it("does not fall back to GALAXY_URL or the only stored login", async () => {
      const h = harness({ stored: [fakeLogin()], hostFromEnv: "https://dev.galaxy.example.org", env: { CLAUDE_CODE_MCP_SERVER_URL: "https://evil.example/api/mcp" } });
      expect(await headersCommand({}, h.deps)).toBe(77);
      expect(h.cap.out).toBe("");
    });

    it("refuses when --host disagrees with it, and accepts them when they agree", async () => {
      const disagree = two();
      expect(await headersCommand({ host: OTHER }, disagree.deps)).toBe(77);
      expect(disagree.cap.out).toBe("");
      const agree = two();
      expect(await headersCommand({ host: "DEV.galaxy.example.org/api" }, agree.deps)).toBe(0);
      expect(agree.cap.out).toBe(`{"x-api-key":"${FAKE_TOKEN}"}\n`);
    });

    it("refuses an expired login too", async () => {
      const h = harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })], env: { CLAUDE_CODE_MCP_SERVER_URL: MCP } });
      expect(await headersCommand({}, h.deps)).toBe(77);
      expect(h.cap.out).toBe("");
    });
  });
});
