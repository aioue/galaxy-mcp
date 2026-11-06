import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { envCommand } from "../../src/auth/commands/env";
import { headersCommand } from "../../src/auth/commands/headers";
import { loginCommand } from "../../src/auth/commands/login";
import { logoutCommand } from "../../src/auth/commands/logout";
import { statusCommand } from "../../src/auth/commands/status";
import { tokenCommand } from "../../src/auth/commands/token";
import { sanitize } from "../../src/auth/commands/common";
import { FileStore } from "../../src/auth/file-store";
import { KeyringStore } from "../../src/auth/keyring-store";
import { CombinedStore } from "../../src/auth/store";
import { AuthError } from "../../src/auth/types";
import { FakeKeyring } from "./support";
import { FAKE_TOKEN, HOST, OTHER, fakeLogin, harness } from "./fakes";

const HOST_ARG = "https://dev.galaxy.example.org";
// Our own multi-line output keeps its newlines; everything else a terminal could act on must go.
// eslint-disable-next-line no-control-regex
const CONTROL_EXCEPT_NEWLINE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/;

describe("sanitize", () => {
  it("removes ESC, C0, DEL and C1 controls, including CR and LF", () => {
    expect(sanitize("a\u001b]0;x\u0007b\u001b[2Jc\r\nd\u007fe\u009bf\tg")).toBe("a]0;xb[2Jcdefg");
    expect(sanitize("ordinary text, ✓ and é")).toBe("ordinary text, ✓ and é");
  });
  it("can keep newlines for our own multi-line messages", () => {
    expect(sanitize("a\nb\u001b[0m\r", { keepNewlines: true })).toBe("a\nb[0m");
  });
});

describe("server text is sanitised before it is printed", () => {
  const EVIL = "\u001b]0;pwned\u0007\u001b[2J";

  it("login: user code, verification URI and username", async () => {
    const h = harness();
    h.server.pending.userCode = `AB${EVIL}CD`;
    h.server.pending.verificationUri = `https://dev.galaxy.example.org/${EVIL}device`;
    h.knobs.whoami = { username: `evil${EVIL}user`, email: "e@example.org" };
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(0);
    expect(h.cap.err).not.toMatch(CONTROL_EXCEPT_NEWLINE);
    expect(h.cap.err).toContain("One-time code: AB]0;pwned[2JCD");
    expect(h.cap.err).toContain("Logged in to dev.galaxy.example.org as evil]0;pwned[2Juser");
  });

  it("status: username, whoami error text and stored username", async () => {
    const h = harness({ stored: [fakeLogin({ username: `st${EVIL}ored` })] });
    h.knobs.whoami = new AuthError("not_logged_in", `bad${EVIL}key`);
    await statusCommand({}, h.deps);
    expect(h.cap.err).not.toMatch(CONTROL_EXCEPT_NEWLINE);
    const j = harness({ stored: [fakeLogin()] });
    j.knobs.whoami = { username: `u${EVIL}x` };
    await statusCommand({ json: true }, j.deps);
    expect(JSON.parse(j.cap.out)[0].username).toBe("u]0;pwned[2Jx");
  });

  it("failures: an AuthError quoting the server", async () => {
    const h = harness();
    h.knobs.discoverError = new AuthError("protocol", `refused: ${EVIL}`);
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(76);
    expect(h.cap.err).not.toMatch(CONTROL_EXCEPT_NEWLINE);
  });

  it("logout: the revocation error text", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.server.revokeError = new Error(`no${EVIL}pe`);
    await logoutCommand({}, h.deps);
    expect(h.cap.err).not.toMatch(CONTROL_EXCEPT_NEWLINE);
    expect(h.cap.err).toContain("no]0;pwned[2Jpe");
  });
});

describe("auth headers and CLAUDE_CODE_MCP_SERVER_URL", () => {
  const MCP = "https://dev.galaxy.example.org/api/mcp";
  const stored = () => harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, token: "other-fake-token" })], env: { CLAUDE_CODE_MCP_SERVER_URL: MCP } });

  it("picks the stored login for the server URL's Galaxy when --host is not given", async () => {
    const h = stored();
    expect(await headersCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe(`{"x-api-key":"${FAKE_TOKEN}"}\n`);
  });

  it("works with a path prefix and a trailing slash", async () => {
    const prefixed = fakeLogin({ baseUrl: "https://dev.galaxy.example.org/galaxy" as never, token: "prefixed-fake-token" });
    const h = harness({ stored: [fakeLogin(), prefixed], env: { CLAUDE_CODE_MCP_SERVER_URL: "https://DEV.galaxy.example.org/galaxy/api/mcp/" } });
    await headersCommand({}, h.deps);
    expect(h.cap.out).toBe('{"x-api-key":"prefixed-fake-token"}\n');
  });

  it("refuses with 77 and prints nothing when no stored login matches that Galaxy", async () => {
    const h = harness({ stored: [fakeLogin()], env: { CLAUDE_CODE_MCP_SERVER_URL: "https://evil.example/api/mcp" } });
    expect(await headersCommand({}, h.deps)).toBe(77);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("does not match by prefix: a Galaxy at a longer or shorter path is another Galaxy", async () => {
    for (const url of ["https://dev.galaxy.example.org/galaxy/api/mcp", "https://dev.galaxy.example.org.evil.example/api/mcp"]) {
      const h = harness({ stored: [fakeLogin()], env: { CLAUDE_CODE_MCP_SERVER_URL: url } });
      expect(await headersCommand({}, h.deps)).toBe(77);
      expect(h.cap.out).toBe("");
    }
  });

  it("does not fall back to GALAXY_URL or the only stored login when the server URL names another Galaxy", async () => {
    const h = harness({ stored: [fakeLogin()], hostFromEnv: HOST_ARG, env: { CLAUDE_CODE_MCP_SERVER_URL: "https://evil.example/api/mcp" } });
    expect(await headersCommand({}, h.deps)).toBe(77);
    expect(h.cap.out).toBe("");
  });

  it("refuses when --host and the server URL disagree, and accepts them when they agree", async () => {
    const bad = stored();
    expect(await headersCommand({ host: "https://other.example.org" }, bad.deps)).toBe(77);
    expect(bad.cap.out).toBe("");
    const ok = stored();
    expect(await headersCommand({ host: "DEV.galaxy.example.org/api" }, ok.deps)).toBe(0);
    expect(ok.cap.out).toBe(`{"x-api-key":"${FAKE_TOKEN}"}\n`);
  });

  it("refuses an unparseable server URL", async () => {
    const h = harness({ stored: [fakeLogin()], env: { CLAUDE_CODE_MCP_SERVER_URL: "not a url" } });
    expect(await headersCommand({}, h.deps)).toBe(77);
    expect(h.cap.out).toBe("");
  });

  it("without the variable, behaves as before", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await headersCommand({}, h.deps)).toBe(0);
  });

  it("an expired login is refused for the server URL too", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })], env: { CLAUDE_CODE_MCP_SERVER_URL: MCP } });
    expect(await headersCommand({}, h.deps)).toBe(77);
    expect(h.cap.out).toBe("");
  });
});

describe("admin and non-expiring warnings", () => {
  it("login prints a full-admin warning when whoami says is_admin", async () => {
    const h = harness();
    h.knobs.whoami = { username: "root", isAdmin: true };
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("! This token carries full admin rights on dev.galaxy.example.org");
    expect(h.store.putCalls[0]!.opts?.requireKeyring).toBe(true);
  });

  it("login prints no admin warning for an ordinary user", async () => {
    const h = harness();
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.cap.err).not.toContain("admin rights");
    expect(h.store.putCalls[0]!.opts?.requireKeyring).toBeUndefined();
  });

  it("a pasted key gets a separate no-expiry warning", async () => {
    const h = harness({ stdinText: "fake-pasted-key\n" });
    await loginCommand({ host: HOST_ARG, withToken: true }, h.deps);
    expect(h.cap.err).toContain("! This token has no expiry");
    expect(h.cap.err).not.toContain("admin rights");
    const a = harness({ stdinText: "fake-pasted-key\n" });
    a.knobs.whoami = { username: "root", isAdmin: true };
    await loginCommand({ host: HOST_ARG, withToken: true }, a.deps);
    expect(a.cap.err).toContain("admin rights");
    expect(a.cap.err).toContain("no expiry");
  });

  it("status warns for an admin and for a non-expiring token, and --json carries is_admin", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
    h.knobs.whoami = { username: "root", isAdmin: true };
    await statusCommand({}, h.deps);
    expect(h.cap.err).toContain("full admin rights on dev.galaxy.example.org");
    expect(h.cap.err).toContain("no expiry");
    const j = harness({ stored: [fakeLogin()] });
    j.knobs.whoami = { username: "root", isAdmin: true };
    await statusCommand({ json: true }, j.deps);
    expect(JSON.parse(j.cap.out)[0].is_admin).toBe(true);
    const n = harness({ stored: [fakeLogin()] });
    await statusCommand({ json: true }, n.deps);
    expect(JSON.parse(n.cap.out)[0].is_admin).toBeNull();
  });
});

describe("admin tokens and the plaintext file", () => {
  it("login stores nothing and exits 77 when the keyring is unavailable", async () => {
    const h = harness();
    h.store.keyringAvailable = false;
    h.knobs.whoami = { username: "root", isAdmin: true };
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(77);
    expect(h.store.logins.size).toBe(0);
    expect(h.cap.err).toContain("No system keyring here");
    expect(h.cap.err).toContain("--insecure-storage");
    expect(h.cap.err).toContain("GALAXY_API_KEY");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("same for a pasted admin key", async () => {
    const h = harness({ stdinText: "fake-pasted-key\n" });
    h.store.keyringAvailable = false;
    h.knobs.whoami = { username: "root", isAdmin: true };
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(77);
    expect(h.store.logins.size).toBe(0);
  });

  it("--insecure-storage keeps an admin token in the file by choice", async () => {
    const h = harness();
    h.store.keyringAvailable = false;
    h.knobs.whoami = { username: "root", isAdmin: true };
    expect(await loginCommand({ host: HOST_ARG, insecureStorage: true }, h.deps)).toBe(0);
    expect(h.store.logins.get(HOST)?.storage).toBe("file");
  });

  it("a non-admin user keeps the automatic file fallback", async () => {
    const h = harness();
    h.store.keyringAvailable = false;
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(0);
    expect(h.store.logins.size).toBe(1);
  });
});

describe("logout is complete when the server is down (real store, fake keyring)", () => {
  let root: string;
  let kr: FakeKeyring;
  let file: FileStore;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "gxy-lo-"));
    kr = new FakeKeyring();
    file = new FileStore(join(root, "cfg"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("deletes the keyring secret and the record, and reports the failed revoke", async () => {
    const store = new CombinedStore(file, new KeyringStore(kr, 50));
    await store.put(fakeLogin());
    const h = harness();
    h.deps.store = store;
    h.deps.resolveHost = async () => HOST;
    h.knobs.discoverError = new AuthError("network", "connection refused");
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(kr.data.size).toBe(0);
    expect(await file.list()).toEqual([]);
    expect(h.cap.err).toContain("Could not revoke the token on the server (connection refused)");
  });

  it("deletes a file-stored token too, leaving no copy in hosts.yml", async () => {
    kr.mode = "throw";
    const store = new CombinedStore(file, new KeyringStore(kr, 50));
    await store.put(fakeLogin(), { insecureStorage: true });
    expect(await readFile(file.path, "utf8")).toContain(fakeLogin().token);
    const h = harness();
    h.deps.store = store;
    h.deps.resolveHost = async () => HOST;
    h.knobs.discoverError = new AuthError("network", "connection refused");
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(await readFile(file.path, "utf8")).not.toContain(fakeLogin().token);
  });

  it("says the secret may remain, and exits 1, when the keyring will not confirm the delete", async () => {
    const store = new CombinedStore(file, new KeyringStore(kr, 50));
    await store.put(fakeLogin());
    kr.mode = "undeletable";
    const h = harness();
    h.deps.store = store;
    h.deps.resolveHost = async () => HOST;
    h.knobs.discoverError = new AuthError("network", "connection refused");
    expect(await logoutCommand({}, h.deps)).toBe(1);
    expect(await file.list()).toEqual([]);
    expect(h.cap.err).toContain("may remain");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });
});

describe("the token goes to stdout only where it belongs", () => {
  type H = ReturnType<typeof harness>;
  const cases: [name: string, secretOnStdout: boolean, run: (h: H) => Promise<number>][] = [
    ["token", true, (h) => tokenCommand({}, h.deps)],
    ["token --json", true, (h) => tokenCommand({ json: true }, h.deps)],
    ["env", true, (h) => envCommand({}, h.deps)],
    ["env --shell fish", true, (h) => envCommand({ shell: "fish" }, h.deps)],
    ["env --shell powershell", true, (h) => envCommand({ shell: "powershell" }, h.deps)],
    ["headers", true, (h) => headersCommand({}, h.deps)],
    ["status --show-token", true, (h) => statusCommand({ showToken: true }, h.deps)],
    ["status --json --show-token", true, (h) => statusCommand({ json: true, showToken: true }, h.deps)],
    ["status", false, (h) => statusCommand({}, h.deps)],
    ["status --json", false, (h) => statusCommand({ json: true }, h.deps)],
    ["status --host", false, (h) => statusCommand({ host: HOST_ARG }, h.deps)],
    ["logout", false, (h) => logoutCommand({}, h.deps)],
  ];

  it.each(cases)("%s", async (_name, secretOnStdout, run) => {
    const h = harness({ stored: [fakeLogin()] });
    await run(h);
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
    expect(h.cap.out.includes(FAKE_TOKEN)).toBe(secretOnStdout);
  });

  it.each([
    ["token", false, (h: H) => tokenCommand({}, h.deps)],
    ["token --json", false, (h: H) => tokenCommand({ json: true }, h.deps)],
    ["env", false, (h: H) => envCommand({}, h.deps)],
    ["headers", false, (h: H) => headersCommand({}, h.deps)],
    ["status", true, (h: H) => statusCommand({}, h.deps)],
    ["status --json", true, (h: H) => statusCommand({ json: true }, h.deps)],
    ["logout", true, (h: H) => logoutCommand({}, h.deps)],
  ])("%s: no token anywhere when the login is expired, missing or the server fails", async (_name, withServerFailures, run) => {
    // `token`, `env` and `headers` print a valid login by design, so for them only the
    // expired and missing cases apply; the commands that talk to the server get the failures too.
    const makers = [
      () => harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })] }),
      () => harness(),
      ...(withServerFailures
        ? [
            () => {
              const h = harness({ stored: [fakeLogin()] });
              h.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the key");
              h.knobs.discoverError = new AuthError("network", "no route");
              h.server.revokeError = new Error("boom");
              return h;
            },
          ]
        : []),
    ];
    for (const make of makers) {
      const h = make();
      h.deps.resolveHost = async () => HOST;
      await run(h);
      expect(h.cap.err).not.toContain(FAKE_TOKEN);
      if (_name !== "status --json" || !withServerFailures) expect(h.cap.out).not.toContain(FAKE_TOKEN);
    }
  });

  it("login (device and pasted, success and failure) never prints the token or the device code", async () => {
    const make = (stdinText?: string) => harness(stdinText === undefined ? {} : { stdinText });
    const runs: [H, Promise<number>][] = [];
    const a = make();
    runs.push([a, loginCommand({ host: HOST_ARG }, a.deps)]);
    const b = make(`${FAKE_TOKEN}\n`);
    runs.push([b, loginCommand({ host: HOST_ARG, withToken: true }, b.deps)]);
    const c = make(`${FAKE_TOKEN}\n`);
    c.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the key");
    runs.push([c, loginCommand({ host: HOST_ARG, withToken: true }, c.deps)]);
    const d = make();
    d.store.keyringAvailable = false;
    d.knobs.whoami = { username: "root", isAdmin: true };
    runs.push([d, loginCommand({ host: HOST_ARG }, d.deps)]);
    for (const [h, p] of runs) {
      await p;
      expect(h.cap.out).toBe("");
      expect(h.cap.err).not.toContain(FAKE_TOKEN);
      expect(h.cap.err).not.toContain(h.server.pending.deviceCode);
    }
  });

  it("error messages thrown by the store carry no token", async () => {
    const h = harness();
    h.store.keyringAvailable = false;
    h.knobs.whoami = { username: "root", isAdmin: true };
    const e = await h.store.put(fakeLogin(), { requireKeyring: true }).catch((x: unknown) => x);
    expect((e as Error).message).not.toContain(FAKE_TOKEN);
  });
});
