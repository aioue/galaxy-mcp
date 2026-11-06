import { describe, it, expect } from "vitest";
import { loginCommand } from "../../src/auth/commands/login";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, fakeLogin, harness } from "./fakes";

const HOST_ARG = "https://dev.galaxy.example.org";

describe("auth login (device flow)", () => {
  it("prints the transcript to stderr, stores the login, and keeps stdout empty", async () => {
    const h = harness();
    const code = await loginCommand({ host: HOST_ARG, scopes: ["histories:read", "tools:run"] }, h.deps);
    expect(code).toBe(0);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("Requesting access to dev.galaxy.example.org");
    expect(h.cap.err).toContain("Scopes  histories:read tools:run");
    expect(h.cap.err).toContain("! Only approve this code if you ran this command yourself.");
    expect(h.cap.err).toContain("One-time code: WDJB-MJHT");
    expect(h.cap.err).toContain("Enter it at https://dev.galaxy.example.org/login/device");
    expect(h.cap.err).toContain("Waiting for approval (code expires in 14:52)…");
    expect(h.cap.err).toContain("✓ Logged in to dev.galaxy.example.org as aioue");
    expect(h.cap.err).toContain("✓ Token stored in the system keyring (expires 2026-11-06 18:42 UTC)");
    expect(h.server.startedWith).toEqual([["histories:read", "tools:run"]]);
    const stored = h.store.putCalls[0]!.login;
    expect(stored).toMatchObject({ baseUrl: HOST, username: "aioue", method: "device", scopes: ["histories:read"], token: FAKE_TOKEN });
    expect(stored.expiresAt).toBe("2026-11-06T18:42:00.000Z");
  });

  it("says 'server default' without --scopes and passes none", async () => {
    const h = harness();
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.cap.err).toContain("Scopes  server default");
    expect(h.server.startedWith).toEqual([undefined]);
  });

  it("never prints the device code or the token", async () => {
    const h = harness();
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.cap.err + h.cap.out).not.toContain(h.server.pending.deviceCode);
    expect(h.cap.err + h.cap.out).not.toContain(FAKE_TOKEN);
  });

  it("does not offer Enter when not interactive, and still polls", async () => {
    const h = harness({ interactive: false });
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(0);
    expect(h.cap.err).not.toContain("Press Enter");
    expect(h.opened).toEqual([]);
  });

  it("offers Enter when interactive with a browser, and opens the page on Enter", async () => {
    const h = harness({ interactive: true });
    h.server.pending.outcome = "hang";
    const ac = new AbortController();
    const p = loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps);
    await new Promise((r) => setTimeout(r, 10));
    expect(h.cap.err).toContain("Press Enter to open that page in your browser…");
    expect(h.opened).toEqual([]);
    h.stdin.write("\n");
    await new Promise((r) => setTimeout(r, 10));
    expect(h.opened).toEqual(["https://dev.galaxy.example.org/login/device"]);
    ac.abort();
    expect(await p).toBe(130);
  });

  it("omits 'Press Enter' with --no-browser or when no browser is available", async () => {
    const a = harness({ interactive: true });
    await loginCommand({ host: HOST_ARG, browser: false }, a.deps);
    expect(a.cap.err).not.toContain("Press Enter");
    const b = harness({ interactive: true });
    b.knobs.browserAvailable = false;
    await loginCommand({ host: HOST_ARG }, b.deps);
    expect(b.cap.err).not.toContain("Press Enter");
  });

  it("stores with no expiry when the server gave none, and prints the storage warning", async () => {
    const h = harness();
    h.server.pending.outcome = { accessToken: FAKE_TOKEN, scopes: [] };
    h.store.nextStorage = "file";
    h.store.nextWarning = "No keyring here; the token went to a file.";
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.store.putCalls[0]!.login.expiresAt).toBeNull();
    expect(h.cap.err).toContain("! No keyring here; the token went to a file.");
    expect(h.cap.err).toContain("✓ Token stored in a file readable only by you (no expiry)");
  });

  it("passes --insecure-storage to the store", async () => {
    const h = harness();
    await loginCommand({ host: HOST_ARG, insecureStorage: true }, h.deps);
    expect(h.store.putCalls[0]!.opts).toEqual({ insecureStorage: true });
  });

  it("checks whoami with the new token before storing", async () => {
    const h = harness();
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.whoamiCalls).toEqual([{ baseUrl: HOST, token: FAKE_TOKEN }]);
  });

  it("stores nothing and exits 77 when whoami rejects the new token", async () => {
    const h = harness();
    h.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the token.");
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(77);
    expect(h.store.putCalls).toEqual([]);
  });

  it("exits 76 with the --with-token hint when device login is off", async () => {
    const h = harness();
    h.server.supportsDeviceFlow = false;
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(76);
    expect(h.cap.err).toContain(
      "dev.galaxy.example.org does not offer device login (it may be switched off by its admins). Paste an API key instead: gxy auth login --host https://dev.galaxy.example.org --with-token",
    );
  });

  it.each([
    ["denied", 77],
    ["expired", 77],
    ["network", 69],
    ["protocol", 76],
  ] as const)("maps a %s failure to exit %i", async (kind, exit) => {
    const h = harness();
    h.server.pending.outcome = new AuthError(kind, `it was ${kind}`);
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(exit);
    expect(h.cap.err).toContain(`it was ${kind}`);
    expect(h.store.putCalls).toEqual([]);
  });

  it("aborts cleanly on Ctrl-C", async () => {
    const h = harness();
    h.server.pending.outcome = "hang";
    const ac = new AbortController();
    const p = loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps);
    await new Promise((r) => setTimeout(r, 5));
    ac.abort();
    expect(await p).toBe(130);
    expect(h.cap.err).toContain("Cancelled.");
    expect(h.store.putCalls).toEqual([]);
  });

  it("warns that GALAXY_API_KEY takes precedence", async () => {
    const h = harness({ env: { GALAXY_API_KEY: "irrelevant" } });
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.cap.err).toContain("GALAXY_API_KEY is set and will take precedence");
    expect(h.cap.err).not.toContain("irrelevant");
  });

  it("is a usage error without a host when not interactive", async () => {
    const h = harness();
    expect(await loginCommand({}, h.deps)).toBe(64);
    expect(h.cap.err).toContain("--host");
  });

  it("prompts for the URL when interactive and nothing names one", async () => {
    const h = harness({ interactive: true });
    h.stdin.write("dev.galaxy.example.org\n");
    expect(await loginCommand({ browser: false }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("Galaxy URL");
    expect(h.store.putCalls[0]!.login.baseUrl).toBe(HOST);
  });

  it("logs in to the one stored host when none is named", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await loginCommand({}, h.deps)).toBe(0);
  });
});

describe("auth login --with-token", () => {
  it("reads the key from stdin, trims it, and stores a pasted login", async () => {
    const h = harness({ stdinText: `  ${FAKE_TOKEN}\n` });
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(0);
    expect(h.whoamiCalls).toEqual([{ baseUrl: HOST, token: FAKE_TOKEN }]);
    expect(h.store.putCalls[0]!.login).toMatchObject({ method: "pasted", scopes: [], expiresAt: null, token: FAKE_TOKEN, username: "aioue" });
    expect(h.cap.err).toContain("✓ Logged in to dev.galaxy.example.org as aioue");
    expect(h.cap.err).toContain("(no expiry)");
    expect(h.cap.out).toBe("");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("does not use the device flow", async () => {
    const h = harness({ stdinText: FAKE_TOKEN });
    await loginCommand({ host: HOST_ARG, withToken: true }, h.deps);
    expect(h.server.startedWith).toEqual([]);
  });

  it.each([["empty", ""], ["blank", "  \n"], ["multi-line", "abc\ndef\n"]])("refuses %s input", async (_n, text) => {
    const h = harness({ stdinText: text });
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(64);
    expect(h.store.putCalls).toEqual([]);
    expect(h.cap.err).not.toContain("abc");
  });

  it("exits 77 and stores nothing when Galaxy rejects the key", async () => {
    const h = harness({ stdinText: FAKE_TOKEN });
    h.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the key.");
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(77);
    expect(h.store.putCalls).toEqual([]);
  });
});
