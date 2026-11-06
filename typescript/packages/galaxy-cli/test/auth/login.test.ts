import { describe, it, expect, vi } from "vitest";
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
    await vi.waitFor(() => expect(h.cap.err).toContain("Waiting for approval"));
    expect(h.cap.err).toContain("Press Enter to open that page in your browser…");
    expect(h.opened).toEqual([]);
    h.stdin.write("\n");
    await vi.waitFor(() => expect(h.opened).toEqual(["https://dev.galaxy.example.org/login/device"]));
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
      "dev.galaxy.example.org does not offer device login yet (it may be switched off by its admins). Paste an API key instead: gxy auth login --host https://dev.galaxy.example.org --with-token",
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
    await vi.waitFor(() => expect(h.cap.err).toContain("Waiting for approval"));
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

const never = <T,>() => new Promise<T>(() => {});

describe("auth login: Ctrl-C cancels every step (M4)", () => {
  const cancelled = (h: ReturnType<typeof harness>, code: number) => {
    expect(code).toBe(130);
    expect(h.cap.err).toContain("Cancelled.");
    expect(h.store.putCalls).toEqual([]);
    expect(h.cap.out).toBe("");
  };

  it("does nothing when the signal is already aborted", async () => {
    const h = harness();
    const ac = new AbortController();
    ac.abort();
    cancelled(h, await loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps));
    expect(h.server.startedWith).toEqual([]);
  });

  it("cancels during discovery, hands it the signal, and starts no device authorization", async () => {
    const h = harness();
    const ac = new AbortController();
    let seen: AbortSignal | undefined;
    h.deps.discover = (_b, signal) => ((seen = signal), never());
    const p = loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps);
    await vi.waitFor(() => expect(seen).toBeDefined());
    ac.abort();
    cancelled(h, await p);
    expect(seen).toBe(ac.signal);
    expect(h.server.startedWith).toEqual([]);
  });

  it("creates no server-side code when the cancel lands as discovery finishes", async () => {
    const h = harness();
    const ac = new AbortController();
    h.deps.discover = async () => {
      ac.abort();
      return h.server;
    };
    cancelled(h, await loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps));
    expect(h.server.startedWith).toEqual([]);
  });

  it("cancels while the device authorization request is out", async () => {
    const h = harness();
    const ac = new AbortController();
    h.server.startDeviceLogin = (scopes) => (h.server.startedWith.push(scopes), never());
    const p = loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps);
    await vi.waitFor(() => expect(h.server.startedWith).toHaveLength(1));
    ac.abort();
    cancelled(h, await p);
  });

  it("cancels during whoami after approval, handing it the signal, and stores nothing", async () => {
    const h = harness();
    const ac = new AbortController();
    let seen: AbortSignal | undefined;
    h.deps.whoami = (_b, _t, signal) => ((seen = signal), never());
    const p = loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps);
    await vi.waitFor(() => expect(seen).toBeDefined());
    ac.abort();
    cancelled(h, await p);
    expect(seen).toBe(ac.signal);
  });

  it("does not write the store when the cancel lands as whoami answers", async () => {
    const h = harness();
    const ac = new AbortController();
    h.deps.whoami = async () => {
      ac.abort();
      return { username: "aioue" };
    };
    cancelled(h, await loginCommand({ host: HOST_ARG, signal: ac.signal }, h.deps));
  });

  it("cancels at the Galaxy URL prompt", async () => {
    const h = harness({ interactive: true });
    const ac = new AbortController();
    const p = loginCommand({ signal: ac.signal }, h.deps);
    await vi.waitFor(() => expect(h.cap.err).toContain("Galaxy URL"));
    ac.abort();
    cancelled(h, await p);
  });

  it("cancels while reading a piped key, before any whoami", async () => {
    const h = harness(); // stdin stays open and empty
    const ac = new AbortController();
    const p = loginCommand({ host: HOST_ARG, withToken: true, signal: ac.signal }, h.deps);
    await vi.waitFor(() => expect(h.stdin.listenerCount("data")).toBeGreaterThan(0));
    ac.abort();
    cancelled(h, await p);
    expect(h.whoamiCalls).toEqual([]);
    expect(h.stdin.listenerCount("data")).toBe(0);
  });
});

describe("auth login: the approval page must be on the Galaxy (L1)", () => {
  it.each([
    ["another host", "https://evil.example/login/device"],
    ["plain http on the same host", "http://dev.galaxy.example.org/login/device"],
    ["another port", "https://dev.galaxy.example.org:8443/login/device"],
    ["a non-http scheme", "javascript:alert(1)"],
    ["not a URL", "nonsense"],
  ])("refuses %s: nothing shown, nothing opened, nothing polled", async (_n, uri) => {
    const h = harness({ interactive: true });
    h.server.pending.verificationUri = uri;
    const waited = vi.spyOn(h.server.pending, "waitForApproval");
    expect(await loginCommand({ host: HOST_ARG }, h.deps)).toBe(76);
    expect(h.cap.err).toContain("which is not an https page on dev.galaxy.example.org");
    expect(h.cap.err).toContain("--with-token");
    expect(h.cap.err).not.toContain("One-time code");
    expect(h.cap.err).not.toContain("Enter it at");
    expect(h.opened).toEqual([]);
    expect(waited).not.toHaveBeenCalled();
    expect(h.store.putCalls).toEqual([]);
  });

  it("allows http to a loopback Galaxy, on its own origin", async () => {
    const h = harness();
    h.server.pending.verificationUri = "http://127.0.0.1:8080/login/device";
    expect(await loginCommand({ host: "http://127.0.0.1:8080" }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("Enter it at http://127.0.0.1:8080/login/device");
  });
});

describe("auth login --with-token at a terminal (L5)", () => {
  function tty(h: ReturnType<typeof harness>) {
    const calls: boolean[] = [];
    Object.assign(h.stdin, { isTTY: true, setRawMode: (m: boolean) => void calls.push(m) });
    return calls;
  }

  it("prompts on stderr, reads without echo, and restores the terminal", async () => {
    const h = harness({ interactive: true });
    const raw = tty(h);
    const p = loginCommand({ host: HOST_ARG, withToken: true }, h.deps);
    await vi.waitFor(() => expect(raw).toEqual([true]));
    expect(h.cap.err).toContain("Paste your Galaxy API key: ");
    h.stdin.write(`${FAKE_TOKEN}\r`);
    expect(await p).toBe(0);
    expect(raw).toEqual([true, false]);
    expect(h.whoamiCalls).toEqual([{ baseUrl: HOST, token: FAKE_TOKEN }]);
    expect(h.cap.err + h.cap.out).not.toContain(FAKE_TOKEN);
    expect(h.cap.out).toBe("");
  });

  it("honours backspace and ignores escape sequences from a bracketed paste", async () => {
    const h = harness({ interactive: true });
    tty(h);
    const p = loginCommand({ host: HOST_ARG, withToken: true }, h.deps);
    await vi.waitFor(() => expect(h.stdin.listenerCount("data")).toBeGreaterThan(0));
    h.stdin.write("\x1b[200~abXX\x7f\x7fc\x1b[201~\n");
    expect(await p).toBe(0);
    expect(h.whoamiCalls[0]!.token).toBe("abc");
  });

  it("Ctrl-C at the prompt cancels, with exit 130, nothing stored and raw mode restored", async () => {
    const h = harness({ interactive: true });
    const raw = tty(h);
    const p = loginCommand({ host: HOST_ARG, withToken: true }, h.deps);
    await vi.waitFor(() => expect(raw).toEqual([true]));
    h.stdin.write("fake\x03");
    expect(await p).toBe(130);
    expect(raw).toEqual([true, false]);
    expect(h.cap.err).toContain("Cancelled.");
    expect(h.whoamiCalls).toEqual([]);
    expect(h.store.putCalls).toEqual([]);
  });

  it("restores raw mode when the abort signal fires instead", async () => {
    const h = harness({ interactive: true });
    const raw = tty(h);
    const ac = new AbortController();
    const p = loginCommand({ host: HOST_ARG, withToken: true, signal: ac.signal }, h.deps);
    await vi.waitFor(() => expect(raw).toEqual([true]));
    ac.abort();
    expect(await p).toBe(130);
    expect(raw).toEqual([true, false]);
  });

  it("restores raw mode when the key is refused", async () => {
    const h = harness({ interactive: true });
    const raw = tty(h);
    h.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the key.");
    const p = loginCommand({ host: HOST_ARG, withToken: true }, h.deps);
    await vi.waitFor(() => expect(raw).toEqual([true]));
    h.stdin.write("fake-key\n");
    expect(await p).toBe(77);
    expect(raw).toEqual([true, false]);
  });

  it("does not prompt for a pipe, even when otherwise interactive", async () => {
    const h = harness({ interactive: true, stdinText: FAKE_TOKEN });
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(0);
    expect(h.cap.err).not.toContain("Paste your Galaxy API key");
  });
});

describe("auth login --with-token on a pipe: size cap (L5)", () => {
  it("accepts input right at the cap", async () => {
    const h = harness({ stdinText: "k".repeat(16 * 1024) });
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(0);
  });

  it("refuses more than 16 KiB with a usage error, before any whoami", async () => {
    const h = harness({ stdinText: "k".repeat(16 * 1024 + 1) });
    expect(await loginCommand({ host: HOST_ARG, withToken: true }, h.deps)).toBe(64);
    expect(h.cap.err).toContain("16 KiB");
    expect(h.whoamiCalls).toEqual([]);
    expect(h.cap.err).not.toContain("kkkk");
  });
});
