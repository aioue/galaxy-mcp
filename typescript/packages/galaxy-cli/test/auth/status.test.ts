/**
 * `status` in process: every stored login is read back and checked live against its Galaxy, one
 * host at a time, and printed to stderr. stdout is only for what a script asked for (`--json`,
 * `--show-token`).
 */
import { describe, it, expect } from "vitest";
import { statusCommand } from "../../src/auth/commands/status";
import { createWhoami } from "../../src/auth/whoami";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, OTHER, fakeLogin, harness, makeTokenUnreadable } from "./harness";

const expiredLogin = () => fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" });
const twoLogins = () => harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, username: "bob" })] });

describe("auth status", () => {
  it("shows a live check, storage, method, scopes, time left and a masked token, on stderr", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await statusCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("dev.galaxy.example.org");
    expect(h.cap.err).toContain("Logged in as aioue");
    expect(h.cap.err).toMatch(/Storage\s+system keyring/);
    expect(h.cap.err).toMatch(/Method\s+device login/);
    expect(h.cap.err).toMatch(/Scopes\s+histories:read tools:run/);
    expect(h.cap.err).toMatch(/Expires\s+in 7h/);
    // The token is masked: only its last four characters show.
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
    expect(h.cap.err).toContain(FAKE_TOKEN.slice(-4));
    expect(h.whoamiCalls).toHaveLength(1);
  });

  // `--show-token` is the one way `status` prints a token, and it goes to stdout, where a script
  // reads data, like `auth token`. stderr always carries the masked form, so it stays safe to log.
  it("puts the unmasked token on stdout, never stderr, with --show-token", async () => {
    const h = harness({ stored: [fakeLogin()] });
    await statusCommand({ showToken: true }, h.deps);
    expect(h.cap.out).toBe(`${HOST}\t${FAKE_TOKEN}\n`);
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("says 'no expiry' and 'pasted' for a pasted key", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
    await statusCommand({}, h.deps);
    expect(h.cap.err).toMatch(/Expires\s+no expiry/);
    expect(h.cap.err).toMatch(/Method\s+pasted API key/);
  });

  it("lists every stored login, or just the one with --host", async () => {
    const all = twoLogins();
    await statusCommand({}, all.deps);
    expect(all.cap.err).toContain("dev.galaxy.example.org");
    expect(all.cap.err).toContain("other.example.org");

    const one = twoLogins();
    await statusCommand({ host: OTHER }, one.deps);
    expect(one.cap.err).not.toContain("dev.galaxy.example.org");
    expect(one.cap.err).toContain("other.example.org");
  });

  // An expiry the clock already shows needs no request to find out, so none is made: `whoamiCalls`
  // is empty, and the token goes nowhere.
  it("exits 1 and skips the live check for an expired login", async () => {
    const h = harness({ stored: [expiredLogin()] });
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("expired at 2026-11-06 09:00 UTC");
    expect(h.whoamiCalls).toEqual([]);
  });

  it.each([
    ["Galaxy rejects the token", new AuthError("not_logged_in", "Galaxy rejected the token.")],
    ["Galaxy cannot be reached", new AuthError("network", "Could not reach dev.galaxy.example.org.")],
  ])("exits 1 and says why when %s", async (_when, failure) => {
    const h = harness({ stored: [fakeLogin()] });
    h.knobs.whoami = failure;
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain(failure.message);
  });

  it("names the certificate setting when Galaxy cannot be reached securely", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.deps.whoami = createWhoami((async () => {
      throw new TypeError("fetch failed", { cause: Object.assign(new Error("self-signed certificate"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" }) });
    }) as unknown as typeof fetch);
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("NODE_EXTRA_CA_CERTS");
  });

  it("notes that GALAXY_API_KEY overrides stored logins", async () => {
    const h = harness({ stored: [fakeLogin()], env: { GALAXY_API_KEY: "x" } });
    await statusCommand({}, h.deps);
    expect(h.cap.err).toContain("GALAXY_API_KEY is set and takes precedence over stored logins");
  });

  // 77 is EX_NOPERM, as for the other commands that find nothing to use: not logged in.
  it("with nothing stored, says so and exits 77", async () => {
    const h = harness();
    expect(await statusCommand({}, h.deps)).toBe(77);
    expect(h.cap.err).toContain("No stored logins");
  });

  it("with --host and no login for it, says so, names the login command, and exits 77", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await statusCommand({ host: OTHER }, h.deps)).toBe(77);
    expect(h.cap.err).toContain("Not logged in to other.example.org");
    expect(h.cap.err).toContain(`gxy auth login --host ${OTHER}`);
    expect(h.whoamiCalls).toEqual([]);
  });

  it("reports an unreadable store as an unexpected error, exit 70", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.store.list = async () => {
      throw new Error("store is broken");
    };
    expect(await statusCommand({}, h.deps)).toBe(70);
    expect(h.cap.err).toContain("store is broken");
  });

  describe("warnings", () => {
    it("warns for an admin and for a token that does not expire", async () => {
      const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
      h.knobs.whoami = { username: "root", isAdmin: true };
      await statusCommand({}, h.deps);
      expect(h.cap.err).toContain("full admin rights on dev.galaxy.example.org");
      expect(h.cap.err).toContain("no expiry");
    });
  });

  // Every stored login is checked, so a Galaxy that never answers must cost that one host a timeout
  // and a reported failure, not hang the command or hide the others.
  describe("one slow Galaxy", () => {
    it("is that host's failure, and the others are still reported", async () => {
      const h = twoLogins();
      h.deps.whoami = async (baseUrl) => {
        if (baseUrl !== OTHER) return new Promise(() => {}); // never answers, ignores the signal
        return { username: "bob", isAdmin: false };
      };
      expect(await statusCommand({ timeoutMs: 50 }, h.deps)).toBe(1);
      expect(h.cap.err).toMatch(/No answer from dev\.galaxy\.example\.org within/);
      expect(h.cap.err).toContain("Logged in as bob");
    });

    it("stops on Ctrl-C with 130", async () => {
      const h = harness({ stored: [fakeLogin()] });
      h.deps.whoami = () => new Promise(() => {});
      const ac = new AbortController();
      const p = statusCommand({ signal: ac.signal }, h.deps);
      ac.abort();
      expect(await p).toBe(130);
    });
  });

  // `--json` always exits 0 (its option says so): each login's own `status` field carries how its
  // check went, so a failed login is data in the output, not a failed command.
  describe("--json", () => {
    it("prints an array to stdout without tokens and exits 0 even when a login failed", async () => {
      const h = harness({ stored: [expiredLogin()] });
      expect(await statusCommand({ json: true }, h.deps)).toBe(0);
      expect(h.cap.err).toBe("");
      const out = JSON.parse(h.cap.out);
      expect(out).toHaveLength(1);
      expect(out[0]).toMatchObject({ base_url: HOST, username: "aioue", storage: "keyring", method: "device", status: "expired" });
      expect(h.cap.out).not.toContain(FAKE_TOKEN);
      expect(out[0]).not.toHaveProperty("token");
    });

    it("includes the token only with --show-token", async () => {
      const h = harness({ stored: [fakeLogin()] });
      await statusCommand({ json: true, showToken: true }, h.deps);
      expect(JSON.parse(h.cap.out)[0].token).toBe(FAKE_TOKEN);
    });

    it("carries is_admin from the live check, and null when there was none", async () => {
      const admin = harness({ stored: [fakeLogin()] });
      admin.knobs.whoami = { username: "root", isAdmin: true };
      await statusCommand({ json: true }, admin.deps);
      expect(JSON.parse(admin.cap.out)[0].is_admin).toBe(true);

      const unchecked = harness({ stored: [expiredLogin()] });
      await statusCommand({ json: true }, unchecked.deps);
      expect(JSON.parse(unchecked.cap.out)[0].is_admin).toBeNull();
    });

    it("prints [] when nothing is stored, or nothing is stored for --host", async () => {
      const h = harness();
      expect(await statusCommand({ json: true }, h.deps)).toBe(0);
      expect(JSON.parse(h.cap.out)).toEqual([]);
      const named = harness({ stored: [fakeLogin()] });
      expect(await statusCommand({ json: true, host: OTHER }, named.deps)).toBe(0);
      expect(JSON.parse(named.cap.out)).toEqual([]);
    });
  });

  // The record lists the login but its token cannot be read (the keyring is down, or the secret is
  // gone). That host is reported as unavailable and the others are still checked: one unreadable
  // token must not hide the rest.
  describe("when a token cannot be read", () => {
    it.each(["throw", "null"] as const)("reports that host, still checks the others, and exits 1 (%s)", async (how) => {
      const h = twoLogins();
      makeTokenUnreadable(h, [HOST], how);
      expect(await statusCommand({}, h.deps)).toBe(1);
      expect(h.cap.err).toContain("dev.galaxy.example.org");
      expect(h.cap.err).toContain("token unavailable:");
      expect(h.cap.err).toContain("other.example.org");
      expect(h.cap.err).toContain("Logged in as"); // the other host was still checked
      expect(h.whoamiCalls.map((c) => c.baseUrl)).toEqual([OTHER]);
    });

    it("gives it a status value in --json, without a token, and exits 0 like any other --json run", async () => {
      const h = twoLogins();
      makeTokenUnreadable(h, [HOST]);
      expect(await statusCommand({ json: true, showToken: true }, h.deps)).toBe(0);
      const out = JSON.parse(h.cap.out) as { base_url: string; status: string; error?: string; token?: string }[];
      expect(out.map((o) => [o.base_url, o.status])).toEqual([[HOST, "unavailable"], [OTHER, "ok"]]);
      expect(out[0]!.error).toContain("token unavailable:");
      expect(out[0]!.token).toBeUndefined();
      expect(out[1]!.token).toBe(FAKE_TOKEN);
    });

    it("does the same with --host", async () => {
      const h = twoLogins();
      makeTokenUnreadable(h, [HOST]);
      expect(await statusCommand({ host: HOST }, h.deps)).toBe(1);
      expect(h.cap.err).toContain("token unavailable:");
    });
  });

  // An expiry that cannot be parsed is treated as expired, never as no expiry: a token must not
  // look permanent because its record is damaged.
  it("says an unreadable expiry is unreadable, rather than printing NaN, and makes no live check", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "tomorrow" })] });
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("unreadable expiry");
    expect(h.cap.err).not.toContain("NaN");
    expect(h.whoamiCalls).toEqual([]);
  });
});
