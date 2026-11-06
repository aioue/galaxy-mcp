import { describe, expect, it } from "vitest";
import { logoutCommand } from "../../src/auth/commands/logout";
import { statusCommand } from "../../src/auth/commands/status";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, OTHER, fakeLogin, harness } from "./fakes";

/** A store whose `get` fails for the given hosts, as a keyring that is down or has lost the secret does. */
function breakGet(h: ReturnType<typeof harness>, hosts: string[], how: "throw" | "null" = "throw") {
  const get = h.store.get.bind(h.store);
  h.store.get = async (b) => {
    if (!hosts.includes(b)) return get(b);
    if (how === "null") return null;
    throw new AuthError("not_logged_in", "The token for it is in the system keyring, which is not available: no secret service");
  };
}

describe("auth logout when the token cannot be read", () => {
  it.each(["throw", "null"] as const)("skips revocation, removes the record and says what happened (%s)", async (how) => {
    const h = harness({ stored: [fakeLogin()] });
    breakGet(h, [HOST], how);
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(h.server.revoked).toEqual([]);
    expect(await h.store.list()).toEqual([]);
    expect(h.cap.err).toContain("✓ Removed the stored login for dev.galaxy.example.org");
    expect(h.cap.err).toContain("Could not revoke the token on the server (the stored token could not be read");
    expect(h.cap.err).toContain("stays valid until it expires (2026-11-06 18:42 UTC)");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("exits 1 and says the keyring entry may remain when the delete cannot confirm it", async () => {
    const h = harness({ stored: [fakeLogin()] });
    breakGet(h, [HOST]);
    h.store.delete = async (b) => {
      h.store.logins.delete(b);
      throw new AuthError("unsupported", "The login record was removed, but the system keyring could not confirm that the secret for x is gone, so it may remain there: down");
    };
    expect(await logoutCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("may remain there");
    expect(await h.store.list()).toEqual([]);
  });

  it("still says 'nothing to remove' when there is no record at all", async () => {
    const h = harness();
    expect(await logoutCommand({ host: HOST }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("nothing to remove");
  });

  it("a pasted key with an unreadable secret is removed with the not-revoked note", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
    breakGet(h, [HOST]);
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(h.cap.err).toContain("not revoked");
    expect(await h.store.list()).toEqual([]);
  });
});

describe("auth status with an unreadable token", () => {
  const two = () => harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, username: "bob" })] });

  it.each(["throw", "null"] as const)("reports that host, checks the others, and exits 1 (%s)", async (how) => {
    const h = two();
    breakGet(h, [HOST], how);
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("dev.galaxy.example.org");
    expect(h.cap.err).toContain("token unavailable:");
    expect(h.cap.err).toContain("Token    unavailable");
    expect(h.cap.err).toContain("other.example.org");
    expect(h.cap.err).toContain("✓ Logged in as aioue"); // the other host was still checked (fake whoami answers aioue)
    expect(h.whoamiCalls.map((c) => c.baseUrl)).toEqual([OTHER]);
  });

  it("shows it as a status value in --json and exits 0 like any other --json run", async () => {
    const h = two();
    breakGet(h, [HOST]);
    expect(await statusCommand({ json: true, showToken: true }, h.deps)).toBe(0);
    const out = JSON.parse(h.cap.out) as { base_url: string; status: string; error?: string; token?: string }[];
    expect(out.map((o) => [o.base_url, o.status])).toEqual([[HOST, "unavailable"], [OTHER, "ok"]]);
    expect(out[0]!.error).toContain("token unavailable:");
    expect(out[0]!.token).toBeUndefined();
    expect(out[1]!.token).toBe(FAKE_TOKEN);
  });

  it("does the same with --host", async () => {
    const h = two();
    breakGet(h, [HOST]);
    expect(await statusCommand({ host: HOST }, h.deps)).toBe(1);
    expect(h.cap.err).toContain("token unavailable:");
  });

  it("does not print a corrupt expiry as NaN", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "tomorrow" })] });
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("unreadable expiry");
    expect(h.cap.err).not.toContain("NaN");
    expect(h.whoamiCalls).toEqual([]);
  });
});
