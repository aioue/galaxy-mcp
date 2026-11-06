import { describe, it, expect } from "vitest";
import { statusCommand } from "../../src/auth/commands/status";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, OTHER, fakeLogin, harness } from "./fakes";

describe("auth status", () => {
  it("shows a live check, storage, method, scopes, time left and a masked token, on stderr", async () => {
    const h = harness({ stored: [fakeLogin()] });
    expect(await statusCommand({}, h.deps)).toBe(0);
    expect(h.cap.out).toBe("");
    expect(h.cap.err).toContain("dev.galaxy.example.org");
    expect(h.cap.err).toContain("✓ Logged in as aioue");
    expect(h.cap.err).toContain("Storage  system keyring");
    expect(h.cap.err).toContain("Method   device login");
    expect(h.cap.err).toContain("Scopes   histories:read tools:run");
    expect(h.cap.err).toContain("Expires  in 7h 58m (2026-11-06 18:42 UTC)");
    expect(h.cap.err).toContain("********cdef");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
    expect(h.whoamiCalls).toHaveLength(1);
  });

  it("puts the unmasked token on stdout, never stderr, with --show-token", async () => {
    const h = harness({ stored: [fakeLogin()] });
    await statusCommand({ showToken: true }, h.deps);
    expect(h.cap.out).toBe(`${HOST}\t${FAKE_TOKEN}\n`);
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("says 'no expiry' for a pasted key", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
    await statusCommand({}, h.deps);
    expect(h.cap.err).toContain("Expires  no expiry");
    expect(h.cap.err).toContain("Method   pasted API key");
  });

  it("lists every stored login, or just the one with --host", async () => {
    const h = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, username: "bob" })] });
    await statusCommand({}, h.deps);
    expect(h.cap.err).toContain("dev.galaxy.example.org");
    expect(h.cap.err).toContain("other.example.org");
    const g = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, username: "bob" })] });
    await statusCommand({ host: "https://other.example.org" }, g.deps);
    expect(g.cap.err).not.toContain("dev.galaxy.example.org");
    expect(g.cap.err).toContain("other.example.org");
  });

  it("exits 1 and skips the live check for an expired login", async () => {
    const h = harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })] });
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("expired at 2026-11-06 09:00 UTC");
    expect(h.whoamiCalls).toEqual([]);
  });

  it("exits 1 when Galaxy rejects the token", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the token.");
    expect(await statusCommand({}, h.deps)).toBe(1);
    expect(h.cap.err).toContain("Galaxy rejected the token.");
  });

  it("exits 1 on a network failure", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.knobs.whoami = new AuthError("network", "Could not reach dev.galaxy.example.org.");
    expect(await statusCommand({}, h.deps)).toBe(1);
  });

  it("notes that GALAXY_API_KEY overrides stored logins", async () => {
    const h = harness({ stored: [fakeLogin()], env: { GALAXY_API_KEY: "x" } });
    await statusCommand({}, h.deps);
    expect(h.cap.err).toContain("GALAXY_API_KEY is set and takes precedence over stored logins");
  });

  it("with nothing stored, says so and exits 77", async () => {
    const h = harness();
    expect(await statusCommand({}, h.deps)).toBe(77);
    expect(h.cap.err).toContain("No stored logins");
  });

  describe("--json", () => {
    it("prints an array to stdout without tokens and exits 0 even when a login failed", async () => {
      const h = harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })] });
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

    it("prints [] when nothing is stored", async () => {
      const h = harness();
      expect(await statusCommand({ json: true }, h.deps)).toBe(0);
      expect(JSON.parse(h.cap.out)).toEqual([]);
    });
  });
});
