import { describe, it, expect } from "vitest";
import { logoutCommand } from "../../src/auth/commands/logout";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, fakeLogin, harness } from "./fakes";

describe("auth logout", () => {
  it("revokes the device token, then deletes the login", async () => {
    const h = harness({ stored: [fakeLogin()] });
    const order: string[] = [];
    const revoke = h.server.revoke.bind(h.server);
    h.server.revoke = async (t) => {
      order.push("revoke");
      await revoke(t);
    };
    const del = h.store.delete.bind(h.store);
    h.store.delete = async (b) => {
      order.push("delete");
      return del(b);
    };
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(order).toEqual(["revoke", "delete"]);
    expect(h.server.revoked).toEqual([FAKE_TOKEN]);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("✓ Revoked the token on dev.galaxy.example.org");
    expect(h.cap.out).toBe("");
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
  });

  it("still deletes locally when revocation fails, and says the token stays valid until expiry", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.server.revokeError = new AuthError("network", "connection refused");
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("Could not revoke the token on the server (connection refused)");
    expect(h.cap.err).toContain("stays valid until it expires (2026-11-06 18:42 UTC)");
  });

  it("treats a failed discovery as a failed revocation", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.knobs.discoverError = new AuthError("network", "no route");
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("no route");
  });

  it("says so when the server has no revocation endpoint", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.server.supportsRevocation = false;
    await logoutCommand({}, h.deps);
    expect(h.cap.err).toContain("does not offer token revocation");
    expect(await h.store.get(HOST)).toBeNull();
  });

  it("deletes a pasted key without contacting the server and says it was not revoked", async () => {
    const h = harness({ stored: [fakeLogin({ method: "pasted", scopes: [], expiresAt: null })] });
    h.knobs.discoverError = new AuthError("network", "should not be called");
    expect(await logoutCommand({}, h.deps)).toBe(0);
    expect(h.server.revoked).toEqual([]);
    expect(await h.store.get(HOST)).toBeNull();
    expect(h.cap.err).toContain("not revoked");
    expect(h.cap.err).toContain("user preferences");
    expect(h.cap.err).not.toContain("should not be called");
  });

  it("is a no-op with a note when nothing is stored for the host", async () => {
    const h = harness();
    expect(await logoutCommand({ host: "https://dev.galaxy.example.org" }, h.deps)).toBe(0);
    expect(h.cap.err).toContain("nothing to remove");
  });
});
