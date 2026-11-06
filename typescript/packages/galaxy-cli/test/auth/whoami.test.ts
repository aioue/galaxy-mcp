import { beforeEach, describe, expect, it } from "vitest";
import { createWhoami, probeGalaxy } from "../../src/auth/whoami";
import { discover } from "../../src/auth/oauth";
import { withUserAgent } from "../../src/auth/user-agent";
import { startFakeGalaxy, useFakeGalaxies, type FakeGalaxy } from "../support/fake-galaxy";
import type { BaseUrl } from "../../src/auth/types";
import { version } from "../../package.json";
import { authErrorOf } from "./harness";

const start = useFakeGalaxies();
let galaxy: FakeGalaxy;
beforeEach(async () => {
  galaxy = await start();
});
const base = () => galaxy.baseUrl as BaseUrl;

const certificateError = () => new TypeError("fetch failed", { cause: Object.assign(new Error("self-signed certificate"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" }) });
/** A `fetch` that fails every request the way a certificate failure does. */
const tlsFailure = (async () => {
  throw certificateError();
}) as unknown as typeof fetch;
/** The same, except that it answers the version probe, so the failure comes at the user lookup. */
const tlsFailureAfterProbe = (async (input: RequestInfo | URL) => {
  if (String(input instanceof Request ? input.url : input).endsWith("/api/version")) return Response.json({ version_major: "26.1" });
  throw certificateError();
}) as typeof fetch;

describe("whoami", () => {
  it("returns the user and whether they are an admin", async () => {
    expect(await createWhoami()(base(), galaxy.issueToken({ admin: true }))).toEqual({ username: "fake-user", email: "fake-user@example.org", isAdmin: true });
    expect((await createWhoami()(base(), galaxy.issueToken())).isAdmin).toBe(false);
  });

  it("refuses the anonymous record Galaxy answers with 200 for a key it does not know", async () => {
    // Observed on Galaxy 26.1: 200 and no `username`.
    expect((await authErrorOf(createWhoami()(base(), "not-a-real-token"))).kind).toBe("not_logged_in");
  });

  it.each([
    ["a 403", 403, "not_logged_in"],
    ["a 401", 401, "not_logged_in"],
    ["a 503", 503, "network"],
  ] as const)("treats %s as %s", async (_what, status, kind) => {
    galaxy.setUsersCurrentStatus(status);
    expect((await authErrorOf(createWhoami()(base(), "fake-token-xyz"))).kind).toBe(kind);
  });

  it("calls a 404 a non-Galaxy address, not a bad token", async () => {
    galaxy.setUsersCurrentStatus(404);
    const e = await authErrorOf(createWhoami()(base(), "fake-token-xyz"));
    expect(e.kind).toBe("protocol");
    expect(e.message).toContain("does not look like a Galaxy API");
    expect(e.message).not.toMatch(/invalid|expired/);
  });

  it("calls a 429 rate limiting, to retry later, not a bad token", async () => {
    galaxy.setUsersCurrentStatus(429);
    const e = await authErrorOf(createWhoami()(base(), "fake-token-xyz"));
    expect(e.kind).toBe("network");
    expect(e.message).toMatch(/rate-limiting/);
  });

  it("stops when the signal is already aborted, sending no token", async () => {
    const controller = new AbortController();
    controller.abort(new Error("ctrl-c"));
    await expect(createWhoami()(base(), galaxy.issueToken(), controller.signal)).rejects.toThrow("ctrl-c");
    expect(galaxy.requestsTo("/api/users/current")).toHaveLength(0);
  });

  it("never gives the key to the origin a Galaxy redirects to", async () => {
    const elsewhere = await start();
    galaxy.setRedirect("/api/users/current", `${elsewhere.baseUrl}/api/users/current`);
    expect((await authErrorOf(createWhoami()(base(), "fake-token-xyz"))).kind).toBe("not_logged_in");
    expect(elsewhere.requests).toEqual([]);
  });
});

describe("version probe before the token is sent", () => {
  it("runs once per Galaxy, anonymously", async () => {
    const token = galaxy.issueToken();
    const who = createWhoami();
    await who(base(), token);
    await who(base(), token);
    const probes = galaxy.requestsTo("/api/version");
    expect(probes).toHaveLength(1);
    expect(probes[0]!.headers["x-api-key"]).toBeUndefined();
  });

  it("stops at a redirect, offering the address it points to, and sends no token", async () => {
    galaxy.setVersionMode("redirect");
    const e = await authErrorOf(createWhoami()(base(), "fake-token-xyz"));
    expect(e.kind).toBe("protocol");
    expect(e.message).toContain("https://elsewhere.example");
    expect(galaxy.requestsTo("/api/users/current")).toHaveLength(0);
  });

  it("stops at an answer that is not a Galaxy version, and sends no token", async () => {
    galaxy.setVersionMode("html");
    const e = await authErrorOf(createWhoami()(base(), "fake-token-xyz"));
    expect(e.kind).toBe("protocol");
    expect(e.message).toContain("does not look like a Galaxy API");
    expect(galaxy.requestsTo("/api/users/current")).toHaveLength(0);
  });
});

describe("network and TLS failures", () => {
  it("an unreachable host is a network error naming the proxy and CA settings", async () => {
    const dead = await startFakeGalaxy();
    const url = dead.baseUrl as BaseUrl;
    await dead.close();
    const e = await authErrorOf(probeGalaxy(url));
    expect(e.kind).toBe("network");
    expect(e.message).toContain("NODE_USE_ENV_PROXY");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
  });

  it("a certificate failure in the version probe names NODE_EXTRA_CA_CERTS", async () => {
    const e = await authErrorOf(probeGalaxy("https://galaxy.example.org" as BaseUrl, tlsFailure));
    expect(e.kind).toBe("network");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
    expect(e.message).toContain("NODE_USE_ENV_PROXY");
  });

  it("a certificate failure in the user lookup names NODE_EXTRA_CA_CERTS", async () => {
    const e = await authErrorOf(createWhoami(tlsFailureAfterProbe)("https://galaxy.example.org" as BaseUrl, "fake-token-xyz"));
    expect(e.kind).toBe("network");
    expect(e.message).toContain("self-signed certificate");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
    expect(e.message).toContain("NODE_USE_ENV_PROXY");
  });
});

describe("User-Agent", () => {
  it("is gxy/<package version> (galaxy-cli) on whoami, the probe and every OAuth call", async () => {
    const token = galaxy.issueToken();
    await createWhoami()(base(), token);
    const server = await discover(base(), { fetch: withUserAgent() });
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode);
    await pending.waitForApproval();
    await server.revoke(token);

    const paths = galaxy.requests.map((r) => new URL(r.url, "http://x").pathname);
    for (const expected of ["/api/version", "/api/users/current", "/oauth/device_authorization", "/oauth/token", "/oauth/revoke"]) {
      expect(paths).toContain(expected);
    }
    for (const r of galaxy.requests) expect(r.headers["user-agent"], r.url).toBe(`gxy/${version} (galaxy-cli)`);
  });
});
