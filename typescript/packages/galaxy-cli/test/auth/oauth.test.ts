import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { discover } from "../../src/auth/oauth";
import { AuthError, CLIENT_ID, type BaseUrl } from "../../src/auth/types";
import { startFakeGalaxy, type FakeGalaxy } from "../support/fake-galaxy";

let galaxy: FakeGalaxy;
const open: FakeGalaxy[] = [];
async function start(options?: Parameters<typeof startFakeGalaxy>[0]) {
  galaxy = await startFakeGalaxy(options);
  open.push(galaxy);
  return galaxy;
}
const url = () => galaxy.baseUrl as BaseUrl;

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(open.splice(0).map((g) => g.close()));
});

async function whoami(token: string) {
  const res = await fetch(`${galaxy.baseUrl}/api/users/current`, { headers: { "x-api-key": token } });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

async function expectAuthError(p: Promise<unknown>, kind: AuthError["kind"]) {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AuthError);
  expect((err as AuthError).kind).toBe(kind);
}

describe("discover", () => {
  beforeEach(() => start());

  it("reads the metadata and reports what the server offers", async () => {
    const server = await discover(url());
    expect(server.issuer).toBe(galaxy.baseUrl);
    expect(server.supportsDeviceFlow).toBe(true);
    expect(server.supportsRevocation).toBe(true);
    expect(galaxy.requests[0]?.url).toBe("/.well-known/oauth-authorization-server");
  });

  it("reports no device flow when the metadata has no device endpoint, and refuses to start one", async () => {
    galaxy.setDeviceFlow(false);
    const server = await discover(url());
    expect(server.supportsDeviceFlow).toBe(false);
    await expectAuthError(server.startDeviceLogin(), "unsupported");
    expect(galaxy.requestsTo("/oauth/device_authorization")).toHaveLength(0);
  });

  it("reports no revocation when the metadata has no revocation endpoint", async () => {
    galaxy.setRevocationEndpoint(false);
    const server = await discover(url());
    expect(server.supportsRevocation).toBe(false);
    await expectAuthError(server.revoke("fake-access-token-1"), "unsupported");
  });

  it("is unsupported when there is no metadata (404)", async () => {
    galaxy.setMetadataMode("not-found");
    await expectAuthError(discover(url()), "unsupported");
  });

  it("is unsupported when the metadata is not JSON", async () => {
    galaxy.setMetadataMode("not-json");
    await expectAuthError(discover(url()), "unsupported");
  });

  it("is a protocol error when the JSON is malformed", async () => {
    galaxy.setMetadataMode("malformed");
    await expectAuthError(discover(url()), "protocol");
  });

  it("is insecure when the metadata names another issuer", async () => {
    galaxy.setMetadataMode("wrong-issuer");
    await expectAuthError(discover(url()), "insecure");
  });

  it("is a network error when nothing is listening", async () => {
    const dead = await startFakeGalaxy();
    const deadUrl = dead.baseUrl as BaseUrl;
    await dead.close();
    await expectAuthError(discover(deadUrl), "network");
  });

  it("refuses plain http to a non-loopback host without making a request", async () => {
    const fetchSpy = vi.fn<typeof fetch>();
    await expectAuthError(discover("http://galaxy.example.org" as BaseUrl, { fetch: fetchSpy }), "insecure");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("path-prefixed Galaxy", () => {
  it("finds the metadata by RFC 8414 path insertion", async () => {
    await start({ pathPrefix: "/galaxy" });
    const server = await discover(url());
    expect(server.issuer).toBe(galaxy.baseUrl);
    expect(galaxy.requests[0]?.url).toBe("/.well-known/oauth-authorization-server/galaxy");

    const pending = await server.startDeviceLogin();
    expect(pending.verificationUri.startsWith(`${galaxy.baseUrl}/`)).toBe(true);
    expect(galaxy.requestsTo("/galaxy/oauth/device_authorization")).toHaveLength(1);
  });
});

describe("device login", () => {
  beforeEach(() => start());

  it("runs the happy path: code out, approval in, token with granted scopes", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin(["read", "write"]);
    expect(pending.userCode).toBe(galaxy.lastUserCode());
    expect(pending.verificationUri).toBe(`${galaxy.baseUrl}/oauth/device`);
    expect(pending.expiresAt.getTime()).toBeGreaterThan(Date.now());

    galaxy.approve(pending.userCode, { scopes: ["read"], expiresIn: 1800 });
    const grant = await pending.waitForApproval();
    expect(grant).toEqual({ accessToken: "fake-access-token-1", expiresIn: 1800, scopes: ["read"] });
    expect(await whoami(grant.accessToken)).toMatchObject({ status: 200, body: { username: "fake-user" } });
  });

  it("sends the public client id and scope, and no secret or Authorization header", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin(["read", "write"]);
    galaxy.approve(pending.userCode);
    await pending.waitForApproval();

    const device = galaxy.requestsTo("/oauth/device_authorization")[0]!;
    expect(device.form).toEqual({ client_id: CLIENT_ID, scope: "read write" });
    const token = galaxy.requestsTo("/oauth/token")[0]!;
    expect(token.form.client_id).toBe(CLIENT_ID);
    expect(token.form.grant_type).toBe("urn:ietf:params:oauth:grant-type:device_code");
    for (const r of galaxy.requests) {
      expect(r.headers.authorization).toBeUndefined();
      expect(r.form.client_secret).toBeUndefined();
      expect(r.form.client_assertion).toBeUndefined();
    }
  });

  it("sends scope only when scopes are given", async () => {
    const server = await discover(url());
    await server.startDeviceLogin();
    await server.startDeviceLogin([]);
    for (const r of galaxy.requestsTo("/oauth/device_authorization")) expect(r.form).toEqual({ client_id: CLIENT_ID });
  });

  it("uses the client id from the options", async () => {
    const server = await discover(url(), { clientId: "other-client" });
    await server.startDeviceLogin();
    expect(galaxy.requestsTo("/oauth/device_authorization")[0]!.form.client_id).toBe("other-client");
  });

  it("falls back to the requested scopes when the response has no scope", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin(["read"]);
    galaxy.approve(pending.userCode, { scopes: undefined, expiresIn: null });
    const grant = await pending.waitForApproval();
    expect(grant.scopes).toEqual(["read"]);
    expect(grant.expiresIn).toBeUndefined();
  });

  it("has no scopes when none were requested or returned", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode, { scopes: undefined });
    expect((await pending.waitForApproval()).scopes).toEqual([]);
  });

  it("keeps polling while pending, then succeeds once approved", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    const done = pending.waitForApproval();
    await vi.waitFor(() => expect(galaxy.requestsTo("/oauth/token").length).toBeGreaterThanOrEqual(3));
    galaxy.approve(pending.userCode, { scopes: ["read"] });
    await expect(done).resolves.toMatchObject({ scopes: ["read"] });
  });

  it("rejects with denied when the user denies", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.deny(pending.userCode);
    await expectAuthError(pending.waitForApproval(), "denied");
  });

  it("rejects with expired when the server says the code expired", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.expire(pending.userCode);
    await expectAuthError(pending.waitForApproval(), "expired");
  });

  it("rejects with protocol when the device authorization response is malformed", async () => {
    galaxy.setDeviceAuthorizationOverride({ status: 200, body: "{nope" });
    const server = await discover(url());
    await expectAuthError(server.startDeviceLogin(), "protocol");
  });

  it("rejects with protocol when the device authorization response lacks the user code", async () => {
    galaxy.setDeviceAuthorizationOverride({ status: 200, body: JSON.stringify({ device_code: "x", verification_uri: "y", expires_in: 5 }) });
    const server = await discover(url());
    await expectAuthError(server.startDeviceLogin(), "protocol");
  });

  it("rejects with protocol on an unexpected token error", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.setTokenOverride({ status: 400, body: JSON.stringify({ error: "server_error" }) });
    await expectAuthError(pending.waitForApproval(), "protocol");
  });

  it("aborts at once when the signal is already aborted", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    const controller = new AbortController();
    controller.abort();
    await expect(pending.waitForApproval(controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(0);
  });
});

/** Let real socket I/O finish: fake timers do not cover it. */
const flush = async () => {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
};
const advance = async (ms: number) => {
  await vi.advanceTimersByTimeAsync(ms);
  await flush();
};

describe("endpoints must be on the issuer's origin", () => {
  beforeEach(() => start());

  it.each(["device_authorization_endpoint", "token_endpoint", "revocation_endpoint"])("refuses a %s on another origin", async (field) => {
    galaxy.setMetadataOverrides({ [field]: "http://127.0.0.1:1/elsewhere" });
    const err = await discover(url()).then(() => undefined, (e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).kind).toBe("insecure");
    expect((err as AuthError).message).toContain(field);
  });

  it("refuses an endpoint that is not a URL", async () => {
    galaxy.setMetadataOverrides({ token_endpoint: "not a url" });
    await expectAuthError(discover(url()), "insecure");
  });

  it("accepts endpoints on the same origin under another path", async () => {
    galaxy.setMetadataOverrides({ revocation_endpoint: `${galaxy.baseUrl}/somewhere/else` });
    await expect(discover(url())).resolves.toMatchObject({ supportsRevocation: true });
  });
});

describe("cancelling", () => {
  beforeEach(() => start());

  it("passes the signal to discovery: an abort during it rejects with the reason", async () => {
    const controller = new AbortController();
    const slowFetch: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason), { once: true }));
    const p = discover(url(), { fetch: slowFetch, signal: controller.signal });
    controller.abort(new Error("ctrl-c"));
    await expect(p).rejects.toThrow("ctrl-c");
  });

  it("creates no device code when the signal was aborted before startDeviceLogin", async () => {
    const controller = new AbortController();
    const server = await discover(url(), { signal: controller.signal });
    controller.abort(new Error("ctrl-c"));
    await expect(server.startDeviceLogin()).rejects.toThrow("ctrl-c");
    expect(galaxy.requestsTo("/oauth/device_authorization")).toHaveLength(0);
  });

  it("aborts polling with the signal's reason and polls no more", async () => {
    await start({ interval: 1 });
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const controller = new AbortController();
    const done = pending.waitForApproval(controller.signal);
    done.catch(() => undefined);
    await advance(1100);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(1);
    controller.abort(new Error("user pressed ctrl-c"));
    await expect(done).rejects.toThrow("user pressed ctrl-c");
    await advance(10_000);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(1);
  });

  it("rejects with expired at the local deadline even if the server never says so", async () => {
    // The server stays pending (Date is not faked, so it never notices the time passing).
    await start({ interval: 100, deviceExpiresIn: 250 });
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const done = pending.waitForApproval();
    const outcome = done.then(() => undefined, (e: unknown) => e);
    await advance(100_500);
    await advance(100_000);
    expect(galaxy.requestsTo("/oauth/token").length).toBeGreaterThanOrEqual(2);
    await advance(60_000);
    const err = await outcome;
    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).kind).toBe("expired");
  });
});

describe("transient failures while polling", () => {
  beforeEach(() => start());
  const tokenRequests = () => galaxy.requestsTo("/oauth/token").length;

  it("keeps polling through connection resets, then succeeds", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(2, { reset: true });
    galaxy.approve(pending.userCode, { scopes: ["read"] });
    await expect(pending.waitForApproval()).resolves.toMatchObject({ accessToken: "fake-access-token-1" });
    expect(tokenRequests()).toBe(3);
  });

  it.each([502, 503, 504])("keeps polling through an HTML %i", async (status) => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(2, { status });
    galaxy.approve(pending.userCode);
    await expect(pending.waitForApproval()).resolves.toMatchObject({ accessToken: "fake-access-token-1" });
    expect(tokenRequests()).toBe(3);
  });

  it("keeps polling through a 500 with an OAuth error body", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(1, { status: 500, body: JSON.stringify({ error: "server_error" }) });
    galaxy.approve(pending.userCode);
    await expect(pending.waitForApproval()).resolves.toMatchObject({ accessToken: "fake-access-token-1" });
  });

  it("fails fast on any other OAuth error: one request, no retry", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.setTokenOverride({ status: 400, body: JSON.stringify({ error: "server_error" }) });
    await expectAuthError(pending.waitForApproval(), "protocol");
    expect(tokenRequests()).toBe(1);
  });

  it("fails fast on a 4xx that is not 429", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(5, { status: 403 });
    await expectAuthError(pending.waitForApproval(), "protocol");
    expect(tokenRequests()).toBe(1);
  });

  it("fails fast on a certificate error", async () => {
    let attempts = 0;
    const tlsFetch: typeof fetch = (input, init) => {
      if (!String(input instanceof Request ? input.url : input).endsWith("/oauth/token")) return fetch(input, init);
      attempts += 1;
      return Promise.reject(Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("self-signed certificate"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" }) }));
    };
    const server = await discover(url(), { fetch: tlsFetch });
    const pending = await server.startDeviceLogin();
    const err = await pending.waitForApproval().then(() => undefined, (e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).kind).toBe("network");
    expect((err as AuthError).message).toContain("secure connection");
    expect(attempts).toBe(1);
  });

  it("still ends at the code's deadline when the server keeps failing", async () => {
    await start({ interval: 100, deviceExpiresIn: 250 });
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(1000, { status: 502 });
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const outcome = pending.waitForApproval().then(() => undefined, (e: unknown) => e);
    for (let i = 0; i < 6; i++) await advance(100_000);
    const err = await outcome;
    expect((err as AuthError).kind).toBe("expired");
  });

  it("waits out a 429's Retry-After before polling again", async () => {
    await start({ interval: 1 });
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(1, { status: 429, headers: { "retry-after": "20" } });
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const done = pending.waitForApproval();
    done.catch(() => undefined);
    await advance(1100); // first poll: 429
    expect(tokenRequests()).toBe(1);
    await advance(19_000);
    expect(tokenRequests()).toBe(1);
    await advance(3_300);
    expect(tokenRequests()).toBe(2);
    galaxy.approve(pending.userCode);
    await advance(1_100);
    await expect(done).resolves.toMatchObject({ accessToken: "fake-access-token-1" });
  });
});

describe("polling interval", () => {
  it("waits the server's interval before the first poll and between polls", async () => {
    await start({ interval: 2 });
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const done = pending.waitForApproval();
    done.catch(() => undefined);

    await advance(1900);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(0);
    await advance(200);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(1);
    await advance(1900);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(1);
    await advance(200);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(2);

    galaxy.approve(pending.userCode);
    await advance(2100);
    await expect(done).resolves.toMatchObject({ accessToken: "fake-access-token-1" });
  });

  it("adds 5 seconds to the interval after slow_down", async () => {
    await start({ interval: 1 });
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.slowDown(1);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const done = pending.waitForApproval();
    done.catch(() => undefined);

    await advance(1100); // first poll: slow_down
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(1);
    await advance(5500); // interval is now 6 s: 5.5 s is not enough
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(1);
    await advance(600);
    expect(galaxy.requestsTo("/oauth/token")).toHaveLength(2);

    galaxy.approve(pending.userCode);
    await advance(6100);
    await expect(done).resolves.toMatchObject({ accessToken: "fake-access-token-1" });
  });
});

describe("revocation", () => {
  beforeEach(() => start());

  it("revokes the token, after which Galaxy treats the key as anonymous", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode);
    const { accessToken } = await pending.waitForApproval();
    expect((await whoami(accessToken)).body).toHaveProperty("username");

    await server.revoke(accessToken);

    const req = galaxy.requestsTo("/oauth/revoke")[0]!;
    expect(req.form).toEqual({ token: accessToken, token_type_hint: "access_token", client_id: CLIENT_ID });
    expect(req.headers.authorization).toBeUndefined();
    expect((await whoami(accessToken)).body).toEqual({ total_disk_usage: 0, nice_total_disk_usage: "0 bytes", quota_percent: null });
  });

  it("can have Galaxy answer 403 instead of the anonymous user for a revoked key", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode);
    const { accessToken } = await pending.waitForApproval();
    await server.revoke(accessToken);
    galaxy.setInvalidKeyResponse("forbidden");
    expect((await whoami(accessToken)).status).toBe(403);
  });

  it("treats a token Galaxy does not know as revoked (RFC 7009 answers 200)", async () => {
    const server = await discover(url());
    await expect(server.revoke("fake-unknown-token")).resolves.toBeUndefined();
  });

  it("rejects an expired token at /api/users/current", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode, { expiresIn: 0 });
    const { accessToken } = await pending.waitForApproval();
    expect((await whoami(accessToken)).body).not.toHaveProperty("username");
  });
});
