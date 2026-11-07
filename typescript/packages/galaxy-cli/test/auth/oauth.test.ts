import { beforeEach, describe, expect, it, vi } from "vitest";
import { discover } from "../../src/auth/oauth";
import { CLIENT_ID, type AuthServer, type BaseUrl } from "../../src/auth/types";
import { startFakeGalaxy, useFakeGalaxies, type FakeGalaxy } from "../support/fake-galaxy";
import { authErrorOf } from "./harness";

const start = useFakeGalaxies();
let galaxy: FakeGalaxy;
const url = () => galaxy.baseUrl as BaseUrl;

describe("discover", () => {
  beforeEach(async () => {
    galaxy = await start();
  });

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
    expect((await authErrorOf(server.startDeviceLogin())).kind).toBe("unsupported");
    expect(galaxy.requestsTo("/oauth/device_authorization")).toHaveLength(0);
  });

  it("reports no revocation when the metadata has no revocation endpoint", async () => {
    galaxy.setRevocationEndpoint(false);
    const server = await discover(url());
    expect(server.supportsRevocation).toBe(false);
    expect((await authErrorOf(server.revoke("fake-access-token-1"))).kind).toBe("unsupported");
  });

  it.each([
    ["404 (what Galaxy 26.1 sends)", "not-found", "unsupported"],
    ["a page that is not JSON", "not-json", "unsupported"],
    ["malformed JSON", "malformed", "protocol"],
    ["another issuer", "wrong-issuer", "insecure"],
  ] as const)("classifies metadata that is %s as %s", async (_what, mode, kind) => {
    galaxy.setMetadataMode(mode);
    expect((await authErrorOf(discover(url()))).kind).toBe(kind);
  });

  it("is a network error, naming the proxy and CA settings, when nothing is listening", async () => {
    const dead = await startFakeGalaxy();
    const deadUrl = dead.baseUrl as BaseUrl;
    await dead.close();
    const e = await authErrorOf(discover(deadUrl));
    expect(e.kind).toBe("network");
    expect(e.message).toContain("NODE_USE_ENV_PROXY=1");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
  });
});

describe("a Galaxy under a path prefix", () => {
  it("finds the metadata by RFC 8414 path insertion", async () => {
    galaxy = await start({ pathPrefix: "/galaxy" });
    const server = await discover(url());
    expect(server.issuer).toBe(galaxy.baseUrl);
    expect(galaxy.requests[0]?.url).toBe("/.well-known/oauth-authorization-server/galaxy");

    const pending = await server.startDeviceLogin();
    expect(pending.verificationUri.startsWith(`${galaxy.baseUrl}/`)).toBe(true);
    expect(galaxy.requestsTo("/galaxy/oauth/device_authorization")).toHaveLength(1);
  });
});

describe("endpoints must be on the issuer's origin", () => {
  beforeEach(async () => {
    galaxy = await start();
  });

  it.each(["device_authorization_endpoint", "token_endpoint", "revocation_endpoint"])("refuses a %s on another origin", async (field) => {
    galaxy.setMetadataOverrides({ [field]: "http://127.0.0.1:1/elsewhere" });
    const e = await authErrorOf(discover(url()));
    expect(e.kind).toBe("insecure");
    expect(e.message).toContain(field);
  });

  it("refuses an endpoint that is not a URL", async () => {
    galaxy.setMetadataOverrides({ token_endpoint: "not a url" });
    expect((await authErrorOf(discover(url()))).kind).toBe("insecure");
  });

  it("accepts endpoints on the same origin under another path", async () => {
    galaxy.setMetadataOverrides({ revocation_endpoint: `${galaxy.baseUrl}/somewhere/else` });
    await expect(discover(url())).resolves.toMatchObject({ supportsRevocation: true });
  });
});

describe("device login", () => {
  beforeEach(async () => {
    galaxy = await start();
  });

  it("runs the happy path: code out, approval in, token with granted scopes", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin(["read", "write"]);
    expect(pending.userCode).toBe(galaxy.pendingCodes()[0]);
    expect(pending.verificationUri).toBe(`${galaxy.baseUrl}/oauth/device`);
    expect(pending.expiresAt.getTime()).toBeGreaterThan(Date.now());

    galaxy.approve(pending.userCode, { scopes: ["read"], expiresIn: 1800 });
    const grant = await pending.waitForApproval();
    expect(grant).toEqual({ accessToken: galaxy.issuedTokens()[0], expiresIn: 1800, scopes: ["read"] });
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

  it("falls back to the requested scopes when the response has no scope, and has no expiry without expires_in", async () => {
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

  it("rejects with denied when the user denies", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.deny(pending.userCode);
    expect((await authErrorOf(pending.waitForApproval())).kind).toBe("denied");
  });

  it("rejects with expired when the server says the code expired", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.expire(pending.userCode);
    expect((await authErrorOf(pending.waitForApproval())).kind).toBe("expired");
  });

  it.each([
    ["malformed JSON", "{nope"],
    ["no user code", JSON.stringify({ device_code: "x", verification_uri: "y", expires_in: 5 })],
  ])("rejects with protocol when the device authorization response has %s", async (_what, body) => {
    galaxy.setDeviceAuthorizationOverride({ status: 200, body });
    const server = await discover(url());
    expect((await authErrorOf(server.startDeviceLogin())).kind).toBe("protocol");
  });
});

describe("the token Galaxy issues", () => {
  beforeEach(async () => {
    galaxy = await start();
  });

  async function grantWith(accessToken: string) {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode, { accessToken });
    return pending.waitForApproval();
  }

  it("is used when it is printable ASCII without whitespace", async () => {
    await expect(grantWith("fake-ok_token.1")).resolves.toMatchObject({ accessToken: "fake-ok_token.1" });
  });

  it.each([["whitespace", "abc def"], ["a curly quote", "abc‘def"], ["a control character", "tok\u0000en"], ["non-ASCII letters", "tökén"], ["nothing at all", ""]])(
    "is refused as a protocol error, without being echoed, when it has %s",
    async (_what, bad) => {
      const e = await authErrorOf(grantWith(bad));
      expect(e.kind).toBe("protocol");
      if (bad) expect(e.message).not.toContain(bad);
    },
  );
});

describe("revocation", () => {
  beforeEach(async () => {
    galaxy = await start();
  });

  it("sends the token as a form post to the revocation endpoint, with no Authorization header", async () => {
    const server = await discover(url());
    const token = galaxy.issueToken();
    await server.revoke(token);
    const req = galaxy.requestsTo("/oauth/revoke")[0]!;
    expect(req.form).toEqual({ token, token_type_hint: "access_token", client_id: CLIENT_ID });
    expect(req.headers.authorization).toBeUndefined();
  });

  it("treats a token Galaxy does not know as revoked (RFC 7009 answers 200)", async () => {
    const server = await discover(url());
    await expect(server.revoke("fake-unknown-token")).resolves.toBeUndefined();
  });
});

// What the OAuth client refuses or hides: redirects with credentials, plain http, hostile server text.


describe("no request reaches another origin through a redirect", () => {
  // `redirect()` makes the Galaxy answer the named path with a redirect to another origin,
  // which stands for anything a hostile or misconfigured Galaxy could point at.
  type Step = { galaxy: FakeGalaxy; server: AuthServer; redirect: () => void };
  const rows: [what: string, path: string, act: (s: Step) => Promise<unknown>][] = [
    ["the metadata", "/.well-known/oauth-authorization-server", ({ galaxy, redirect }) => (redirect(), discover(galaxy.baseUrl as BaseUrl))],
    ["the device authorization endpoint", "/oauth/device_authorization", ({ server, redirect }) => (redirect(), server.startDeviceLogin())],
    [
      "the token endpoint",
      "/oauth/token",
      async ({ server, redirect }) => {
        const pending = await server.startDeviceLogin();
        redirect();
        return pending.waitForApproval();
      },
    ],
    ["the revocation endpoint", "/oauth/revoke", ({ server, redirect }) => (redirect(), server.revoke("fake-access-token-1"))],
  ];

  it.each(rows)("a redirect from %s is refused", async (_what, path, act) => {
    const galaxy = await start();
    const other = await start();
    const server = await discover(galaxy.baseUrl as BaseUrl);
    await authErrorOf(act({ galaxy, server, redirect: () => galaxy.setRedirect(path, `${other.baseUrl}${path}`) }));
    // No device code, token or key was sent to the other origin.
    expect(other.requests).toEqual([]);
  });
});

describe("plain http", () => {
  it("is refused to a non-loopback host without making a request", async () => {
    const fetchSpy = vi.fn<typeof fetch>();
    const e = await authErrorOf(discover("http://galaxy.example.org" as BaseUrl, { fetch: fetchSpy }));
    expect(e.kind).toBe("insecure");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("network and TLS errors name the fixes", () => {
  it("a certificate failure names NODE_EXTRA_CA_CERTS and never suggests turning verification off", async () => {
    const cause = Object.assign(new Error("self-signed certificate in certificate chain"), { code: "SELF_SIGNED_CERT_IN_CHAIN" });
    const failing = (async () => {
      throw new TypeError("fetch failed", { cause });
    }) as unknown as typeof fetch;
    const e = await authErrorOf(discover("https://galaxy.example.org" as BaseUrl, { fetch: failing }));
    expect(e.kind).toBe("network");
    expect(e.message).toContain("self-signed certificate");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
    expect(e.message).toContain("NODE_USE_ENV_PROXY=1");
    expect(e.message).not.toMatch(/NODE_TLS_REJECT_UNAUTHORIZED|insecure|--no-verify|disable/i);
  });
});

describe("server text in errors is sanitised", () => {
  it("strips terminal control characters from an OAuth error and its description", async () => {
    const galaxy = await start();
    galaxy.setDeviceAuthorizationOverride({
      status: 400,
      body: JSON.stringify({ error: "bad\u001b]0;pwned\u0007thing", error_description: "line\r\nbreak \u001b[2J" }),
    });
    const server = await discover(galaxy.baseUrl as BaseUrl);
    const e = await authErrorOf(server.startDeviceLogin());
    expect(e.message).toContain("bad]0;pwnedthing");
    // eslint-disable-next-line no-control-regex
    expect(e.message).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
  });
});
