/** What the OAuth client refuses or hides: redirects with credentials, plain http, hostile server text. */
import { describe, expect, it, vi } from "vitest";
import { discover } from "../../src/auth/oauth";
import type { AuthServer, BaseUrl } from "../../src/auth/types";
import { useFakeGalaxies, type FakeGalaxy } from "../support/fake-galaxy";
import { authErrorOf } from "./harness";

const start = useFakeGalaxies();

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
