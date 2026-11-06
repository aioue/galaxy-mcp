import { afterEach, describe, expect, it } from "vitest";
import { createGalaxyContext, getUser } from "@galaxyproject/galaxy-ops";
import { discover } from "../../src/auth/oauth";
import { AuthError, type BaseUrl } from "../../src/auth/types";
import { startFakeGalaxy, type FakeGalaxy } from "../support/fake-galaxy";

const open: FakeGalaxy[] = [];
async function start(options?: Parameters<typeof startFakeGalaxy>[0]) {
  const g = await startFakeGalaxy(options);
  open.push(g);
  return g;
}
afterEach(async () => {
  await Promise.all(open.splice(0).map((g) => g.close()));
});

async function errorOf(p: Promise<unknown>): Promise<AuthError> {
  const e = await p.then(
    () => undefined,
    (x: unknown) => x,
  );
  expect(e).toBeInstanceOf(AuthError);
  return e as AuthError;
}

describe("no redirects with credentials", () => {
  // `elsewhere` stands for any other origin a hostile or misconfigured Galaxy points at.
  it.each([
    ["the metadata", "/.well-known/oauth-authorization-server"],
    ["the device authorization endpoint", "/oauth/device_authorization"],
    ["the token endpoint", "/oauth/token"],
    ["the revocation endpoint", "/oauth/revoke"],
  ])("openid-client does not follow a redirect from %s", async (_what, suffix) => {
    const galaxy = await start();
    const elsewhere = await start();
    const server = await discover(galaxy.baseUrl as BaseUrl);
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode);
    const grant = await pending.waitForApproval();

    galaxy.setRedirect(suffix, `${elsewhere.baseUrl}${suffix}`);
    if (suffix.includes("well-known")) {
      await errorOf(discover(galaxy.baseUrl as BaseUrl));
    } else if (suffix.includes("device_authorization")) {
      await errorOf(server.startDeviceLogin());
    } else if (suffix.includes("token")) {
      const p2 = await server.startDeviceLogin().catch(() => undefined);
      // The first device code came before the redirect was set; poll it with the redirect on.
      expect(p2).toBeDefined();
      await errorOf(p2!.waitForApproval());
    } else {
      await errorOf(server.revoke(grant.accessToken));
    }

    // Nothing reached the other origin: no device code, no token, no key.
    expect(elsewhere.requests).toEqual([]);
  });

  it("whoami (galaxy-ops) does not send the key to a redirect target", async () => {
    const galaxy = await start();
    const elsewhere = await start();
    galaxy.setRedirect("/api/users/current", `${elsewhere.baseUrl}/api/users/current`);
    const ctx = createGalaxyContext({ baseUrl: galaxy.baseUrl, apiKey: "fake-key-not-real" });
    await expect(getUser({}, ctx)).rejects.toThrow(/redirect/i);
    expect(galaxy.requestsTo("/api/users/current")).toHaveLength(1);
    expect(elsewhere.requests).toEqual([]);
  });
});

describe("network and TLS errors name the fixes", () => {
  it("a refused connection mentions the proxy variable and the CA variable", async () => {
    const dead = await startFakeGalaxy();
    const url = dead.baseUrl as BaseUrl;
    await dead.close();
    const e = await errorOf(discover(url));
    expect(e.kind).toBe("network");
    expect(e.message).toContain("NODE_USE_ENV_PROXY=1");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
  });

  it("a certificate failure names NODE_EXTRA_CA_CERTS and never suggests turning verification off", async () => {
    const cause = Object.assign(new Error("self-signed certificate in certificate chain"), { code: "SELF_SIGNED_CERT_IN_CHAIN" });
    const failing = (async () => {
      throw new TypeError("fetch failed", { cause });
    }) as unknown as typeof fetch;
    const e = await errorOf(discover("https://galaxy.example.org" as BaseUrl, { fetch: failing }));
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
    const e = await errorOf(server.startDeviceLogin());
    expect(e.message).toContain("bad]0;pwnedthing");
    // eslint-disable-next-line no-control-regex
    expect(e.message).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
  });
});

describe("polling deadline", () => {
  it("still expires locally when the caller passes a signal that never fires", async () => {
    const galaxy = await start({ deviceExpiresIn: 0.3 });
    galaxy.setTokenOverride({ status: 400, body: JSON.stringify({ error: "authorization_pending" }) });
    const server = await discover(galaxy.baseUrl as BaseUrl);
    const pending = await server.startDeviceLogin();
    const never = new AbortController();
    const started = Date.now();
    const e = await errorOf(pending.waitForApproval(never.signal));
    expect(e.kind).toBe("expired");
    expect(Date.now() - started).toBeLessThan(5000);
    expect(never.signal.aborted).toBe(false);
  });
});
