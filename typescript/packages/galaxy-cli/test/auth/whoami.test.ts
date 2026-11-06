import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createWhoami, probeGalaxy } from "../../src/auth/whoami";
import { discover } from "../../src/auth/oauth";
import { withUserAgent, USER_AGENT } from "../../src/auth/user-agent";
import { startFakeGalaxy, type FakeGalaxy } from "../support/fake-galaxy";
import { AuthError, type BaseUrl } from "../../src/auth/types";
import { version } from "../../package.json";

let galaxy: FakeGalaxy;
beforeEach(async () => {
  galaxy = await startFakeGalaxy();
});
afterEach(() => galaxy.close());

async function token(opts: { admin?: boolean } = {}): Promise<string> {
  const { startDevice } = await import("./whoami.helpers");
  return startDevice(galaxy, opts);
}

const base = () => galaxy.baseUrl as BaseUrl;
const rejects = async (p: Promise<unknown>, kind: string) => {
  const e = await p.then(() => null, (x) => x);
  expect(e).toBeInstanceOf(AuthError);
  expect((e as AuthError).kind).toBe(kind);
  return e as AuthError;
};

describe("whoami (rule 1)", () => {
  it("returns the user and is_admin for a good token", async () => {
    const who = await createWhoami()(base(), await token({ admin: true }));
    expect(who).toEqual({ username: "fake-user", email: "fake-user@example.org", isAdmin: true });
    expect((await createWhoami()(base(), await token())).isAdmin).toBe(false);
  });

  it("refuses the anonymous record Galaxy returns with 200 for an unknown key", async () => {
    const e = await rejects(createWhoami()(base(), "not-a-real-token"), "not_logged_in");
    expect(e.message).toMatch(/invalid.*newer API key.*expired.*deactivated/);
  });

  it("refuses a 403", async () => {
    galaxy.setInvalidKeyResponse("forbidden");
    await rejects(createWhoami()(base(), "not-a-real-token"), "not_logged_in");
  });

  it("uses only /api/users/current", async () => {
    await createWhoami()(base(), await token());
    const paths = galaxy.requests.filter((r) => r.url.startsWith("/api/")).map((r) => r.url);
    expect(paths.every((p) => p === "/api/version" || p === "/api/users/current")).toBe(true);
  });

  it("probes once per Galaxy, anonymously, before sending the token", async () => {
    const t = await token();
    const who = createWhoami();
    await who(base(), t);
    await who(base(), t);
    const probes = galaxy.requestsTo("/api/version");
    expect(probes).toHaveLength(1);
    expect(probes[0]!.headers["x-api-key"]).toBeUndefined();
  });
});

describe("version probe (rule 2)", () => {
  it("does not send the token when the answer is a redirect, and offers the Location", async () => {
    galaxy.setVersionMode("redirect");
    const e = await rejects(createWhoami()(base(), "fake-token-xyz"), "protocol");
    expect(e.message).toContain("https://elsewhere.example");
    expect(galaxy.requestsTo("/api/users/current")).toHaveLength(0);
  });

  it("does not send the token when the answer is not JSON", async () => {
    galaxy.setVersionMode("html");
    const e = await rejects(createWhoami()(base(), "fake-token-xyz"), "protocol");
    expect(e.message).toMatch(/does not look like a Galaxy API/);
    expect(galaxy.requestsTo("/api/users/current")).toHaveLength(0);
  });

  it("reports an unreachable host as a network error", async () => {
    const dead = await startFakeGalaxy();
    const url = dead.baseUrl as BaseUrl;
    await dead.close();
    await rejects(probeGalaxy(url), "network");
  });
});

describe("User-Agent (rule 17)", () => {
  const ua = `gxy/${version} (galaxy-cli)`;

  it("is gxy/<package version> (galaxy-cli)", () => {
    expect(USER_AGENT).toBe(ua);
  });

  it("is sent by whoami, the probe and the OAuth calls", async () => {
    const t = await token();
    galaxy.requests.length = 0;
    await createWhoami()(base(), t);
    const server = await discover(base(), { fetch: withUserAgent() });
    const pending = await server.startDeviceLogin();
    galaxy.approve(pending.userCode);
    await pending.waitForApproval();
    await server.revoke(t);
    expect(galaxy.requests.length).toBeGreaterThanOrEqual(6);
    for (const r of galaxy.requests) expect(r.headers["user-agent"], r.url).toBe(ua);
  });
});

describe("a Galaxy that redirects", () => {
  let other: Server;
  let hits: string[];
  beforeEach(async () => {
    hits = [];
    other = createServer((req, res) => {
      hits.push(`${req.url} ${req.headers["x-api-key"] ?? ""}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", r));
  });
  afterEach(() => new Promise((r) => other.close(r)));

  it("never gets the key from whoami", async () => {
    const target = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.endsWith("/api/version")) return Response.json({ version_major: "24.2" });
      return new Response(null, { status: 302, headers: { location: `${target}/api/users/current` } });
    }) as typeof fetch;
    await rejects(createWhoami(fetchImpl)(base(), "fake-token-xyz"), "not_logged_in");
    expect(hits).toEqual([]);
  });
});
