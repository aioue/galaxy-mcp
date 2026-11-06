/**
 * How the device login waits: the interval and `slow_down` (RFC 8628 §3.5), transient
 * failures, Retry-After, the local deadline and cancelling.
 *
 * Timing tests fake only `setTimeout` and `clearTimeout`, so the sockets still run for real.
 * They do not guess how long the sockets need: the client's `fetch` is wrapped to know when
 * a request has been answered in full, and after each step of the fake clock `tick` waits for
 * exactly that. What remains after it is in-process work with no I/O left to wait for.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { discover } from "../../src/auth/oauth";
import type { BaseUrl, PendingDeviceLogin } from "../../src/auth/types";
import { useFakeGalaxies, type FakeGalaxy } from "../support/fake-galaxy";
import { authErrorOf } from "./harness";

const start = useFakeGalaxies();
let galaxy: FakeGalaxy;
const url = () => galaxy.baseUrl as BaseUrl;
const tokenRequests = () => galaxy.requestsTo("/oauth/token").length;

afterEach(() => {
  vi.useRealTimers();
});

/** Real event-loop turns until `condition` holds, or fail after a generous bound. */
async function until(condition: () => boolean, what: string): Promise<void> {
  const deadline = performance.now() + 10_000;
  while (!condition()) {
    if (performance.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setImmediate(resolve));
  }
}
const turn = () => new Promise((resolve) => setImmediate(resolve));

/** A `fetch` that knows how many requests are still waiting for their answer (body included). */
function tracked() {
  let inflight = 0;
  const impl: typeof fetch = async (input, init) => {
    inflight += 1;
    try {
      const res = await fetch(input, init);
      await res.clone().arrayBuffer();
      return res;
    } finally {
      inflight -= 1;
    }
  };
  return { fetch: impl, idle: () => inflight === 0 };
}

/** Discovery through a tracked `fetch`. */
async function connect() {
  const net = tracked();
  return { server: await discover(url(), { fetch: net.fetch }), net };
}

/** Slack on top of an interval, so a step lands just after the timer it means to fire. */
const JUST_AFTER = 100;

/** Start waiting under fake timers. `tick(ms)` moves the clock, then waits for any poll it fired to be answered. */
function startWaiting(pending: PendingDeviceLogin, net: { idle(): boolean }, signal?: AbortSignal) {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const done = pending.waitForApproval(signal);
  return {
    done,
    async tick(ms: number) {
      await vi.advanceTimersByTimeAsync(ms);
      await until(net.idle, "the poll to be answered");
      await turn();
      await turn();
    },
  };
}

describe("polling", () => {
  beforeEach(async () => {
    galaxy = await start({ interval: 0.01 });
  });

  it("keeps polling while pending, then succeeds once approved", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    const done = pending.waitForApproval();
    await vi.waitFor(() => expect(tokenRequests()).toBeGreaterThanOrEqual(3));
    galaxy.approve(pending.userCode, { scopes: ["read"] });
    await expect(done).resolves.toMatchObject({ scopes: ["read"] });
  });

  it("waits the server's interval before the first poll and between polls", async () => {
    galaxy = await start({ interval: 2 });
    const { server, net } = await connect();
    const w = startWaiting(await server.startDeviceLogin(), net);
    w.done.catch(() => undefined);
    const pending = galaxy.pendingCodes()[0]!;

    await w.tick(2000 - JUST_AFTER);
    expect(tokenRequests()).toBe(0);
    await w.tick(2 * JUST_AFTER);
    expect(tokenRequests()).toBe(1);
    await w.tick(2000 - 2 * JUST_AFTER);
    expect(tokenRequests()).toBe(1);
    await w.tick(2 * JUST_AFTER);
    expect(tokenRequests()).toBe(2);

    galaxy.approve(pending);
    await vi.advanceTimersByTimeAsync(2000 + JUST_AFTER);
    await expect(w.done).resolves.toMatchObject({ scopes: [] });
  });

  it("adds 5 seconds to the interval after slow_down", async () => {
    galaxy = await start({ interval: 1 });
    const { server, net } = await connect();
    galaxy.slowDown(1);
    const w = startWaiting(await server.startDeviceLogin(), net);
    w.done.catch(() => undefined);

    await w.tick(1000 + JUST_AFTER); // first poll: slow_down
    expect(tokenRequests()).toBe(1);
    await w.tick(6000 - 2 * JUST_AFTER); // the interval is now 6 s: not yet
    expect(tokenRequests()).toBe(1);
    await w.tick(3 * JUST_AFTER);
    expect(tokenRequests()).toBe(2);

    galaxy.approve(galaxy.pendingCodes()[0]!);
    await vi.advanceTimersByTimeAsync(6000 + JUST_AFTER);
    await expect(w.done).resolves.toBeDefined();
  });
});

describe("the local deadline", () => {
  it("rejects with expired when the code's lifetime passes, even if the server never says so", async () => {
    // The server stays pending: its clock is the real one, which this test never moves.
    galaxy = await start({ interval: 100, deviceExpiresIn: 250 });
    const { server, net } = await connect();
    const w = startWaiting(await server.startDeviceLogin(), net);

    await w.tick(100_000 + JUST_AFTER);
    expect(tokenRequests()).toBeGreaterThanOrEqual(1);
    await vi.advanceTimersByTimeAsync(200_000);
    expect((await authErrorOf(w.done)).kind).toBe("expired");
  });

  it("still ends at the deadline when the server keeps failing, so only the local timer can end it", async () => {
    galaxy = await start({ interval: 100, deviceExpiresIn: 250 });
    const { server, net } = await connect();
    galaxy.failTokenPolls(1000, { status: 502 });
    const w = startWaiting(await server.startDeviceLogin(), net);

    await w.tick(100_000 + JUST_AFTER);
    expect(tokenRequests()).toBe(1);
    await vi.advanceTimersByTimeAsync(300_000);
    expect((await authErrorOf(w.done)).kind).toBe("expired");
  });
});

describe("transient failures", () => {
  beforeEach(async () => {
    galaxy = await start({ interval: 0.01 });
  });

  it("keeps polling through connection resets, then succeeds", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(2, { reset: true });
    galaxy.approve(pending.userCode, { scopes: ["read"] });
    await expect(pending.waitForApproval()).resolves.toMatchObject({ scopes: ["read"] });
    expect(tokenRequests()).toBeGreaterThan(2);
  });

  it.each([502, 503, 504])("keeps polling through an HTML %i", async (status) => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(2, { status });
    galaxy.approve(pending.userCode);
    const grant = await pending.waitForApproval();
    expect(galaxy.issuedTokens()).toContain(grant.accessToken);
  });

  it("keeps polling through a 500 with an OAuth error body", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(1, { status: 500, body: JSON.stringify({ error: "server_error" }) });
    galaxy.approve(pending.userCode);
    const grant = await pending.waitForApproval();
    expect(galaxy.issuedTokens()).toContain(grant.accessToken);
  });

  it("fails at once on an OAuth error that is not pending or slow_down", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.setTokenOverride({ status: 400, body: JSON.stringify({ error: "server_error" }) });
    expect((await authErrorOf(pending.waitForApproval())).kind).toBe("protocol");
    expect(tokenRequests()).toBe(1);
  });

  it("fails at once on a 4xx that is not 429", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    galaxy.failTokenPolls(5, { status: 403 });
    expect((await authErrorOf(pending.waitForApproval())).kind).toBe("protocol");
    expect(tokenRequests()).toBe(1);
  });

  it("fails at once on a certificate error, naming how to fix it", async () => {
    let attempts = 0;
    const tlsFetch: typeof fetch = (input, init) => {
      if (!String(input instanceof Request ? input.url : input).endsWith("/oauth/token")) return fetch(input, init);
      attempts += 1;
      return Promise.reject(Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("self-signed certificate"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" }) }));
    };
    const server = await discover(url(), { fetch: tlsFetch });
    const pending = await server.startDeviceLogin();
    const e = await authErrorOf(pending.waitForApproval());
    expect(e.kind).toBe("network");
    expect(e.message).toContain("NODE_EXTRA_CA_CERTS");
    expect(attempts).toBe(1);
  });

  it("waits out a 429's Retry-After before polling again", async () => {
    galaxy = await start({ interval: 1 });
    const { server, net } = await connect();
    galaxy.failTokenPolls(1, { status: 429, headers: { "retry-after": "20" } });
    const w = startWaiting(await server.startDeviceLogin(), net);
    w.done.catch(() => undefined);

    await w.tick(1000 + JUST_AFTER); // first poll: 429
    expect(tokenRequests()).toBe(1);
    await w.tick(19_000); // 20 s have not passed since the 429
    expect(tokenRequests()).toBe(1);
    await w.tick(2000 + JUST_AFTER);
    expect(tokenRequests()).toBe(2);

    galaxy.approve(galaxy.pendingCodes()[0]!);
    await vi.advanceTimersByTimeAsync(1000 + JUST_AFTER);
    await expect(w.done).resolves.toBeDefined();
  });
});

describe("cancelling", () => {
  beforeEach(async () => {
    galaxy = await start();
  });

  it("aborts at once when the signal is already aborted, without polling", async () => {
    const server = await discover(url());
    const pending = await server.startDeviceLogin();
    const controller = new AbortController();
    controller.abort();
    await expect(pending.waitForApproval(controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(tokenRequests()).toBe(0);
  });

  it("aborts polling with the signal's reason and polls no more", async () => {
    galaxy = await start({ interval: 1 });
    const { server, net } = await connect();
    const controller = new AbortController();
    const w = startWaiting(await server.startDeviceLogin(), net, controller.signal);
    w.done.catch(() => undefined);

    await w.tick(1000 + JUST_AFTER);
    expect(tokenRequests()).toBe(1);
    controller.abort(new Error("user pressed ctrl-c"));
    await expect(w.done).rejects.toThrow("user pressed ctrl-c");
    await vi.advanceTimersByTimeAsync(10_000);
    expect(tokenRequests()).toBe(1);
  });

  it("rejects with the reason when the signal aborts during discovery", async () => {
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
});
