import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loginCommand } from "../../src/auth/commands/login";
import { discover } from "../../src/auth/oauth";
import type { AuthDeps, BaseUrl } from "../../src/auth/types";
import { startFakeGalaxy, type FakeGalaxy, type MetadataMode } from "../support/fake-galaxy";
import { Capture, harness } from "./fakes";

const HOST_ARG = "https://dev.galaxy.example.org";

describe("login against a Galaxy with no device login", () => {
  let galaxy: FakeGalaxy;
  beforeEach(async () => {
    galaxy = await startFakeGalaxy();
  });
  afterEach(() => galaxy.close());

  async function login(mode: MetadataMode | "no-device") {
    if (mode === "no-device") galaxy.setDeviceFlow(false);
    else galaxy.setMetadataMode(mode);
    const cap = new Capture();
    const deps = {
      discover: (u: BaseUrl, signal?: AbortSignal) => discover(u, { signal }),
      resolveHost: async () => galaxy.baseUrl as BaseUrl,
      env: {},
      io: { stdin: new PassThrough(), stdout: cap.stdout, stderr: cap.stderr, interactive: false },
      commandName: "gxy",
    } as unknown as AuthDeps;
    const code = await loginCommand({ host: galaxy.baseUrl }, deps);
    return { code, err: cap.err };
  }
  const hint = () => `Paste an API key instead: gxy auth login --host ${galaxy.baseUrl} --with-token`;
  const hostName = () => new URL(galaxy.baseUrl).host;

  it.each(["not-found", "not-json"] as const)("%s metadata gives the friendly message and exit 76", async (mode) => {
    const { code, err } = await login(mode);
    expect(code).toBe(76);
    expect(err).toContain(`${hostName()} does not offer device login yet (it publishes no OAuth metadata). ${hint()}`);
    expect(err).not.toContain("unexpected HTTP response");
  });

  it("metadata without a device endpoint gets the same wording and hint", async () => {
    const { code, err } = await login("no-device");
    expect(code).toBe(76);
    expect(err).toContain(`${hostName()} does not offer device login yet (it may be switched off by its admins). ${hint()}`);
  });

  it("malformed JSON stays a protocol error, with no --with-token hint", async () => {
    const { code, err } = await login("malformed");
    expect(code).toBe(76);
    expect(err).not.toContain("does not offer device login");
  });

  it("an issuer mismatch stays an insecure error", async () => {
    const { code, err } = await login("wrong-issuer");
    expect(err).toContain("different issuer");
    expect(err).not.toContain("does not offer device login");
    expect(code).not.toBe(0);
  });
});

describe("login and a .env host it ignores", () => {
  it("says so before 'Logging in to' when .env names a different Galaxy", async () => {
    const h = harness({ hostFromEnv: HOST_ARG, ignoredLoginHost: { source: "dotenv", url: "https://other.example.org" } });
    expect(await loginCommand({}, h.deps)).toBe(0);
    const line = "Ignoring GALAXY_URL from .env (https://other.example.org): login only uses --host or GALAXY_URL from the environment.";
    expect(h.cap.err).toContain(line);
    expect(h.cap.err.indexOf(line)).toBeLessThan(h.cap.err.indexOf("Logging in to"));
  });

  it("stays quiet when .env names the chosen host (even written differently)", async () => {
    const h = harness({ hostFromEnv: HOST_ARG, ignoredLoginHost: { source: "dotenv", url: `${HOST_ARG}/` } });
    await loginCommand({}, h.deps);
    expect(h.cap.err).not.toContain("Ignoring");
  });

  it("stays quiet with --host (named on purpose)", async () => {
    const h = harness({ ignoredLoginHost: { source: "dotenv", url: "https://other.example.org" } });
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.cap.err).not.toContain("Ignoring");
  });
});

describe("the admin warning when storing is refused", () => {
  it.each([["pasted"], ["device"]])("%s: warns before the refusal", async (kind) => {
    const h = harness({ stdinText: "fake-pasted-key\n" });
    h.knobs.whoami = { username: "root", isAdmin: true };
    h.store.keyringAvailable = false;
    const code = await loginCommand({ host: HOST_ARG, withToken: kind === "pasted" }, h.deps);
    expect(code).not.toBe(0);
    const warn = h.cap.err.indexOf("! This token carries full admin rights on dev.galaxy.example.org");
    const refusal = h.cap.err.indexOf("No system keyring here");
    expect(warn).toBeGreaterThanOrEqual(0);
    expect(refusal).toBeGreaterThan(warn);
  });

  it("prints the admin warning once on success", async () => {
    const h = harness();
    h.knobs.whoami = { username: "root", isAdmin: true };
    await loginCommand({ host: HOST_ARG }, h.deps);
    expect(h.cap.err.match(/full admin rights/g)).toHaveLength(1);
  });
});
