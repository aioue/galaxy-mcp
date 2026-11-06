/**
 * Where a token may appear. It goes to stdout only from the commands whose job is to hand it
 * out, and nowhere else: not stderr, not an error, not a failed or half-finished run.
 */
import { describe, expect, it } from "vitest";
import { envCommand } from "../../src/auth/commands/env";
import { headersCommand } from "../../src/auth/commands/headers";
import { loginCommand } from "../../src/auth/commands/login";
import { logoutCommand } from "../../src/auth/commands/logout";
import { statusCommand } from "../../src/auth/commands/status";
import { tokenCommand } from "../../src/auth/commands/token";
import { AuthError } from "../../src/auth/types";
import { FAKE_TOKEN, HOST, fakeLogin, harness } from "./harness";

const HOST_ARG = "https://dev.galaxy.example.org";
type H = ReturnType<typeof harness>;
type Run = (h: H) => Promise<number>;

describe("a stored, valid login", () => {
  const cases: [name: string, handsOutToken: boolean, run: Run][] = [
    ["token", true, (h) => tokenCommand({}, h.deps)],
    ["token --json", true, (h) => tokenCommand({ json: true }, h.deps)],
    ["env", true, (h) => envCommand({}, h.deps)],
    ["env --shell fish", true, (h) => envCommand({ shell: "fish" }, h.deps)],
    ["env --shell powershell", true, (h) => envCommand({ shell: "powershell" }, h.deps)],
    ["headers", true, (h) => headersCommand({}, h.deps)],
    ["status --show-token", true, (h) => statusCommand({ showToken: true }, h.deps)],
    ["status --json --show-token", true, (h) => statusCommand({ json: true, showToken: true }, h.deps)],
    ["status", false, (h) => statusCommand({}, h.deps)],
    ["status --json", false, (h) => statusCommand({ json: true }, h.deps)],
    ["status --host", false, (h) => statusCommand({ host: HOST }, h.deps)],
    ["logout", false, (h) => logoutCommand({}, h.deps)],
  ];

  it.each(cases)("%s", async (_name, handsOutToken, run) => {
    const h = harness({ stored: [fakeLogin()] });
    await run(h);
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
    expect(h.cap.out.includes(FAKE_TOKEN)).toBe(handsOutToken);
  });
});

describe("when there is no usable login or the server fails", () => {
  const expiredLogin = () => harness({ stored: [fakeLogin({ expiresAt: "2026-11-06T09:00:00.000Z" })] });
  const noLogin = () => {
    const h = harness();
    h.deps.resolveHost = async () => HOST;
    return h;
  };
  const serverDown = () => {
    const h = harness({ stored: [fakeLogin()] });
    h.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the key");
    h.knobs.discoverError = new AuthError("network", "no route");
    h.server.revokeError = new Error("boom");
    return h;
  };

  const withoutServer: [string, Run][] = [
    ["token", (h) => tokenCommand({}, h.deps)],
    ["token --json", (h) => tokenCommand({ json: true }, h.deps)],
    ["env", (h) => envCommand({}, h.deps)],
    ["headers", (h) => headersCommand({}, h.deps)],
  ];
  const withServer: [string, Run][] = [
    ["status", (h) => statusCommand({}, h.deps)],
    ["status --json", (h) => statusCommand({ json: true }, h.deps)],
    ["logout", (h) => logoutCommand({}, h.deps)],
  ];
  const situations: [string, () => H][] = [
    ["an expired login", expiredLogin],
    ["no login", noLogin],
  ];

  // token, env and headers never talk to the server, so only the first two situations apply.
  const matrix = [
    ...withoutServer.flatMap(([name, run]) => situations.map(([what, make]) => [name, what, make, run] as const)),
    ...withServer.flatMap(([name, run]) => [...situations, ["a failing server", serverDown] as [string, () => H]].map(([what, make]) => [name, what, make, run] as const)),
  ];

  it.each(matrix)("%s with %s prints no token", async (_name, _what, make, run) => {
    const h = make();
    await run(h);
    expect(h.cap.err).not.toContain(FAKE_TOKEN);
    expect(h.cap.out).not.toContain(FAKE_TOKEN);
  });
});

describe("login", () => {
  it("never prints the token or the device code, whether it succeeds, is refused, or cannot store", async () => {
    const device = harness();
    const pasted = harness({ stdinText: `${FAKE_TOKEN}\n` });
    const refused = harness({ stdinText: `${FAKE_TOKEN}\n` });
    refused.knobs.whoami = new AuthError("not_logged_in", "Galaxy rejected the key");
    const unstorable = harness();
    unstorable.store.keyringAvailable = false;
    unstorable.knobs.whoami = { username: "root", isAdmin: true };

    await loginCommand({ host: HOST_ARG }, device.deps);
    await loginCommand({ host: HOST_ARG, withToken: true }, pasted.deps);
    await loginCommand({ host: HOST_ARG, withToken: true }, refused.deps);
    await loginCommand({ host: HOST_ARG }, unstorable.deps);

    for (const h of [device, pasted, refused, unstorable]) {
      expect(h.cap.out).toBe("");
      expect(h.cap.err).not.toContain(FAKE_TOKEN);
      expect(h.cap.err).not.toContain(h.server.pending.deviceCode);
    }
  });
});
