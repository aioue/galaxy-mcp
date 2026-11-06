/**
 * End to end: the built binary, run as `gxy` and as `galaxy-cli`, against the fake Galaxy.
 * The config dir is a temp dir, the keyring is off (`GXY_NO_KEYRING`) and HOME is a temp
 * dir too, so nothing here touches the developer's real logins.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { execa, type ResultPromise } from "execa";
import { mkdtemp, mkdir, readFile, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeGalaxy, type Approval, type FakeGalaxy } from "../support/fake-galaxy";
import { startDevice } from "./whoami.helpers";

const tsDir = fileURLToPath(new URL("../../../..", import.meta.url));
const dist = fileURLToPath(new URL("../../dist/index.js", import.meta.url));

let work: string;
const bins: Record<string, string> = {};

beforeAll(async () => {
  // Build once (galaxy-ops first, which the CLI imports at run time).
  await execa("corepack", ["pnpm", "-r", "build"], { cwd: tsDir, env: { COREPACK_ENABLE_DOWNLOAD_PROMPT: "0" } });
  work = await mkdtemp(join(tmpdir(), "gxy-e2e-"));
  for (const name of ["gxy", "galaxy-cli"]) {
    await mkdir(join(work, "bin", name), { recursive: true });
    bins[name] = join(work, "bin", name, name);
    await symlink(dist, bins[name]!);
  }
}, 180_000);

afterAll(() => rm(work, { recursive: true, force: true }));

const open: FakeGalaxy[] = [];
async function galaxyWith(options?: Parameters<typeof startFakeGalaxy>[0]): Promise<FakeGalaxy> {
  const g = await startFakeGalaxy(options);
  open.push(g);
  return g;
}
afterEach(async () => {
  await Promise.all(open.splice(0).map((g) => g.close()));
});

describe.each(["gxy", "galaxy-cli"])("%s auth, end to end", (name) => {
  let configDir: string;
  let galaxy: FakeGalaxy;

  beforeEach(async () => {
    configDir = join(work, `config-${name}-${Math.random().toString(36).slice(2)}`);
    galaxy = await galaxyWith();
  });

  const run = (args: string[], opts: { env?: Record<string, string>; input?: string } = {}) =>
    execa(process.execPath, [bins[name]!, ...args], {
      cwd: work,
      extendEnv: false,
      env: { PATH: process.env.PATH ?? "", HOME: work, GXY_CONFIG_DIR: configDir, GXY_NO_KEYRING: "1", ...opts.env },
      input: opts.input,
      stdin: opts.input === undefined ? "ignore" : undefined,
      reject: false,
    });

  /** Start a device login, approve its code on the fake while the CLI polls, and wait for it. */
  async function deviceLogin(g: FakeGalaxy, approval: Approval | "expire" | "none" = {}, extra: string[] = []) {
    const before = new Set(g.pendingCodes());
    const p: ResultPromise = run(["auth", "login", "--host", g.baseUrl, ...extra]) as ResultPromise;
    if (approval !== "none") {
      const deadline = Date.now() + 15_000;
      let code: string | undefined;
      while (!code && Date.now() < deadline) {
        code = g.pendingCodes().find((c) => !before.has(c));
        if (!code) await new Promise((r) => setTimeout(r, 20));
      }
      if (!code) throw new Error("the CLI never asked for a device code");
      if (approval === "expire") g.expire(code);
      else g.approve(code, { expiresIn: 3600, ...approval });
    }
    return p;
  }

  it("logs in, shows it, hands out the token, runs an operation, logs out", async () => {
    const login = await deviceLogin(galaxy);
    expect(login.exitCode, login.stderr).toBe(0);
    expect(login.stderr).toContain("Logged in to");
    const token = galaxy.issuedTokens()[0]!;
    expect(login.stdout + login.stderr).not.toContain(token);

    // Modes: the directory is private to the user, and so is the file that holds the token.
    expect((await stat(configDir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(configDir, "hosts.yml"))).mode & 0o777).toBe(0o600);

    const status = await run(["auth", "status"]);
    expect(status.exitCode, status.stderr).toBe(0);
    expect(status.stderr).toContain("Logged in as fake-user");
    expect(status.stdout + status.stderr).not.toContain(token);

    const json = await run(["auth", "status", "--json"]);
    expect(JSON.parse(json.stdout)[0]).toMatchObject({ base_url: galaxy.baseUrl, username: "fake-user", status: "ok" });

    const tok = await run(["auth", "token"]);
    expect(tok.exitCode).toBe(0);
    expect(tok.stdout.trim()).toBe(token);

    const env = await run(["auth", "env"]);
    expect(env.stdout).toContain(galaxy.baseUrl);
    expect(env.stdout).toContain(token);
    expect(env.stdout).toMatch(/GALAXY_URL=/);
    expect(env.stdout).toMatch(/GALAXY_API_KEY=/);

    const headers = await run(["auth", "headers"]);
    expect(JSON.parse(headers.stdout)).toEqual({ "x-api-key": token });

    // An existing operation uses the stored login with no flags.
    const user = await run(["--format", "json", "get_user"]);
    expect(user.exitCode, user.stderr).toBe(0);
    const parsed = JSON.parse(user.stdout);
    expect(parsed.success).toBe(true);
    expect(parsed.data.username).toBe("fake-user");
    expect(galaxy.requestsTo("/api/users/current").at(-1)!.headers["x-api-key"]).toBe(token);

    const out = await run(["auth", "logout"]);
    expect(out.exitCode, out.stderr).toBe(0);
    expect(galaxy.isTokenValid(token)).toBe(false);
    expect(await readFile(join(configDir, "hosts.yml"), "utf8")).not.toContain(galaxy.baseUrl);
    const gone = await run(["auth", "token"]);
    expect(gone.exitCode).toBe(77); // nothing stored: not logged in
    expect(gone.stdout).toBe("");
  }, 60_000);

  it("stores an API key from stdin with --with-token", async () => {
    const token = await startDevice(galaxy);
    const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: `${token}\n` });
    expect(login.exitCode, login.stderr).toBe(0);
    expect(login.stderr).toContain("Logged in to");
    expect(login.stdout + login.stderr).not.toContain(token);
    expect((await run(["auth", "token"])).stdout.trim()).toBe(token);
  }, 30_000);

  it("refuses a pasted key Galaxy does not know, and stores nothing", async () => {
    const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: "fake-not-a-key\n" });
    expect(login.exitCode).toBe(77);
    expect(login.stderr).toMatch(/invalid|newer API key/);
    await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toThrow();
  }, 30_000);

  it("exits 76 and points at --with-token when the device flow is off", async () => {
    galaxy.setDeviceFlow(false);
    const login = await run(["auth", "login", "--host", galaxy.baseUrl]);
    expect(login.exitCode).toBe(76);
    expect(login.stderr).toContain("--with-token");
    expect(login.stderr).toContain(`${name} auth login`);
  }, 30_000);

  it("exits 77 when the code expires", async () => {
    const login = await deviceLogin(galaxy, "expire");
    expect(login.exitCode, login.stderr).toBe(77);
    expect(login.stderr).toMatch(/expired/);
  }, 30_000);

  it("asks which Galaxy when two are stored", async () => {
    const second = await galaxyWith();
    expect((await deviceLogin(galaxy)).exitCode).toBe(0);
    expect((await deviceLogin(second)).exitCode).toBe(0);
    const ambiguous = await run(["auth", "token"]);
    expect(ambiguous.exitCode).toBe(64);
    expect(ambiguous.stdout).toBe("");
    expect(ambiguous.stderr).toContain(galaxy.baseUrl);
    expect(ambiguous.stderr).toContain(second.baseUrl);
    const ops = await run(["get_user"]);
    expect(ops.exitCode).toBe(64);
    expect((await run(["auth", "token", "--host", second.baseUrl])).stdout.trim()).toBe(second.issuedTokens()[0]);
  }, 60_000);

  it("lets GALAXY_API_KEY override the stored login", async () => {
    expect((await deviceLogin(galaxy)).exitCode).toBe(0);
    const stored = galaxy.issuedTokens()[0]!;
    const seen = galaxy.requestsTo("/api/users/current").length;
    const user = await run(["--format", "json", "get_user"], { env: { GALAXY_URL: galaxy.baseUrl, GALAXY_API_KEY: "fake-env-key" } });
    expect(user.exitCode, user.stderr).toBe(0);
    const keys = galaxy.requestsTo("/api/users/current").slice(seen).map((r) => r.headers["x-api-key"]);
    expect(keys).toEqual(["fake-env-key"]);
    expect(keys.at(-1)).toBe("fake-env-key");
    expect(keys).not.toContain(stored);
  }, 60_000);

  it("warns that --api-key is deprecated", async () => {
    const user = await run(["--url", galaxy.baseUrl, "--api-key", "fake-flag-key", "get_user"]);
    expect(user.stderr).toMatch(/--api-key is deprecated/);
    expect(user.stderr).toContain(`${name} auth login`);
  }, 30_000);

  it("keeps the old error when nothing is configured", async () => {
    const user = await run(["get_user"]);
    expect(user.exitCode).toBe(64);
    expect(user.stderr).toMatch(/No Galaxy credentials/);
  }, 30_000);
});
