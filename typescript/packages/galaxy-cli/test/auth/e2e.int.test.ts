/**
 * End to end: the built binary against the fake Galaxy, for what only the real binary shows:
 * the wiring in `deps.ts` and `index.ts`, real processes, real pipes, real files. One journey
 * runs as `gxy`; the rest are cases that need the binary. The config dir is a temp dir, the
 * keyring is off (`GXY_NO_KEYRING`) and HOME is a temp dir too, so nothing here touches the
 * developer's real logins.
 *
 * The CLI is built here into a private cache directory. galaxy-ops is not: it must already be
 * built (`corepack pnpm --filter @galaxyproject/galaxy-ops build`), and the test fails at
 * once, saying so, when its build is missing or older than its sources.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { execa, type ResultPromise } from "execa";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeGalaxy, type Approval, type FakeGalaxy } from "../support/fake-galaxy";

const pkgDir = fileURLToPath(new URL("../..", import.meta.url));
const opsDir = fileURLToPath(new URL("../../../galaxy-ops", import.meta.url));
// Built into a private directory inside the package (so `galaxy-ops` still resolves from
// node_modules), never into `dist`: `bin.smoke.int.test.ts` reads that.
const outDir = join(pkgDir, "node_modules", ".cache", "gxy-e2e");
const dist = join(outDir, "index.js");
const buildEnv = { COREPACK_ENABLE_DOWNLOAD_PROMPT: "0" };
const NAMES = ["gxy", "galaxy-cli"] as const;
type Name = (typeof NAMES)[number];

let work: string | undefined;
const bins: Record<string, string> = {};

async function newestMtime(dir: string): Promise<number> {
  let newest = 0;
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) newest = Math.max(newest, (await stat(join(entry.parentPath, entry.name))).mtimeMs);
  }
  return newest;
}

async function requireFreshOpsBuild(): Promise<void> {
  const rebuild = "Run: corepack pnpm --filter @galaxyproject/galaxy-ops build";
  const built = await stat(join(opsDir, "dist", "index.js")).catch(() => undefined);
  if (!built) throw new Error(`galaxy-ops has no build, which the binary imports at run time. ${rebuild}`);
  if (built.mtimeMs < (await newestMtime(join(opsDir, "src")))) {
    throw new Error(`galaxy-ops' build is older than its sources, so the binary would run stale code. ${rebuild}`);
  }
}

beforeAll(async () => {
  await requireFreshOpsBuild();
  await execa("corepack", ["pnpm", "exec", "tsup", "--out-dir", outDir], { cwd: pkgDir, env: buildEnv });
  work = await mkdtemp(join(tmpdir(), "gxy-e2e-"));
  for (const name of NAMES) {
    await mkdir(join(work, "bin", name), { recursive: true });
    bins[name] = join(work, "bin", name, name);
    await symlink(dist, bins[name]!);
  }
}, 180_000);

afterAll(async () => {
  // `work` is unset when beforeAll failed: leave that failure as the one that is reported.
  if (work) await rm(work, { recursive: true, force: true });
  await rm(outDir, { recursive: true, force: true });
});

const open: FakeGalaxy[] = [];
async function galaxyWith(options?: Parameters<typeof startFakeGalaxy>[0]): Promise<FakeGalaxy> {
  const g = await startFakeGalaxy(options);
  open.push(g);
  return g;
}
afterEach(async () => {
  await Promise.all(open.splice(0).map((g) => g.close()));
});

describe("auth, end to end", () => {
  let configDir: string;
  let galaxy: FakeGalaxy;

  beforeEach(async () => {
    configDir = join(work!, `config-${Math.random().toString(36).slice(2)}`);
    galaxy = await galaxyWith();
  });

  const cliEnv = (extra: Record<string, string> = {}) => ({ PATH: process.env.PATH ?? "", HOME: work!, GXY_CONFIG_DIR: configDir, GXY_NO_KEYRING: "1", ...extra });

  const run = (args: string[], opts: { env?: Record<string, string>; input?: string; name?: Name } = {}) =>
    execa(process.execPath, [bins[opts.name ?? "gxy"]!, ...args], {
      cwd: work,
      extendEnv: false,
      env: cliEnv(opts.env),
      input: opts.input,
      stdin: opts.input === undefined ? "ignore" : undefined,
      reject: false,
      timeout: 60_000,
    });

  /**
   * Start a device login, approve its code on the fake while the CLI polls, and wait for it.
   * The child never outlives the call, whatever happens in between.
   */
  async function deviceLogin(g: FakeGalaxy, approval: Approval | "expire" = {}, opts: { env?: Record<string, string> } = {}) {
    const before = new Set(g.pendingCodes());
    const child = run(["auth", "login", "--host", g.baseUrl], opts) as ResultPromise;
    try {
      let code: string | undefined;
      await vi.waitFor(
        () => {
          code = g.pendingCodes().find((c) => !before.has(c));
          if (!code) throw new Error("the CLI never asked for a device code");
        },
        { timeout: 15_000, interval: 20 },
      );
      if (approval === "expire") g.expire(code!);
      else g.approve(code!, { expiresIn: 3600, ...approval });
      return await child;
    } finally {
      child.kill();
      await child;
    }
  }

  it("logs in, shows it, hands out the token, runs an operation, logs out", async () => {
    const login = await deviceLogin(galaxy);
    expect(login.exitCode, login.stderr).toBe(0);
    expect(login.stderr).toContain("Logged in to");
    const token = galaxy.issuedTokens()[0]!;
    expect(login.stdout + login.stderr).not.toContain(token);

    // The directory is private to the user, and so is the file that holds the token.
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
    expect(env.stdout).toContain(`GALAXY_URL='${galaxy.baseUrl}'`);
    expect(env.stdout).toContain(`GALAXY_API_KEY='${token}'`);

    expect(JSON.parse((await run(["auth", "headers"])).stdout)).toEqual({ "x-api-key": token });

    // An existing operation uses the stored login with no flags.
    const user = await run(["--format", "json", "get_user"]);
    expect(user.exitCode, user.stderr).toBe(0);
    expect(JSON.parse(user.stdout)).toMatchObject({ success: true, data: { username: "fake-user" } });
    expect(galaxy.requestsTo("/api/users/current").at(-1)!.headers["x-api-key"]).toBe(token);

    // The binary identifies itself on every call of its own.
    for (const suffix of ["/api/version", "/oauth/device_authorization", "/oauth/token"]) {
      for (const r of galaxy.requestsTo(suffix)) expect(r.headers["user-agent"], r.url).toMatch(/^gxy\//);
    }

    const out = await run(["auth", "logout"]);
    expect(out.exitCode, out.stderr).toBe(0);
    expect(galaxy.isTokenValid(token)).toBe(false);
    expect(await readFile(join(configDir, "hosts.yml"), "utf8")).not.toContain(galaxy.baseUrl);
    const gone = await run(["auth", "token"]);
    expect(gone.exitCode).toBe(77); // nothing stored: not logged in
    expect(gone.stdout).toBe("");
  }, 90_000);

  it("presents the client id from GXY_OAUTH_CLIENT_ID", async () => {
    const login = await deviceLogin(galaxy, {}, { env: { GXY_OAUTH_CLIENT_ID: "fake-other-client" } });
    expect(login.exitCode, login.stderr).toBe(0);
    for (const suffix of ["/oauth/device_authorization", "/oauth/token"]) {
      expect(galaxy.requestsTo(suffix)[0]!.form.client_id).toBe("fake-other-client");
    }
  }, 30_000);

  describe("login --with-token", () => {
    it("stores an API key read from stdin", async () => {
      const token = galaxy.issueToken();
      const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: `${token}\n` });
      expect(login.exitCode, login.stderr).toBe(0);
      expect(login.stderr).toContain("Logged in to");
      expect(login.stdout + login.stderr).not.toContain(token);
      expect((await run(["auth", "token"])).stdout.trim()).toBe(token);
    }, 30_000);

    it("refuses a key Galaxy does not know, and stores nothing", async () => {
      const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: "fake-not-a-key\n" });
      expect(login.exitCode).toBe(77);
      await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toThrow();
    }, 30_000);

    it("refuses an admin key, storing nothing, when there is no keyring to keep it in", async () => {
      const token = galaxy.issueToken({ admin: true });
      const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: `${token}\n` });
      expect(login.exitCode, login.stderr).toBe(77);
      expect(login.stderr).toContain("admin rights");
      expect(login.stdout + login.stderr).not.toContain(token);
      await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toThrow();
    }, 30_000);
  });

  it.each(NAMES)("as %s, exits 76 and points at --with-token under its own name when the device flow is off", async (name) => {
    galaxy.setDeviceFlow(false);
    const login = await run(["auth", "login", "--host", galaxy.baseUrl], { name });
    expect(login.exitCode).toBe(76);
    expect(login.stderr).toContain(`${name} auth login --host ${galaxy.baseUrl} --with-token`);
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
    expect((await run(["get_user"])).exitCode).toBe(64);
    expect((await run(["auth", "token", "--host", second.baseUrl])).stdout.trim()).toBe(second.issuedTokens()[0]);
  }, 90_000);

  it("lets GALAXY_API_KEY override the stored login", async () => {
    expect((await deviceLogin(galaxy)).exitCode).toBe(0);
    const seen = galaxy.requestsTo("/api/users/current").length;
    const user = await run(["--format", "json", "get_user"], { env: { GALAXY_URL: galaxy.baseUrl, GALAXY_API_KEY: "fake-env-key" } });
    expect(user.exitCode, user.stderr).toBe(0);
    const keys = galaxy.requestsTo("/api/users/current").slice(seen).map((r) => r.headers["x-api-key"]);
    expect(keys).toEqual(["fake-env-key"]);
  }, 60_000);

  describe("headers for Claude Code's MCP server", () => {
    it("hands out the token for the Galaxy the server URL names, and refuses any other", async () => {
      expect((await deviceLogin(galaxy)).exitCode).toBe(0);
      const token = galaxy.issuedTokens()[0]!;

      const matching = await run(["auth", "headers"], { env: { CLAUDE_CODE_MCP_SERVER_URL: `${galaxy.baseUrl}/api/mcp` } });
      expect(matching.exitCode, matching.stderr).toBe(0);
      expect(JSON.parse(matching.stdout)).toEqual({ "x-api-key": token });

      const other = await run(["auth", "headers"], { env: { CLAUDE_CODE_MCP_SERVER_URL: "https://other.example.org/api/mcp" } });
      expect(other.exitCode).toBe(77);
      expect(other.stdout).toBe("");
      expect(other.stdout + other.stderr).not.toContain(token);
    }, 60_000);
  });

  it("lets `auth token | head -c1` end quietly with 0", async () => {
    expect((await deviceLogin(galaxy)).exitCode).toBe(0);
    const errFile = join(work!, "epipe-stderr");
    const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(bins.gxy)} auth token 2>${JSON.stringify(errFile)} | head -c1 >/dev/null; echo \${PIPESTATUS[0]}`;
    const r = await execa("bash", ["-c", command], { cwd: work, extendEnv: false, env: cliEnv(), timeout: 30_000 });
    expect(r.stdout.trim()).toBe("0");
    expect(await readFile(errFile, "utf8")).toBe("");
  }, 60_000);
});
