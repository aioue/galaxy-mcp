/**
 * End to end: the built binary against the fake Galaxy, for what only the real binary shows:
 * the wiring in `deps.ts` and `index.ts`, real processes, real pipes, real files. One journey
 * runs as `gxy`; the rest are cases that need the binary. The config dir is a temp dir, the
 * keyring is off (`GXY_NO_KEYRING`) and HOME is a temp dir too, so nothing here touches the
 * developer's real logins.
 *
 * The CLI is built here into a private cache directory, and galaxy-ops (which the binary
 * imports at run time) is built first, so a stale or missing build cannot be what is tested.
 */
import { afterAll, beforeAll, describe, expect, test as base, vi } from "vitest";
import { execa, type ResultPromise } from "execa";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, mkdir, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { createServer, type Socket } from "node:net";
import { fileURLToPath } from "node:url";
import { startFakeGalaxy, type Approval, type FakeGalaxy } from "../support/fake-galaxy";

const pkgDir = fileURLToPath(new URL("../..", import.meta.url));
// Built into a private directory inside the package (so `galaxy-ops` still resolves from
// node_modules), never into `dist`: `bin.smoke.int.test.ts` reads that.
const outDir = join(pkgDir, "node_modules", ".cache", "gxy-e2e");
const dist = join(outDir, "index.js");
const buildEnv = { COREPACK_ENABLE_DOWNLOAD_PROMPT: "0" };
const NAMES = ["gxy", "galaxy-cli"] as const;
type Name = (typeof NAMES)[number];

let work: string | undefined;
const bins: Record<string, string> = {};

beforeAll(async () => {
  // The binary imports galaxy-ops' build at run time, so build it too rather than trust a cached one.
  await execa("corepack", ["pnpm", "--filter", "@galaxyproject/galaxy-ops", "build"], { cwd: pkgDir, env: buildEnv });
  await execa("corepack", ["pnpm", "exec", "tsup", "--out-dir", outDir], { cwd: pkgDir, env: buildEnv });
  work = await mkdtemp(join(tmpdir(), "gxy-e2e-"));
  for (const name of NAMES) {
    await mkdir(join(work, "bin", name), { recursive: true });
    bins[name] = join(work, "bin", name, name);
    await symlink(dist, bins[name]!);
  }
}, 240_000);

afterAll(async () => {
  // `work` is unset when beforeAll failed: leave that failure as the one that is reported.
  if (work) await rm(work, { recursive: true, force: true });
  await rm(outDir, { recursive: true, force: true });
});

type Run = (args: string[], opts?: { env?: Record<string, string>; input?: string; name?: Name; cwd?: string }) => ResultPromise<{ reject: false }>;
type Login = Awaited<ReturnType<Run>>;
/** What one run of the CLI printed, for the checks that no secret went to a screen. */
interface Seen {
  args: string[];
  stdout: string;
  stderr: string;
}

// Every test gets its own HOME (and so its own config dir, under it), its own fake Galaxy and a
// `run` that starts the binary with them. They are made when a test asks for them and removed when it ends.
const test = base.extend<{
  home: string;
  configDir: string;
  galaxyWith: (options?: Parameters<typeof startFakeGalaxy>[0]) => Promise<FakeGalaxy>;
  galaxy: FakeGalaxy;
  transcript: Seen[];
  cliEnv: (extra?: Record<string, string>) => Record<string, string>;
  run: Run;
  deviceLogin: (g: FakeGalaxy, approval?: Approval | "expire", opts?: { env?: Record<string, string>; cwd?: string; noHost?: boolean }) => Promise<Login>;
}>({
  home: async ({ onTestFinished }, use) => {
    const dir = await mkdtemp(join(work!, "home-"));
    onTestFinished(() => rm(dir, { recursive: true, force: true }));
    await use(dir);
  },
  configDir: async ({ home }, use) => use(join(home, "config")),
  galaxyWith: async ({ onTestFinished }, use) =>
    use(async (options) => {
      const g = await startFakeGalaxy(options);
      onTestFinished(() => g.close());
      return g;
    }),
  galaxy: async ({ galaxyWith }, use) => use(await galaxyWith()),
  transcript: async ({}, use) => use([]),
  cliEnv: async ({ home, configDir }, use) =>
    use((extra = {}) => ({ PATH: process.env.PATH ?? "", HOME: home, GXY_CONFIG_DIR: configDir, GXY_NO_KEYRING: "1", ...extra })),
  run: async ({ home, cliEnv, transcript }, use) =>
    use((args, opts = {}) => {
      // Typed as text output: `input` and `stdin` below are both conditional, which widens execa's result.
      const child = execa(process.execPath, [bins[opts.name ?? "gxy"]!, ...args], {
        cwd: opts.cwd ?? home,
        extendEnv: false,
        env: cliEnv(opts.env),
        input: opts.input,
        stdin: opts.input === undefined ? "ignore" : undefined,
        reject: false,
        timeout: 60_000,
      }) as unknown as ResultPromise<{ reject: false }>;
      // Registered before any caller's `await`, so the transcript is complete when the caller resumes.
      void child.then((r) => transcript.push({ args, stdout: r.stdout, stderr: r.stderr }));
      return child;
    }),
  /**
   * Start a device login, approve its code on the fake while the CLI polls, and wait for it.
   * The child never outlives the call, whatever happens in between.
   */
  deviceLogin: async ({ run }, use) =>
    use(async (g, approval = {}, opts = {}) => {
      const before = new Set(g.pendingCodes());
      const child = run(opts.noHost ? ["auth", "login"] : ["auth", "login", "--host", g.baseUrl], opts);
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
        const result = await child;
        // The device code is the secret the CLI polls with: it must never be shown to anyone.
        for (const deviceCode of g.deviceCodes()) {
          expect(result.stdout, "stdout").not.toContain(deviceCode);
          expect(result.stderr, "stderr").not.toContain(deviceCode);
        }
        return result;
      } finally {
        child.kill();
        await child;
      }
    }),
});

// The canary: a token no other value in the run resembles, so finding it anywhere is finding the secret.
const CANARY = "fake-canary-6d3f0a9b2e71";

/** Every file under `root` (as a path relative to it, sorted) whose bytes contain `needle`. */
async function filesHolding(root: string, needle: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile() && (await readFile(path)).includes(needle)) found.push(relative(root, path));
    }
  };
  await walk(root);
  return found.sort();
}

/**
 * The token is only where it belongs, wherever it could have gone:
 * - on disk, in `files` (paths under `home`) and nowhere else under HOME, whatever the file is called;
 * - on the wire, in an `x-api-key` or `authorization` header, or in the body of a revocation: never
 *   in a URL (which proxies and logs keep), another header or another body;
 * - on screen, only for the commands whose job is to print it: `auth token`, `env` and `headers`.
 */
async function expectTokenOnlyWhereAllowed(
  token: string,
  where: { home: string; files: string[]; galaxy: FakeGalaxy; transcript: Seen[] },
): Promise<void> {
  expect(await filesHolding(where.home, token), "files under HOME holding the token").toEqual(where.files);
  const forms = [token, encodeURIComponent(token)];
  for (const r of where.galaxy.requests) {
    const what = `${r.method} ${r.url}`;
    for (const form of forms) expect(r.url, what).not.toContain(form);
    for (const [name, value] of Object.entries(r.headers)) {
      if (name === "x-api-key" || name === "authorization") continue;
      expect([value].flat().join("\n"), `${what}, header ${name}`).not.toContain(token);
    }
    if (!new URL(r.url, "http://x").pathname.endsWith("/oauth/revoke")) expect(r.body, `${what}, body`).not.toContain(token);
  }
  for (const seen of where.transcript) {
    if (seen.args[0] === "auth" && ["token", "env", "headers"].includes(seen.args[1] ?? "")) continue;
    expect(seen.stdout, `stdout of ${seen.args.join(" ")}`).not.toContain(token);
    expect(seen.stderr, `stderr of ${seen.args.join(" ")}`).not.toContain(token);
  }
}

describe("auth, end to end", () => {
  test("logs in, shows it, hands out the token, runs an operation, logs out", async ({ galaxy, run, deviceLogin, configDir, home, transcript }) => {
    const login = await deviceLogin(galaxy, { accessToken: CANARY });
    expect(login.exitCode, login.stderr).toBe(0);
    expect(login.stderr).toContain("Logged in to");
    const token = galaxy.issuedTokens()[0]!;
    expect(token).toBe(CANARY);
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

    // Logged in: the token is in the one file that holds logins, and nowhere else.
    await expectTokenOnlyWhereAllowed(token, { home, files: ["config/hosts.yml"], galaxy, transcript });

    const out = await run(["auth", "logout"]);
    expect(out.exitCode, out.stderr).toBe(0);
    expect(galaxy.isTokenValid(token)).toBe(false);
    expect(await readFile(join(configDir, "hosts.yml"), "utf8")).not.toContain(galaxy.baseUrl);
    // Logged out: it is gone from every file under HOME, not only from the one we know about.
    await expectTokenOnlyWhereAllowed(token, { home, files: [], galaxy, transcript });
    const gone = await run(["auth", "token"]);
    expect(gone.exitCode).toBe(77); // nothing stored: not logged in
    expect(gone.stdout).toBe("");
  }, 90_000);

  test("presents the client id from GXY_OAUTH_CLIENT_ID", async ({ galaxy, deviceLogin }) => {
    const login = await deviceLogin(galaxy, {}, { env: { GXY_OAUTH_CLIENT_ID: "fake-other-client" } });
    expect(login.exitCode, login.stderr).toBe(0);
    for (const suffix of ["/oauth/device_authorization", "/oauth/token"]) {
      expect(galaxy.requestsTo(suffix)[0]!.form.client_id).toBe("fake-other-client");
    }
  }, 30_000);

  describe("login --with-token", () => {
    test("stores an API key read from stdin", async ({ galaxy, run, home, transcript }) => {
      const token = galaxy.issueToken({ accessToken: CANARY });
      const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: `${token}\n` });
      expect(login.exitCode, login.stderr).toBe(0);
      expect(login.stderr).toContain("Logged in to");
      expect(login.stdout + login.stderr).not.toContain(token);
      expect((await run(["auth", "token"])).stdout.trim()).toBe(token);
      await expectTokenOnlyWhereAllowed(token, { home, files: ["config/hosts.yml"], galaxy, transcript });
    }, 30_000);

    test("refuses a key Galaxy does not know, and stores nothing", async ({ galaxy, run, configDir }) => {
      const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: "fake-not-a-key\n" });
      expect(login.exitCode).toBe(77);
      await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    }, 30_000);

    test("refuses an admin key, storing nothing, when there is no keyring to keep it in", async ({ galaxy, run, configDir, home, transcript }) => {
      const token = galaxy.issueToken({ admin: true, accessToken: CANARY });
      const login = await run(["auth", "login", "--host", galaxy.baseUrl, "--with-token"], { input: `${token}\n` });
      expect(login.exitCode, login.stderr).toBe(77);
      expect(login.stderr).toContain("admin rights");
      expect(login.stdout + login.stderr).not.toContain(token);
      await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
      // Refused, so the token reached no file at all, wherever a store might have put it.
      await expectTokenOnlyWhereAllowed(token, { home, files: [], galaxy, transcript });
    }, 30_000);
  });

  test.for(NAMES)("as %s, exits 76 and points at --with-token under its own name when the device flow is off", { timeout: 30_000 }, async (name, { galaxy, run }) => {
    galaxy.setDeviceFlow(false);
    const login = await run(["auth", "login", "--host", galaxy.baseUrl], { name });
    expect(login.exitCode).toBe(76);
    expect(login.stderr).toContain(`${name} auth login --host ${galaxy.baseUrl} --with-token`);
  });

  test("exits 77 when the code expires", async ({ galaxy, deviceLogin }) => {
    const login = await deviceLogin(galaxy, "expire");
    expect(login.exitCode, login.stderr).toBe(77);
    expect(login.stderr).toMatch(/expired/);
  }, 30_000);

  test("asks which Galaxy when two are stored", async ({ galaxy, galaxyWith, run, deviceLogin }) => {
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

  test("lets GALAXY_API_KEY override the stored login", async ({ galaxy, run, deviceLogin }) => {
    expect((await deviceLogin(galaxy)).exitCode).toBe(0);
    const seen = galaxy.requestsTo("/api/users/current").length;
    const user = await run(["--format", "json", "get_user"], { env: { GALAXY_URL: galaxy.baseUrl, GALAXY_API_KEY: "fake-env-key" } });
    expect(user.exitCode, user.stderr).toBe(0);
    const keys = galaxy.requestsTo("/api/users/current").slice(seen).map((r) => r.headers["x-api-key"]);
    expect(keys).toEqual(["fake-env-key"]);
  }, 60_000);

  describe("headers for Claude Code's MCP server", () => {
    test("hands out the token for the Galaxy the server URL names, and refuses any other", async ({ galaxy, run, deviceLogin }) => {
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

  test("lets `auth token | head -c1` end quietly with 0, when the output is more than the pipe holds", async ({ galaxy, run, cliEnv, home, configDir }) => {
    // A short token fits in the pipe's buffer before `head` leaves, so no write ever fails and
    // nothing is tested. A token of half a megabyte cannot: the write is still going when the
    // reader goes, and it fails with a real EPIPE. (Any printable ASCII is a token: token-shape.ts.)
    const token = "fake-big-token-".padEnd(512 * 1024, "x");
    await mkdir(configDir, { mode: 0o700 });
    await writeFile(
      join(configDir, "hosts.yml"),
      `hosts:\n  ${galaxy.baseUrl}:\n    username: fake-user\n    method: pasted\n    scopes: []\n    expires_at: null\n    obtained_at: "2026-01-01T00:00:00.000Z"\n    storage: file\n    token: ${token}\n`,
      { mode: 0o600 },
    );
    const whole = await run(["auth", "token"]);
    expect(whole.exitCode, whole.stderr).toBe(0);
    expect(whole.stdout.length, "more than a 64 KiB pipe buffer").toBeGreaterThan(256 * 1024);

    const errFile = join(home, "epipe-stderr");
    const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(bins.gxy)} auth token 2>${JSON.stringify(errFile)} | head -c1 >/dev/null; echo \${PIPESTATUS[0]}`;
    const r = await execa("bash", ["-c", command], { cwd: home, extendEnv: false, env: cliEnv(), timeout: 30_000 });
    expect(r.stdout.trim()).toBe("0");
    expect(await readFile(errFile, "utf8")).toBe("");
  }, 60_000);

  describe("login never takes its host from a .env in the working directory", () => {
    /** A working directory whose `.env` names `url` as the Galaxy. */
    async function cwdWithDotenv(home: string, url: string): Promise<string> {
      const dir = await mkdtemp(join(home, "cwd-"));
      await writeFile(join(dir, ".env"), `GALAXY_URL=${url}\n`);
      return dir;
    }

    test("a pasted key with no --host is a usage error, and the .env's Galaxy is never contacted", async ({ galaxyWith, run, configDir, home }) => {
      const decoy = await galaxyWith();
      const cwd = await cwdWithDotenv(home, decoy.baseUrl);
      const token = decoy.issueToken();
      const login = await run(["auth", "login", "--with-token"], { cwd, input: `${token}\n` });
      expect(login.exitCode, login.stderr).toBe(64);
      expect(decoy.requests).toEqual([]);
      expect(login.stdout + login.stderr).not.toContain(token);
      await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    }, 30_000);

    test("the device flow goes to the stored login, says it ignored the .env, and never contacts the .env's Galaxy", async ({ galaxy, galaxyWith, deviceLogin, home }) => {
      const decoy = await galaxyWith();
      expect((await deviceLogin(galaxy)).exitCode).toBe(0);
      const cwd = await cwdWithDotenv(home, decoy.baseUrl);
      const seen = galaxy.requests.length;
      const login = await deviceLogin(galaxy, {}, { cwd, noHost: true });
      expect(login.exitCode, login.stderr).toBe(0);
      expect(login.stderr).toContain("Ignoring GALAXY_URL from .env");
      expect(galaxy.requests.length).toBeGreaterThan(seen);
      expect(decoy.requests).toEqual([]);
    }, 60_000);
  });

  describe("Ctrl-C", () => {
    test("aborts the wait for approval: exit 130, \"Cancelled.\", nothing stored, and the process is gone", async ({ galaxy, run, configDir }) => {
      const child = run(["auth", "login", "--host", galaxy.baseUrl]);
      try {
        await vi.waitFor(
          () => {
            if (galaxy.pendingCodes().length === 0) throw new Error("the CLI never asked for a device code");
          },
          { timeout: 15_000, interval: 20 },
        );
        child.kill("SIGINT");
        const r = await child;
        expect(r.signal).toBeUndefined(); // handled, not killed by the signal
        expect(r.exitCode).toBe(130);
        expect(r.stderr).toContain("Cancelled.");
        await expect(readFile(join(configDir, "hosts.yml"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        child.kill();
        await child;
      }
    }, 30_000);
  });

  // `interactive` is decided in deps.ts from the real streams: stdin and stderr both terminals. Only a
  // pseudo-terminal shows it. util-linux `script` gives the binary one without a native addon.
  // On a terminal the CLI offers to open the page (when it can: `$BROWSER` here), and Enter does it.
  const hasScript = process.platform === "linux" && /util-linux/.test(spawnSync("script", ["--version"], { encoding: "utf8" }).stdout ?? "");
  describe.skipIf(!hasScript)("on a terminal (a pseudo-terminal from `script`)", () => {
    const OFFER = "Press Enter to open that page in your browser";

    /** A `$BROWSER` that records its argument count and arguments, one per line, in a file. */
    async function browserStub(home: string) {
      const path = join(home, "stub-browser");
      const argvFile = join(home, "stub-browser.argv");
      await writeFile(path, `#!/bin/sh\nprintf '%s\\n' "$#" "$@" > "${argvFile}.part" && mv "${argvFile}.part" "${argvFile}"\n`);
      await chmod(path, 0o755);
      return { path, argvFile, opened: () => readFile(argvFile, "utf8").then((t) => t.split("\n").slice(0, -1), () => null) };
    }

    /** `script` runs `command` with a terminal for stdin, stdout and stderr, and exits with its status. */
    function onTerminal(command: string, home: string, env: Record<string, string>) {
      return execa("script", ["-qec", command, "/dev/null"], { cwd: home, extendEnv: false, env, stdin: "pipe", reject: false, timeout: 60_000 });
    }
    const quoted = (...args: string[]) => args.map((a) => JSON.stringify(a)).join(" ");

    test("shows the code and offers the browser, and Enter opens the verification page as one argument", async ({ galaxy, home, cliEnv }) => {
      const stub = await browserStub(home);
      const child = onTerminal(quoted(process.execPath, bins.gxy!, "auth", "login", "--host", galaxy.baseUrl), home, cliEnv({ BROWSER: stub.path }));
      let screen = "";
      child.stdout!.on("data", (d: Buffer) => (screen += d.toString()));
      try {
        await vi.waitFor(() => expect(screen).toContain(OFFER), { timeout: 15_000, interval: 20 });
        const [code] = galaxy.pendingCodes();
        expect(screen).toContain(`One-time code: ${code}`);
        expect(await stub.opened(), "nothing opens before Enter").toBeNull();

        child.stdin!.write("\n");
        await vi.waitFor(async () => expect(await stub.opened()).not.toBeNull(), { timeout: 15_000, interval: 20 });
        expect(await stub.opened()).toEqual(["1", `${galaxy.baseUrl}/oauth/device`]);

        galaxy.approve(code!, { expiresIn: 3600 });
        const r = await child;
        expect(r.exitCode, screen).toBe(0);
        expect(r.stdout).toContain("Logged in to");
        for (const deviceCode of galaxy.deviceCodes()) expect(r.stdout).not.toContain(deviceCode);
      } finally {
        child.kill();
        await child;
      }
    }, 60_000);

    // The offer needs both streams to be terminals: this is what tells `gxy auth login | tee` and
    // `gxy auth login 2>log` from a person at a keyboard, so neither may wait for Enter.
    test.for(["stdin is a pipe", "stderr goes to a file"] as const)("offers nothing, and opens nothing, when %s", { timeout: 60_000 }, async (why, { galaxy, home, cliEnv, deviceLogin }) => {
      const stub = await browserStub(home);
      let screen: string;
      if (why === "stdin is a pipe") {
        const r = await deviceLogin(galaxy, {}, { env: { BROWSER: stub.path } });
        expect(r.exitCode, r.stderr).toBe(0);
        screen = r.stderr;
      } else {
        const errFile = join(home, "login-stderr");
        const command = `${quoted(process.execPath, bins.gxy!, "auth", "login", "--host", galaxy.baseUrl)} 2>${JSON.stringify(errFile)}`;
        const child = onTerminal(command, home, cliEnv({ BROWSER: stub.path }));
        try {
          await vi.waitFor(() => expect(galaxy.pendingCodes()).not.toEqual([]), { timeout: 15_000, interval: 20 });
          child.stdin!.write("\n"); // were it offered, this would open the page
          galaxy.approve(galaxy.pendingCodes()[0]!, { expiresIn: 3600 });
          expect((await child).exitCode).toBe(0);
        } finally {
          child.kill();
          await child;
        }
        screen = await readFile(errFile, "utf8");
      }
      expect(screen).toContain("One-time code:");
      expect(screen).toContain("Logged in to");
      expect(screen).not.toContain(OFFER);
      expect(await stub.opened()).toBeNull();
    });
  });

  // The keyring helper is a second built file (dist/keyring-child.js). Every other case turns the
  // keyring off, so this is the one that would notice it missing from the build.
  describe.skipIf(process.platform !== "linux")("the real keyring helper, against a session bus that never answers", () => {
    test("reports that the keyring did not answer, within the timeout plus a margin, and exits", async ({ galaxy, run, configDir, skip }) => {
      const dir = await mkdtemp(join(tmpdir(), "gxy-bus-"));
      const sockets = new Set<Socket>();
      const server = createServer((c) => {
        sockets.add(c);
        c.on("data", () => {});
        c.on("error", () => {});
      });
      try {
        const sock = join(dir, "bus.sock");
        try {
          await new Promise<void>((res, rej) => {
            server.once("error", rej);
            server.listen(sock, res);
          });
        } catch {
          skip(); // no unix sockets here
        }
        // A login whose token lives in the keyring: the record is in hosts.yml, the token is not.
        await mkdir(configDir, { mode: 0o700 });
        await writeFile(
          join(configDir, "hosts.yml"),
          `hosts:\n  ${galaxy.baseUrl}:\n    username: fake-user\n    method: device\n    scopes: []\n    expires_at: null\n    obtained_at: "2026-01-01T00:00:00.000Z"\n    storage: keyring\n`,
          { mode: 0o600 },
        );
        const t0 = Date.now();
        const r = await run(["auth", "token"], { env: { GXY_NO_KEYRING: "", DBUS_SESSION_BUS_ADDRESS: `unix:path=${sock}` } });
        expect(r.exitCode, r.stderr).toBe(77);
        expect(r.stderr).toContain("did not answer");
        expect(r.stdout).toBe("");
        expect(Date.now() - t0).toBeLessThan(5000 + 15_000); // the 5 s timeout, plus a loaded machine
      } finally {
        for (const c of sockets) c.destroy();
        server.close();
        await rm(dir, { recursive: true, force: true });
      }
    }, 40_000);
  });
});
