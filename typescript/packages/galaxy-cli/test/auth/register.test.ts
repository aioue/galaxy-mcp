import { describe, it, expect, vi } from "vitest";
import { buildProgram, programName } from "../../src/program";
import { parseScopes } from "../../src/auth/register";
import { allOperations } from "@galaxyproject/galaxy-ops";
import { FAKE_TOKEN, fakeLogin, harness } from "./fakes";

async function run(argv: string[], h = harness({ stored: [fakeLogin()] })) {
  process.exitCode = 0;
  const makeAuthDeps = vi.fn(() => h.deps);
  await buildProgram({ makeAuthDeps, invokedAs: "gxy" }).parseAsync(["node", "gxy", ...argv]);
  const code = process.exitCode;
  process.exitCode = 0;
  return { h, code, makeAuthDeps };
}

describe("registerAuth", () => {
  it("lists the six subcommands in `auth --help`", () => {
    const auth = buildProgram().commands.find((c) => c.name() === "auth")!;
    expect(auth.commands.map((c) => c.name()).sort()).toEqual(["env", "headers", "login", "logout", "status", "token"]);
    const help = auth.helpInformation();
    for (const n of ["login", "status", "token", "env", "headers", "logout"]) expect(help).toContain(n);
  });

  it("does not build deps for --help or for operation commands", () => {
    const makeAuthDeps = vi.fn(() => harness().deps);
    buildProgram({ makeAuthDeps });
    expect(makeAuthDeps).not.toHaveBeenCalled();
  });

  it("parses --scopes comma- or space-separated", () => {
    expect(parseScopes("a,b")).toEqual(["a", "b"]);
    expect(parseScopes("a b")).toEqual(["a", "b"]);
    expect(parseScopes("a, b  c")).toEqual(["a", "b", "c"]);
  });

  it("runs `auth token` through the injected deps, with the command name, and sets the exit code", async () => {
    const { h, code, makeAuthDeps } = await run(["auth", "token"]);
    expect(makeAuthDeps).toHaveBeenCalledWith("gxy");
    expect(h.cap.out).toBe(`${FAKE_TOKEN}\n`);
    expect(code).toBe(0);
  });

  it("passes --host, --json and --show-token", async () => {
    const { h } = await run(["auth", "status", "--host", "https://dev.galaxy.example.org", "--json", "--show-token"]);
    expect(JSON.parse(h.cap.out)[0].token).toBe(FAKE_TOKEN);
  });

  it("passes --shell and rejects bad values", async () => {
    const { h } = await run(["auth", "env", "--shell", "fish"]);
    expect(h.cap.out).toContain("set -gx GALAXY_API_KEY");
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const prog = buildProgram({ makeAuthDeps: () => harness().deps });
    prog.exitOverride();
    prog.commands.find((c) => c.name() === "auth")!.commands.forEach((c) => c.exitOverride());
    await expect(prog.parseAsync(["node", "gxy", "auth", "env", "--shell", "csh"])).rejects.toThrow();
    err.mockRestore();
  });

  it("login: --scopes, --no-browser, --with-token and --insecure-storage reach the command", async () => {
    const h = harness({ stdinText: `${FAKE_TOKEN}\n` });
    const { code } = await run(["auth", "login", "--host", "https://dev.galaxy.example.org", "--with-token", "--insecure-storage", "--no-browser", "--scopes", "a,b"], h);
    expect(code).toBe(0);
    expect(h.store.putCalls[0]!.opts).toEqual({ insecureStorage: true });
    const d = harness();
    await run(["auth", "login", "--host", "https://dev.galaxy.example.org", "--scopes", "a b"], d);
    expect(d.server.startedWith).toEqual([["a", "b"]]);
  });

  it("a deps factory that throws gives exit 70 and a message", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    process.exitCode = 0;
    await buildProgram({ makeAuthDeps: () => { throw new Error("nope"); } }).parseAsync(["node", "gxy", "auth", "token"]);
    expect(process.exitCode).toBe(70);
    expect(err.mock.calls.flat().join("")).toContain("nope");
    err.mockRestore();
    process.exitCode = 0;
  });
});

describe("program name", () => {
  it("is gxy only when invoked as gxy", () => {
    expect(programName("/usr/local/bin/gxy")).toBe("gxy");
    expect(programName("/home/u/bin/gxy.cmd")).toBe("gxy");
    expect(programName("/x/dist/index.js")).toBe("galaxy-cli");
    expect(programName("/usr/bin/galaxy-cli")).toBe("galaxy-cli");
    expect(programName(undefined)).toBe("galaxy-cli");
  });
});

describe("existing commands are undisturbed", () => {
  it("keeps the global options and every operation subcommand", () => {
    const p = buildProgram();
    expect(p.options.map((o) => o.long).sort()).toEqual(["--api-key", "--format", "--profile", "--quiet", "--timeout", "--url"]);
    const names = p.commands.map((c) => c.name());
    for (const op of allOperations) expect(names).toContain(op.name);
    expect(names).toContain("auth");
  });
});
