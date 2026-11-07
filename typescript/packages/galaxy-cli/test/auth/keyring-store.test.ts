import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { childEnv, KeyringStore, KeyringUnavailableError, nativeBackend } from "../../src/auth/keyring-store";
import { HOST as baseUrl, FakeKeyring, useTempDir } from "./harness";

describe("KeyringStore", () => {
  it("keys entries by gxy:<baseUrl> and username", async () => {
    const kr = new FakeKeyring();
    const s = new KeyringStore(kr, 50);
    await s.set(baseUrl, "alice", "FAKE");
    expect([...kr.data.keys()]).toEqual([`gxy:${baseUrl}|alice`]);
    expect(await s.get(baseUrl, "alice")).toBe("FAKE");
    expect(await s.delete(baseUrl, "alice")).toBe(true);
  });
  it("times out a hung backend", async () => {
    const kr = new FakeKeyring();
    kr.mode = "hang";
    await expect(new KeyringStore(kr, 20).get(baseUrl, "alice")).rejects.toThrow(KeyringUnavailableError);
  });
  it("wraps backend errors", async () => {
    const kr = new FakeKeyring();
    kr.mode = "throw";
    await expect(new KeyringStore(kr, 50).set(baseUrl, "a", "x")).rejects.toThrow(/system keyring failed/);
  });
});

describe("KeyringStore.delete is verified", () => {
  it("reads back after deleting and reports the secret may remain when it is still there", async () => {
    const kr = new FakeKeyring();
    const s = new KeyringStore(kr, 50);
    await s.set(baseUrl, "alice", "FAKE");
    kr.mode = "undeletable";
    await expect(s.delete(baseUrl, "alice")).rejects.toThrow(/may remain/);
  });
  it("reports false when there was nothing to delete, and does not throw", async () => {
    expect(await new KeyringStore(new FakeKeyring(), 50).delete(baseUrl, "alice")).toBe(false);
  });
});

// The real backend against stub children: the protocol, the kill on timeout, and what the child is given.
describe("nativeBackend (stub child)", () => {
  const tmp = useTempDir("gxy-kc-");
  const stub = async (body: string) => {
    const p = join(tmp.path, "stub.mjs");
    await writeFile(p, body);
    return p;
  };
  const env = { PATH: process.env.PATH };

  it("sends the request as JSON on stdin and reads the JSON reply", async () => {
    const script = await stub(`
      let s = ""; for await (const c of process.stdin) s += c;
      const r = JSON.parse(s);
      process.stdout.write(JSON.stringify({ ok: true, value: r.op === "get" ? r.service + "/" + r.account : true }));`);
    const b = nativeBackend({ script, env, timeoutMs: 5000 });
    expect(await b.get("svc", "acct")).toBe("svc/acct");
    await b.set("svc", "acct", "FAKE");
    expect(await b.delete("svc", "acct")).toBe(true);
  });

  it("keeps the secret out of the child's argv and environment, and passes no GALAXY_* variables", async () => {
    const log = join(tmp.path, "log.json");
    const script = await stub(`
      import { writeFileSync } from "node:fs";
      let s = ""; for await (const c of process.stdin) s += c;
      writeFileSync(${JSON.stringify(log)}, JSON.stringify({ argv: process.argv, env: process.env, stdin: s }));
      process.stdout.write(JSON.stringify({ ok: true, value: true }));`);
    const secret = "FAKE-SECRET-VALUE-123";
    const saved = process.env.GALAXY_API_KEY;
    process.env.GALAXY_API_KEY = "FAKE-API-KEY-456";
    try {
      await nativeBackend({ script, timeoutMs: 5000 }).set("svc", "acct", secret);
    } finally {
      if (saved === undefined) delete process.env.GALAXY_API_KEY; else process.env.GALAXY_API_KEY = saved;
    }
    const seen = JSON.parse(await readFile(log, "utf8")) as { argv: string[]; env: Record<string, string>; stdin: string };
    expect(JSON.stringify(seen.argv)).not.toContain(secret);
    expect(JSON.stringify(seen.env)).not.toContain(secret);
    expect(JSON.stringify(seen.env)).not.toContain("FAKE-API-KEY-456");
    expect(Object.keys(seen.env).some((k) => k.startsWith("GALAXY_"))).toBe(false);
    expect(JSON.parse(seen.stdin)).toMatchObject({ op: "set", secret });
  });

  it("childEnv keeps what the bus needs and drops everything else", () => {
    const e = childEnv({ HOME: "/h", DBUS_SESSION_BUS_ADDRESS: "unix:path=/x", GALAXY_API_KEY: "K", AWS_SECRET_ACCESS_KEY: "S" });
    expect(e).toEqual({ HOME: "/h", DBUS_SESSION_BUS_ADDRESS: "unix:path=/x" });
  });

  it("kills a child that never answers and reports that the keyring did not answer", async () => {
    const pidFile = join(tmp.path, "pid");
    const script = await stub(`
      import { writeFileSync } from "node:fs";
      writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
      setInterval(() => {}, 1000);`);
    // The backend's timeout is shorter than the store's, so it is the layer that gives up. It is
    // wide enough for a loaded machine to start Node and write the pid file.
    const call = new KeyringStore(nativeBackend({ script, env, timeoutMs: 2500 }), 6000).get(baseUrl, "alice");
    const outcome = expect(call).rejects.toThrow(/did not answer a get within 2500 ms/);
    await vi.waitFor(async () => expect(Number(await readFile(pidFile, "utf8"))).toBeGreaterThan(0), { timeout: 2000, interval: 20 });
    const pid = Number(await readFile(pidFile, "utf8"));
    await outcome;
    // SIGKILL is delivered at once but the process takes a moment to be reaped.
    await vi.waitFor(() => expect(() => process.kill(pid, 0)).toThrow(), { timeout: 5000 });
  }, 20_000);

  it("maps garbage, silence and a crash to unavailable", async () => {
    for (const body of [`process.stdout.write("not json")`, `process.exit(3)`, `process.stdout.write('{"ok":"yes"}')`]) {
      const script = await stub(body);
      await expect(new KeyringStore(nativeBackend({ script, env, timeoutMs: 5000 }), 5000).get(baseUrl, "a")).rejects.toThrow(KeyringUnavailableError);
    }
  });

  it("maps the child's error kinds", async () => {
    const unavailable = await stub(`process.stdout.write(JSON.stringify({ ok: false, kind: "unavailable", message: "no bus" }))`);
    await expect(new KeyringStore(nativeBackend({ script: unavailable, env }), 5000).get(baseUrl, "a")).rejects.toThrow(/no bus/);
    const failed = await stub(`process.stdout.write(JSON.stringify({ ok: false, kind: "failed", message: "locked" }))`);
    await expect(new KeyringStore(nativeBackend({ script: failed, env }), 5000).set(baseUrl, "a", "x")).rejects.toThrow(/system keyring failed a write: locked/);
    const notFound = await stub(`process.stdout.write(JSON.stringify({ ok: false, kind: "not-found", message: "none" }))`);
    expect(await nativeBackend({ script: notFound, env }).get("s", "a")).toBeNull();
  });

  it("reports a child that cannot start", async () => {
    await expect(new KeyringStore(nativeBackend({ script: join(tmp.path, "missing.mjs"), env, timeoutMs: 5000 }), 5000).get(baseUrl, "a")).rejects.toThrow(KeyringUnavailableError);
  });
});

// The real child script, with `@napi-rs/keyring` replaced by a stub module next to a copy of it: what
// the child asks the native module for, without any chance of reaching a real keyring.
describe("keyring-child (stub native module)", () => {
  const tmp = useTempDir("gxy-kn-");
  const childSource = join(__dirname, "../../src/auth/keyring-child.ts");

  /** A copy of the child in a temp dir; `stubModule` is the body of the fake `@napi-rs/keyring`, or undefined for none. */
  async function childWith(stubModule: string | undefined) {
    const script = join(tmp.path, "keyring-child.ts");
    await writeFile(script, await readFile(childSource, "utf8"));
    await writeFile(join(tmp.path, "package.json"), '{"type":"module"}');
    if (stubModule !== undefined) {
      const mod = join(tmp.path, "node_modules", "@napi-rs", "keyring");
      await mkdir(mod, { recursive: true });
      await writeFile(join(mod, "package.json"), '{"name":"@napi-rs/keyring","type":"module","main":"index.js"}');
      await writeFile(join(mod, "index.js"), stubModule);
    }
    return nativeBackend({ script, env: { PATH: process.env.PATH, STUB_LOG: join(tmp.path, "calls.log") }, timeoutMs: 10_000 });
  }
  const recording = `
    import { appendFileSync } from "node:fs";
    export class AsyncEntry {
      constructor(service, account, options) { this.args = { service, account, options }; }
      note(op) { appendFileSync(process.env.STUB_LOG, JSON.stringify({ op, ...this.args }) + "\\n"); }
      async getPassword() { this.note("get"); return null; }
      async setPassword() { this.note("set"); }
      async deletePassword() { this.note("delete"); return true; }
    }`;

  it("pins every entry to the Secret Service, never the kernel keyutils keyring", async () => {
    const b = await childWith(recording);
    await b.get("svc", "acct");
    await b.set("svc", "acct", "FAKE");
    await b.delete("svc", "acct");
    const calls = (await readFile(join(tmp.path, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as { op: string; service: string; account: string; options: unknown });
    expect(calls.map((c) => c.op)).toEqual(["get", "set", "delete"]);
    for (const c of calls) expect(c).toMatchObject({ service: "svc", account: "acct", options: { linux: { store: "secret-service" } } });
  });

  it("reports an unavailable keyring when the entry cannot be constructed", async () => {
    const b = await childWith(`export class AsyncEntry { constructor() { throw new Error("no bus"); } }`);
    await expect(new KeyringStore(b, 10_000).get(baseUrl, "a")).rejects.toThrow(/no bus/);
  });

  it("reports an unavailable keyring when the native module cannot be loaded", async () => {
    const b = await childWith(undefined);
    await expect(new KeyringStore(b, 10_000).get(baseUrl, "a")).rejects.toThrow(/could not be loaded/);
  });
});

// The real child (keyring-child.ts run as source) against a fake session bus that accepts the
// connection and never answers: the case that used to hang the CLI for good.
describe.skipIf(process.platform !== "linux")("real child against a bus that never answers", () => {
  it("returns 'did not answer' within the timeout plus a margin, and the process exits", async (ctx) => {
    const dir = await mkdtemp(join(tmpdir(), "gxy-bus-"));
    const sock = join(dir, "bus.sock");
    const sockets = new Set<Socket>();
    const server = createServer((s) => { sockets.add(s); s.on("data", () => {}); s.on("error", () => {}); });
    try {
      try {
        await new Promise<void>((res, rej) => { server.once("error", rej); server.listen(sock, res); });
      } catch {
        ctx.skip(); // no unix sockets here
      }
      const runner = join(dir, "runner.mjs");
      const store = pathToFileURL(join(__dirname, "../../src/auth/keyring-store.ts")).href;
      await writeFile(runner, `
        import { KeyringStore } from ${JSON.stringify(store)};
        try { await new KeyringStore(undefined, 800).get("gxy:https://galaxy.example.org", "alice"); console.log("ANSWERED"); }
        catch (e) { console.log(e.message); }`);
      const t0 = Date.now();
      const out = await new Promise<{ code: number | null; stdout: string }>((resolve, reject) => {
        const c = spawn(process.execPath, [runner], {
          env: { PATH: process.env.PATH, HOME: dir, DBUS_SESSION_BUS_ADDRESS: `unix:path=${sock}` },
          stdio: ["ignore", "pipe", "inherit"],
        });
        let stdout = "";
        c.stdout.on("data", (d) => (stdout += d));
        const guard = setTimeout(() => { c.kill("SIGKILL"); reject(new Error("the process did not exit")); }, 8000);
        c.on("close", (code) => { clearTimeout(guard); resolve({ code, stdout }); });
      });
      expect(out.stdout).toMatch(/did not answer a read within 800 ms/);
      expect(out.code).toBe(0);
      expect(Date.now() - t0).toBeLessThan(800 + 5000);
    } finally {
      for (const s of sockets) s.destroy();
      server.close();
      await rm(dir, { recursive: true, force: true });
    }
  }, 15000);
});
