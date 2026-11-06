import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { childEnv, KeyringStore, KeyringUnavailableError, nativeBackend } from "../../src/auth/keyring-store";
import { FakeKeyring, fakeLogin } from "./support";

const { baseUrl } = fakeLogin();

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
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "gxy-kc-")); });
  afterEach(() => rm(dir, { recursive: true, force: true }));
  const stub = async (body: string) => {
    const p = join(dir, "stub.mjs");
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
    const log = join(dir, "log.json");
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
    const pidFile = join(dir, "pid");
    const script = await stub(`
      import { writeFileSync } from "node:fs";
      writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
      setInterval(() => {}, 1000);`);
    const t0 = Date.now();
    await expect(new KeyringStore(nativeBackend({ script, env, timeoutMs: 300 }), 300).get(baseUrl, "alice")).rejects.toThrow(/did not answer/);
    expect(Date.now() - t0).toBeLessThan(2000);
    const pid = Number(await readFile(pidFile, "utf8"));
    await new Promise((r) => setTimeout(r, 100));
    expect(() => process.kill(pid, 0)).toThrow(); // gone
  });

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
    await expect(new KeyringStore(nativeBackend({ script: join(dir, "missing.mjs"), env, timeoutMs: 5000 }), 5000).get(baseUrl, "a")).rejects.toThrow(KeyringUnavailableError);
  });
});

// The real child (keyring-child.ts run as source) against a fake session bus that accepts the
// connection and never answers: the case that used to hang the CLI for good.
describe.skipIf(process.platform !== "linux")("real child against a bus that never answers", () => {
  it("returns 'did not answer' within the timeout plus a margin, and the process exits", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gxy-bus-"));
    const sock = join(dir, "bus.sock");
    const sockets = new Set<Socket>();
    const server = createServer((s) => { sockets.add(s); s.on("data", () => {}); s.on("error", () => {}); });
    try {
      try {
        await new Promise<void>((res, rej) => { server.once("error", rej); server.listen(sock, res); });
      } catch {
        return; // no unix sockets here
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
          env: { PATH: process.env.PATH, HOME: process.env.HOME, DBUS_SESSION_BUS_ADDRESS: `unix:path=${sock}` },
          stdio: ["ignore", "pipe", "inherit"],
        });
        let stdout = "";
        c.stdout.on("data", (d) => (stdout += d));
        const guard = setTimeout(() => { c.kill("SIGKILL"); reject(new Error("the process did not exit")); }, 8000);
        c.on("close", (code) => { clearTimeout(guard); resolve({ code, stdout }); });
      });
      expect(out.stdout).toMatch(/did not answer a read within 800 ms/);
      expect(out.code).toBe(0);
      expect(Date.now() - t0).toBeLessThan(800 + 3000);
    } finally {
      for (const s of sockets) s.destroy();
      server.close();
      await rm(dir, { recursive: true, force: true });
    }
  }, 15000);
});
