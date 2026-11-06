import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fakeLogin } from "./support";

// Count every keyring child process that is spawned, and answer for it from memory: nothing here
// touches a real keyring. The fake speaks the same stdin/stdout protocol as keyring-child.ts.
const state = vi.hoisted(() => ({ spawned: 0, secrets: new Map<string, string>() }));
vi.mock("node:child_process", async () => {
  const { EventEmitter } = await import("node:events");
  const { PassThrough } = await import("node:stream");
  return {
    spawn: () => {
      state.spawned++;
      const child = new EventEmitter() as EventEmitter & { stdin: InstanceType<typeof PassThrough>; stdout: InstanceType<typeof PassThrough>; kill: () => void };
      child.stdin = new PassThrough();
      child.stdout = new PassThrough();
      child.kill = () => {};
      let body = "";
      child.stdin.on("data", (d) => (body += d));
      child.stdin.on("end", () => {
        const r = JSON.parse(body) as { op: string; service: string; account: string; secret?: string };
        const k = `${r.service}|${r.account}`;
        const value = r.op === "get" ? (state.secrets.get(k) ?? null) : r.op === "set" ? (state.secrets.set(k, r.secret!), true) : state.secrets.delete(k);
        child.stdout.end(JSON.stringify({ ok: true, value }));
        setImmediate(() => child.emit("close", 0));
      });
      return child;
    },
  };
});

const { createCredentialStore } = await import("../../src/auth/store");
const { loadSourcesAsync, resolveConnection } = await import("../../src/config");

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "gxy-kr-"));
  state.spawned = 0;
  state.secrets.clear();
});
afterEach(() => rm(root, { recursive: true, force: true }));

describe("C2: the keyring is touched only when needed", () => {
  const env = () => ({ GXY_CONFIG_DIR: join(root, "cfg") });
  it("a file-stored login never spawns a keyring child (list, get, operations, delete)", async () => {
    const store = createCredentialStore(env(), root, () => {});
    const login = fakeLogin();
    expect((await store.put(login, { insecureStorage: true })).storage).toBe("file");
    expect(await store.list()).toHaveLength(1);
    expect((await store.get(login.baseUrl))?.token).toBe(login.token);
    const src = await loadSourcesAsync({}, { store, base: { env: {}, dotenv: {}, profiles: {} } });
    expect(resolveConnection({}, src).apiKey).toBe(login.token);
    expect(await store.delete(login.baseUrl)).toBe(true);
    expect(state.spawned).toBe(0);
  });
  it("login writes and reads back through the keyring, and a keyring record is read with one child", async () => {
    const store = createCredentialStore(env(), root, () => {});
    const login = fakeLogin();
    expect((await store.put(login)).storage).toBe("keyring");
    expect(state.spawned).toBe(2); // the write, then the read-back
    state.spawned = 0;
    expect((await store.get(login.baseUrl))?.token).toBe(login.token);
    expect(state.spawned).toBe(1);
  });
});
