// `createCredentialStore`, the one factory, with the keyring child process replaced by an
// in-memory fake that speaks keyring-child.ts's stdin/stdout protocol. This is what stops any test
// here reaching a real keyring, and it counts spawns so "never touched" can be asserted.
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ spawned: 0, secrets: new Map<string, string>() }));
vi.mock("node:child_process", async () => {
  const { EventEmitter } = await import("node:events");
  const { PassThrough } = await import("node:stream");
  return {
    spawn: () => {
      state.spawned++;
      const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), kill: () => {} });
      let body = "";
      child.stdin.on("data", (d: Buffer) => (body += d));
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
const { DAY, FAKE_TOKEN, HOST, fakeLogin, useTempDir } = await import("./harness");

const tmp = useTempDir("gxy-nk-");
beforeEach(() => {
  state.spawned = 0;
  state.secrets.clear();
});
const env = (extra: Record<string, string> = {}) => ({ GXY_CONFIG_DIR: `${tmp.path}/cfg`, ...extra });

describe("GXY_NO_KEYRING", () => {
  it.each(["1", "yes", "true"])("=%s keeps tokens in the file, with a warning, and never starts the keyring", async (v) => {
    const s = createCredentialStore(env({ GXY_NO_KEYRING: v }), tmp.path, () => {});
    const res = await s.put(fakeLogin());
    expect(res.storage).toBe("file");
    expect(res.warning).toMatch(/No system keyring/);
    expect((await s.get(HOST))?.token).toBe(FAKE_TOKEN);
    expect(state.spawned).toBe(0);
  });

  it.each(["", "0", "false", "False"])("=%j leaves the keyring on", async (v) => {
    const s = createCredentialStore(env({ GXY_NO_KEYRING: v }), tmp.path, () => {});
    expect((await s.put(fakeLogin())).storage).toBe("keyring");
    expect(state.spawned).toBeGreaterThan(0);
    expect(state.secrets.size).toBe(1);
  });

  it("unset leaves the keyring on", async () => {
    expect((await createCredentialStore(env(), tmp.path, () => {}).put(fakeLogin())).storage).toBe("keyring");
  });
});

describe("the native keyring is touched only when a record needs it", () => {
  it("a file-stored login never starts a keyring child (put, list, get, an operation's lookup, delete)", async () => {
    const store = createCredentialStore(env(), tmp.path, () => {});
    const login = fakeLogin();
    expect((await store.put(login, { insecureStorage: true })).storage).toBe("file");
    expect(await store.list()).toHaveLength(1);
    expect((await store.get(login.baseUrl))?.token).toBe(login.token);
    const src = await loadSourcesAsync({}, { store, now: new Date(DAY), base: { env: {}, dotenv: {}, profiles: {} } });
    expect(resolveConnection({}, src).apiKey).toBe(login.token);
    expect(await store.delete(login.baseUrl)).toBe(true);
    expect(state.spawned).toBe(0);
  });

  it("a keyring login round-trips through the native backend", async () => {
    const store = createCredentialStore(env(), tmp.path, () => {});
    expect((await store.put(fakeLogin())).storage).toBe("keyring");
    expect((await store.get(HOST))?.token).toBe(FAKE_TOKEN);
    expect(await store.delete(HOST)).toBe(true);
    expect(state.secrets.size).toBe(0);
  });
});
