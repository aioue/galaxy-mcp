import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fakeLogin } from "./support";

// Count every native keyring entry that is constructed. Nothing here touches a real keyring.
const state = vi.hoisted(() => ({ constructed: 0, secrets: new Map<string, string>() }));
vi.mock("@napi-rs/keyring", () => ({
  AsyncEntry: class {
    constructor(private service: string, private account: string) {
      state.constructed++;
    }
    async getPassword() {
      return state.secrets.get(`${this.service}|${this.account}`) ?? null;
    }
    async setPassword(s: string) {
      state.secrets.set(`${this.service}|${this.account}`, s);
    }
    async deletePassword() {
      return state.secrets.delete(`${this.service}|${this.account}`);
    }
  },
}));

const { createCredentialStore } = await import("../../src/auth/store");
const { loadSourcesAsync, resolveConnection } = await import("../../src/config");

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "gxy-kr-"));
  state.constructed = 0;
  state.secrets.clear();
});
afterEach(() => rm(root, { recursive: true, force: true }));

describe("C2: the keyring is touched only when needed", () => {
  const env = () => ({ GXY_CONFIG_DIR: join(root, "cfg") });
  it("a file-stored login never constructs a keyring entry (list, get, operations, delete)", async () => {
    const store = createCredentialStore(env(), root, () => {});
    const login = fakeLogin();
    expect((await store.put(login, { insecureStorage: true })).storage).toBe("file");
    expect(await store.list()).toHaveLength(1);
    expect((await store.get(login.baseUrl))?.token).toBe(login.token);
    const src = await loadSourcesAsync({}, { store, base: { env: {}, dotenv: {}, profiles: {} } });
    expect(resolveConnection({}, src).apiKey).toBe(login.token);
    expect(await store.delete(login.baseUrl)).toBe(true);
    expect(state.constructed).toBe(0);
  });
  it("login probes the keyring once, and a keyring record is read through one entry", async () => {
    const store = createCredentialStore(env(), root, () => {});
    const login = fakeLogin();
    expect((await store.put(login)).storage).toBe("keyring");
    expect(state.constructed).toBe(1);
    expect((await store.get(login.baseUrl))?.token).toBe(login.token);
    expect(state.constructed).toBe(1);
  });
});
