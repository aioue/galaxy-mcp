import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach } from "vitest";
import { normalizeBaseUrl } from "../../src/auth/base-url";
import { FileStore } from "../../src/auth/file-store";
import { resolveHost } from "../../src/auth/host";
import { KeyringStore, type KeyringBackend } from "../../src/auth/keyring-store";
import { CombinedStore } from "../../src/auth/store";
import {
  AuthError,
  type AuthDeps,
  type AuthServer,
  type BaseUrl,
  type CredentialStore,
  type LoginSummary,
  type PendingDeviceLogin,
  type PutResult,
  type StorageKind,
  type StoredLogin,
  type TokenGrant,
  type WhoAmI,
} from "../../src/auth/types";

export const DAY = "2026-11-06T10:44:00.000Z";
export const HOST: BaseUrl = normalizeBaseUrl("https://dev.galaxy.example.org");
export const OTHER: BaseUrl = normalizeBaseUrl("https://other.example.org");
/** Obviously fake. */
export const FAKE_TOKEN = "fake-token-0123456789abcdef";

export function fakeLogin(over: Partial<StoredLogin> = {}): StoredLogin {
  return {
    baseUrl: HOST,
    username: "aioue",
    token: FAKE_TOKEN,
    method: "device",
    scopes: ["histories:read", "tools:run"],
    expiresAt: "2026-11-06T18:42:00.000Z",
    obtainedAt: DAY,
    ...over,
  };
}

/** What `FakeStore` says when it refuses an admin token for lack of a keyring (the real wording is store.ts's). */
export const REFUSED_WITHOUT_KEYRING = "keyring unavailable, nothing stored";

export class FakeStore implements CredentialStore {
  logins = new Map<string, StoredLogin & { storage: StorageKind }>();
  putCalls: { login: StoredLogin; opts?: { insecureStorage?: boolean; requireKeyring?: boolean } }[] = [];
  nextStorage: StorageKind = "keyring";
  nextWarning: string | undefined;
  /**
   * False makes a `requireKeyring` put refuse, as the real store does with no keyring. The
   * wording of that refusal belongs to store.ts and is tested there, not here.
   */
  keyringAvailable = true;
  /** Set to make `put` throw this instead (a failed write). */
  putError: Error | undefined;

  seed(login: StoredLogin, storage: StorageKind = "keyring"): this {
    this.logins.set(login.baseUrl, { ...login, storage });
    return this;
  }
  async get(baseUrl: BaseUrl) {
    return this.logins.get(baseUrl) ?? null;
  }
  async put(login: StoredLogin, opts?: { insecureStorage?: boolean; requireKeyring?: boolean }): Promise<PutResult> {
    this.putCalls.push({ login, opts });
    if (this.putError) throw this.putError;
    if (opts?.requireKeyring && !opts.insecureStorage && !this.keyringAvailable) {
      throw new AuthError("denied", REFUSED_WITHOUT_KEYRING);
    }
    const storage: StorageKind = opts?.insecureStorage ? "file" : this.nextStorage;
    this.logins.set(login.baseUrl, { ...login, storage });
    return { storage, ...(this.nextWarning ? { warning: this.nextWarning } : {}) };
  }
  async delete(baseUrl: BaseUrl) {
    return this.logins.delete(baseUrl);
  }
  async list(): Promise<LoginSummary[]> {
    return [...this.logins.values()]
      .sort((a, b) => a.baseUrl.localeCompare(b.baseUrl))
      .map(({ token: _t, ...rest }) => rest);
  }
}

/**
 * An in-memory keyring, so no test reaches the real one. `mode` is how it misbehaves:
 * `throw` and `hang` for a backend that is down or wedged, `lossy` for one that accepts a write
 * and serves nothing, `wrong` for one that serves something other than what was written, and
 * `undeletable` for one that reports a delete that did not happen.
 */
export class FakeKeyring implements KeyringBackend {
  data = new Map<string, string>();
  mode: "ok" | "throw" | "hang" | "lossy" | "wrong" | "undeletable" = "ok";
  private gate() {
    if (this.mode === "throw") return Promise.reject(new Error("no secret service"));
    if (this.mode === "hang") return new Promise<never>(() => {});
    return undefined;
  }
  async get(service: string, account: string) {
    await this.gate();
    const v = this.data.get(`${service}|${account}`) ?? null;
    return this.mode === "wrong" && v !== null ? "something-else" : v;
  }
  async set(service: string, account: string, secret: string) {
    await this.gate();
    if (this.mode !== "lossy") this.data.set(`${service}|${account}`, secret);
  }
  async delete(service: string, account: string) {
    await this.gate();
    if (this.mode === "undeletable") return true;
    return this.data.delete(`${service}|${account}`);
  }
}

/** A temp directory per test, removed afterwards. Call it at the top of a file or a `describe`. */
export function useTempDir(prefix = "gxy-test-"): { readonly path: string } {
  let dir = "";
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), prefix));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return {
    get path() {
      return dir;
    },
  };
}

/** The real `CombinedStore` over a real `hosts.yml` under `root` and the given fake keyring. */
export function realStore(root: string, keyring: FakeKeyring, keyringTimeoutMs = 50): { store: CombinedStore; file: FileStore } {
  const file = new FileStore(join(root, "cfg"));
  return { file, store: new CombinedStore(file, new KeyringStore(keyring, keyringTimeoutMs)) };
}

export class FakePending implements PendingDeviceLogin {
  userCode = "WDJB-MJHT";
  verificationUri = "https://dev.galaxy.example.org/login/device";
  expiresAt: Date;
  outcome: TokenGrant | AuthError | "hang" = { accessToken: FAKE_TOKEN, expiresIn: 28_680, scopes: ["histories:read"] };
  constructor(now: Date) {
    this.expiresAt = new Date(now.getTime() + (14 * 60 + 52) * 1000);
  }
  async waitForApproval(signal?: AbortSignal): Promise<TokenGrant> {
    if (this.outcome === "hang") {
      return new Promise((_, reject) => {
        signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        if (signal?.aborted) reject(new Error("aborted"));
      });
    }
    if (this.outcome instanceof AuthError) throw this.outcome;
    return this.outcome;
  }
}

export class FakeServer implements AuthServer {
  issuer: string;
  supportsDeviceFlow = true;
  supportsRevocation = true;
  startedWith: (string[] | undefined)[] = [];
  revoked: string[] = [];
  revokeError: Error | undefined;
  pending: FakePending;
  constructor(baseUrl: string, now: Date) {
    this.issuer = baseUrl;
    this.pending = new FakePending(now);
  }
  async startDeviceLogin(scopes?: string[]) {
    this.startedWith.push(scopes);
    return this.pending;
  }
  async revoke(token: string) {
    if (this.revokeError) throw this.revokeError;
    this.revoked.push(token);
  }
}

export class Capture {
  out = "";
  err = "";
  stdout = { write: (s: string) => void (this.out += s) };
  stderr = { write: (s: string) => void (this.err += s) };
}

export interface Harness {
  deps: AuthDeps;
  store: FakeStore;
  server: FakeServer;
  cap: Capture;
  stdin: PassThrough;
  opened: string[];
  whoamiCalls: { baseUrl: string; token: string }[];
  /** Mutable knobs. */
  knobs: { whoami: WhoAmI | AuthError; browserAvailable: boolean; discoverError?: AuthError };
}

/** A set of in-memory fakes behind `AuthDeps`. `stdinText` is written and ended at once. */
export function harness(
  opts: { interactive?: boolean; env?: Record<string, string>; stdinText?: string; stored?: StoredLogin[]; hostFromEnv?: string; ignoredLoginHost?: { source: "dotenv" | "profile"; url: string } } = {},
): Harness {
  const store = new FakeStore();
  for (const l of opts.stored ?? []) store.seed(l);
  const now = () => new Date(DAY);
  const cap = new Capture();
  const stdin = new PassThrough();
  if (opts.stdinText !== undefined) {
    stdin.end(opts.stdinText);
  }
  const server = new FakeServer(HOST, now());
  const opened: string[] = [];
  const whoamiCalls: { baseUrl: string; token: string }[] = [];
  const knobs: Harness["knobs"] = { whoami: { username: "aioue", email: "a@example.org" }, browserAvailable: true };
  const env = { ...(opts.hostFromEnv ? { GALAXY_URL: opts.hostFromEnv } : {}), ...opts.env };
  const deps: AuthDeps = {
    store,
    async discover() {
      if (knobs.discoverError) throw knobs.discoverError;
      return server;
    },
    async whoami(baseUrl, token) {
      whoamiCalls.push({ baseUrl, token });
      if (knobs.whoami instanceof AuthError) throw knobs.whoami;
      return knobs.whoami;
    },
    // The real rule, over the fake store; `.env` and profiles are not in play here.
    resolveHost: (explicit, purpose) => resolveHost({ explicit, env, dotenv: {}, store, forLogin: purpose === "login", commandName: "gxy" }),
    ignoredLoginHost: () => opts.ignoredLoginHost,
    async openBrowser(url) {
      opened.push(url);
      return true;
    },
    canOpenBrowser: () => knobs.browserAvailable,
    now,
    env,
    io: { stdin, stdout: cap.stdout, stderr: cap.stderr, interactive: opts.interactive ?? false },
    commandName: "gxy",
  };
  return { deps, store, server, cap, stdin, opened, whoamiCalls, knobs };
}

/**
 * Make `get` fail for the given hosts, as a keyring that is down (`throw`) or has lost the secret
 * (`null`) does, while the record is still listed.
 */
export function makeTokenUnreadable(h: Harness, hosts: string[], how: "throw" | "null" = "throw"): void {
  const get = h.store.get.bind(h.store);
  h.store.get = async (b) => {
    if (!hosts.includes(b)) return get(b);
    if (how === "null") return null;
    throw new AuthError("not_logged_in", "The token for it is in the system keyring, which is not available: no secret service");
  };
}

/** The `AuthError` a promise rejects with (the test fails if it resolves or rejects with anything else). */
export async function authErrorOf(p: Promise<unknown>): Promise<AuthError> {
  const e = await p.then(
    () => undefined,
    (x: unknown) => x,
  );
  if (!(e instanceof AuthError)) throw new Error(`expected an AuthError, got ${e === undefined ? "a resolved promise" : String(e)}`);
  return e;
}
