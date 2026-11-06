import { PassThrough } from "node:stream";
import { normalizeBaseUrl } from "../../src/auth/base-url";
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

export class FakeStore implements CredentialStore {
  logins = new Map<string, StoredLogin & { storage: StorageKind }>();
  putCalls: { login: StoredLogin; opts?: { insecureStorage?: boolean } }[] = [];
  nextStorage: StorageKind = "keyring";
  nextWarning: string | undefined;
  order: string[] = [];

  seed(login: StoredLogin, storage: StorageKind = "keyring"): this {
    this.logins.set(login.baseUrl, { ...login, storage });
    return this;
  }
  async get(baseUrl: BaseUrl) {
    return this.logins.get(baseUrl) ?? null;
  }
  async put(login: StoredLogin, opts?: { insecureStorage?: boolean }): Promise<PutResult> {
    this.putCalls.push({ login, opts });
    this.order.push("put");
    const storage: StorageKind = opts?.insecureStorage ? "file" : this.nextStorage;
    this.logins.set(login.baseUrl, { ...login, storage });
    return { storage, ...(this.nextWarning ? { warning: this.nextWarning } : {}) };
  }
  async delete(baseUrl: BaseUrl) {
    this.order.push("delete");
    return this.logins.delete(baseUrl);
  }
  async list(): Promise<LoginSummary[]> {
    return [...this.logins.values()]
      .sort((a, b) => a.baseUrl.localeCompare(b.baseUrl))
      .map(({ token: _t, ...rest }) => rest);
  }
}

export class FakePending implements PendingDeviceLogin {
  userCode = "WDJB-MJHT";
  verificationUri = "https://dev.galaxy.example.org/login/device";
  expiresAt: Date;
  /** The device code must never appear in output; tests grep for it. */
  readonly deviceCode = "SECRET-DEVICE-CODE-9999";
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

export class Clock {
  constructor(public t = new Date(DAY)) {}
  now = () => new Date(this.t);
  advance(ms: number) {
    this.t = new Date(this.t.getTime() + ms);
  }
}

export interface Harness {
  deps: AuthDeps;
  store: FakeStore;
  server: FakeServer;
  cap: Capture;
  clock: Clock;
  stdin: PassThrough;
  opened: string[];
  whoamiCalls: { baseUrl: string; token: string }[];
  /** Mutable knobs. */
  knobs: { whoami: WhoAmI | AuthError; browserOpens: boolean; browserAvailable: boolean; discoverError?: AuthError };
}

/** A set of in-memory fakes behind `AuthDeps`. `stdinText` is written and ended at once. */
export function harness(
  opts: { interactive?: boolean; env?: Record<string, string>; stdinText?: string; stored?: StoredLogin[]; hostFromEnv?: string } = {},
): Harness {
  const store = new FakeStore();
  for (const l of opts.stored ?? []) store.seed(l);
  const clock = new Clock();
  const cap = new Capture();
  const stdin = new PassThrough();
  if (opts.stdinText !== undefined) {
    stdin.end(opts.stdinText);
  }
  const server = new FakeServer(HOST, clock.now());
  const opened: string[] = [];
  const whoamiCalls: { baseUrl: string; token: string }[] = [];
  const knobs: Harness["knobs"] = { whoami: { username: "aioue", email: "a@example.org" }, browserOpens: true, browserAvailable: true };
  const env = opts.env ?? {};
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
    async resolveHost(explicit) {
      if (explicit) return normalizeBaseUrl(explicit);
      if (opts.hostFromEnv) return normalizeBaseUrl(opts.hostFromEnv);
      const all = await store.list();
      if (all.length === 1) return all[0]!.baseUrl;
      if (all.length > 1) throw new AuthError("ambiguous_host", `Several logins: ${all.map((l) => l.baseUrl).join(", ")}. Pass --host.`);
      throw new AuthError("usage", "No Galaxy named. Pass --host <url>.");
    },
    async openBrowser(url) {
      opened.push(url);
      return knobs.browserOpens;
    },
    canOpenBrowser: () => knobs.browserAvailable,
    now: clock.now,
    env,
    io: { stdin, stdout: cap.stdout, stderr: cap.stderr, interactive: opts.interactive ?? false },
    commandName: "gxy",
  };
  return { deps, store, server, cap, clock, stdin, opened, whoamiCalls, knobs };
}
