import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { BaseUrl } from "./types";

/**
 * The OS keyring, behind a seam tests can fake. The real backend is `@napi-rs/keyring`
 * pinned to the Secret Service (gnome-keyring, KWallet, ...) and never the kernel keyutils
 * keyring.
 *
 * Why pinned: left to itself the binding tries Secret Service, then silently falls back to
 * keyutils on any error (keyring-node#142). Observed on Linux in a container with no D-Bus
 * session: the default `Entry` constructor throws `PermissionDenied` (the container blocks the
 * keyctl syscalls), while `{ linux: { store: "secret-service" } }` throws a D-Bus error and
 * `"keyutils"` the same `PermissionDenied`. On a host where keyutils does work, the binding's
 * own README says it is in-memory only; it lives in the kernel session/user keyring and is gone
 * at reboot (and, for a session keyring, when the login session ends). A store that appears to
 * work but loses tokens between shells is worse than the plaintext file fallback, so we refuse
 * it: when there is no Secret Service, the keyring is "unavailable" and `store.ts` uses the file.
 *
 * Availability is detected by use, not by a separate probe: `store.ts` writes the token and
 * reads it back, and falls back to the file if either fails. A probe would only say the keyring
 * worked a moment ago. Every call has a timeout, because a locked or wedged Secret Service can
 * wait forever on a prompt nobody sees.
 *
 * The native module runs in a child process per call (`keyring-child.ts`) that is SIGKILLed on
 * the timeout: its constructor can block forever on a dead D-Bus, which nothing in-process can
 * interrupt. So a broken bus costs at most the timeout, and never keeps the CLI alive.
 */
export interface KeyringBackend {
  get(service: string, account: string): Promise<string | null>;
  set(service: string, account: string, secret: string): Promise<void>;
  /** Resolves false when there was nothing to delete. */
  delete(service: string, account: string): Promise<boolean>;
}

/**
 * How long one keyring call may take before it is given up on. A child starts and loads the
 * module in about 20 ms, so this is only ever spent on a keyring that is wedged or waiting on a
 * prompt, and it is the most a broken one can cost a login or logout. gh allows 60 s.
 */
export const KEYRING_TIMEOUT_MS = 5000;

/**
 * Any reason the keyring could not be used for a call: no Secret Service, a call that went
 * wrong, a timeout, a delete that did not take. `store.ts` treats all of them as "no usable
 * keyring" and falls back to the file (or, for an admin token, refuses), never as a crash.
 */
export class KeyringUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "KeyringUnavailableError";
  }
}

/**
 * A keyring that is never there, for `GXY_NO_KEYRING=1`: tokens go to the file, as on a headless
 * box. The test suite sets it so that no test can reach the real keyring of whoever runs it.
 */
export const noKeyringBackend: KeyringBackend = {
  async get() {
    throw new KeyringUnavailableError("disabled by GXY_NO_KEYRING");
  },
  async set() {
    throw new KeyringUnavailableError("disabled by GXY_NO_KEYRING");
  },
  async delete() {
    throw new KeyringUnavailableError("disabled by GXY_NO_KEYRING");
  },
};

/**
 * `gxy:<baseUrl>`, with the username as the account: one entry per login, the layout gh uses
 * (`gh:<hostname>`). The whole normalised URL rather than the host, so two path prefixes on one
 * host are two entries, as they are two keys in `hosts.yml`.
 */
export function keyringService(baseUrl: BaseUrl): string {
  return `gxy:${baseUrl}`;
}

export class KeyringStore {
  private readonly backend: KeyringBackend;
  private readonly timeoutMs: number;

  // No parameter properties: the integration test runs this file as source under Node's type
  // stripping, which does not support them.
  constructor(backend?: KeyringBackend, timeoutMs: number = KEYRING_TIMEOUT_MS) {
    this.timeoutMs = timeoutMs;
    this.backend = backend ?? nativeBackend({ timeoutMs });
  }

  get(baseUrl: BaseUrl, account: string): Promise<string | null> {
    return this.call("read", () => this.backend.get(keyringService(baseUrl), account));
  }

  set(baseUrl: BaseUrl, account: string, secret: string): Promise<void> {
    return this.call("write", () => this.backend.set(keyringService(baseUrl), account, secret));
  }

  /**
   * Delete, then read back and require nothing there. Some backends report success for a
   * delete that did not happen (a locked collection, a different item matched); the binding
   * itself once folded native errors into `false`, which reads as "nothing to delete"
   * (keyring-node#137). A token that quietly stays in the keyring after `logout` is the worst
   * outcome, so "deleted" has to be observed, not assumed.
   */
  async delete(baseUrl: BaseUrl, account: string): Promise<boolean> {
    const service = keyringService(baseUrl);
    const existed = await this.call("delete", () => this.backend.delete(service, account));
    const remaining = await this.call("check after delete", () => this.backend.get(service, account));
    if (remaining !== null) {
      throw new KeyringUnavailableError("The system keyring still holds the secret after a delete, so it may remain there.");
    }
    return existed;
  }

  /**
   * Race the backend against a timer, so that no backend can hang a caller. The native backend
   * also kills its child at the same deadline; this covers any other, including a fake.
   */
  private async call<T>(what: string, fn: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new KeyringUnavailableError(`The system keyring did not answer a ${what} within ${this.timeoutMs} ms.`));
      }, this.timeoutMs);
    });
    try {
      return await Promise.race([fn(), timeout]);
    } catch (e) {
      if (e instanceof KeyringUnavailableError) throw e;
      throw new KeyringUnavailableError(`The system keyring failed a ${what}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface NativeBackendOptions {
  /** Kill the child and give up after this long. */
  timeoutMs?: number;
  /** The child script; found next to this module by default. Tests point it at a stub. */
  script?: string;
  /** Environment for the child; a minimal one built from `process.env` by default. */
  env?: NodeJS.ProcessEnv;
}

/** The child lives beside this module: `dist/keyring-child.js` once built, `keyring-child.ts` from source. */
function childScript(): string {
  const here = import.meta.url;
  for (const name of ["keyring-child.js", "keyring-child.ts"]) {
    const p = fileURLToPath(new URL(name, here));
    if (existsSync(p)) return p;
  }
  return fileURLToPath(new URL("keyring-child.js", here));
}

/**
 * What the child needs to reach the session bus and the OS, and nothing else: no API keys or
 * tokens, so a `GALAXY_API_KEY` in the CLI's environment never reaches a process that has no
 * use for it.
 */
const CHILD_ENV_KEYS = [
  "HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL",
  "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_DATA_DIRS", "XDG_CURRENT_DESKTOP", "XDG_SESSION_ID",
  "DISPLAY", "WAYLAND_DISPLAY",
  // Windows locates the credential store through these.
  "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SystemRoot", "SYSTEMROOT",
];

export function childEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const k of CHILD_ENV_KEYS) if (source[k] !== undefined) out[k] = source[k];
  return out;
}

type ChildReply =
  | { ok: true; value: string | boolean | null }
  | { ok: false; kind: "unavailable" | "not-found" | "failed"; message: string };

/**
 * The real backend: one child process per call, running the native keyring module. Only reached
 * when a record says `keyring` or login probes it, so file-stored logins never spawn it.
 * Starting the child and loading the module costs about 20 ms a call; a call that outlives the
 * timeout is SIGKILLed.
 */
export function nativeBackend(opts: NativeBackendOptions = {}): KeyringBackend {
  const timeoutMs = opts.timeoutMs ?? KEYRING_TIMEOUT_MS;
  const call = (op: "get" | "set" | "delete", service: string, account: string, secret?: string) =>
    new Promise<ChildReply>((resolve, reject) => {
      // Not shell, not argv: argv is readable by every user in `ps` and `/proc`, so the secret
      // goes down stdin only.
      const child = spawn(process.execPath, [opts.script ?? childScript()], {
        env: opts.env ?? childEnv(),
        stdio: ["pipe", "pipe", "ignore"],
        windowsHide: true,
      });
      let out = "";
      // Settle once: the kill on timeout also makes `close` fire, and must not turn that
      // timeout into "no usable answer".
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn();
      };
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(() => reject(new KeyringUnavailableError(`The system keyring did not answer a ${op} within ${timeoutMs} ms.`)));
      }, timeoutMs);
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (d: string) => {
        out += d;
      });
      child.on("error", (e) => finish(() => reject(new KeyringUnavailableError(`The keyring helper could not start: ${e.message}`, { cause: e }))));
      // Garbage, silence and a crash all end up here, and all mean "unavailable".
      child.on("close", () =>
        finish(() => {
          try {
            const r = JSON.parse(out) as ChildReply;
            if (typeof r?.ok !== "boolean") throw new Error("shape");
            resolve(r);
          } catch {
            reject(new KeyringUnavailableError(`The keyring helper gave no usable answer to a ${op}.`));
          }
        }),
      );
      // The child may die before reading; its exit is reported by close, so ignore EPIPE here.
      child.stdin.on("error", () => {});
      child.stdin.end(JSON.stringify({ op, service, account, ...(secret === undefined ? {} : { secret }) }));
    });
  const value = async (op: "get" | "set" | "delete", service: string, account: string, secret?: string) => {
    const r = await call(op, service, account, secret);
    if (r.ok) return r.value;
    if (r.kind === "not-found") return null;
    if (r.kind === "unavailable") throw new KeyringUnavailableError(r.message);
    throw new Error(r.message);
  };
  return {
    async get(service, account) {
      const v = await value("get", service, account);
      return typeof v === "string" ? v : null;
    },
    async set(service, account, secret) {
      await value("set", service, account, secret);
    },
    async delete(service, account) {
      return (await value("delete", service, account)) === true;
    },
  };
}
