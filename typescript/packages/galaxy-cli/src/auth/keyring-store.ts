import type { AsyncEntry } from "@napi-rs/keyring";
import type { BaseUrl } from "./types";
import { trackWedged } from "./wedge";

/**
 * The OS keyring, behind a seam tests can fake. The real backend is `@napi-rs/keyring`
 * pinned to the Secret Service (gnome-keyring, KWallet, ...) and never the kernel keyutils
 * keyring.
 *
 * Why pinned: left to itself the binding tries Secret Service, then silently falls back to
 * keyutils. Observed in this devcontainer (Linux, no D-Bus session): the default `Entry`
 * constructor throws `PermissionDenied` (the container blocks the keyctl syscalls), while
 * `{ linux: { store: "secret-service" } }` throws a D-Bus error and `"keyutils"` the same
 * `PermissionDenied`. On a host where keyutils does work, the binding's own README says it
 * is in-memory only; it lives in the kernel session/user keyring and is gone at reboot (and,
 * for a session keyring, when the login session ends). A store that appears to work but
 * loses tokens between shells is worse than the plaintext file fallback, so we refuse it:
 * when there is no Secret Service, the keyring is "unavailable" and `store.ts` uses the file.
 *
 * Availability is detected by use, not by a separate probe: `store.ts` writes the token and
 * reads it back, and falls back to the file if either fails. Every call has a timeout,
 * because a locked or wedged Secret Service can wait forever on a prompt nobody sees.
 */
export interface KeyringBackend {
  get(service: string, account: string): Promise<string | null>;
  set(service: string, account: string, secret: string): Promise<void>;
  /** Resolves false when there was nothing to delete. */
  delete(service: string, account: string): Promise<boolean>;
}

export const KEYRING_TIMEOUT_MS = 5000;

export class KeyringUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "KeyringUnavailableError";
  }
}

/** A keyring that is never there, for `GXY_NO_KEYRING=1`: tokens go to the file, as on a headless box. */
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

export function keyringService(baseUrl: BaseUrl): string {
  return `gxy:${baseUrl}`;
}

export class KeyringStore {
  constructor(
    private readonly backend: KeyringBackend = nativeBackend(),
    private readonly timeoutMs: number = KEYRING_TIMEOUT_MS,
  ) {}

  get(baseUrl: BaseUrl, account: string): Promise<string | null> {
    return this.call("read", () => this.backend.get(keyringService(baseUrl), account));
  }

  set(baseUrl: BaseUrl, account: string, secret: string): Promise<void> {
    return this.call("write", () => this.backend.set(keyringService(baseUrl), account, secret));
  }

  /**
   * Delete, then read back and require nothing there. Some backends report success for a
   * delete that did not happen (a locked collection, a different item matched), and a token
   * that quietly stays in the keyring after `logout` is the worst outcome, so "deleted" has
   * to be observed, not assumed.
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

  private async call<T>(what: string, fn: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new KeyringUnavailableError(`The system keyring did not answer a ${what} within ${this.timeoutMs} ms.`));
      }, this.timeoutMs);
    });
    try {
      const work = fn();
      // Give up waiting, not working: the native call cannot be cancelled and keeps the process
      // alive until it returns (see wedge.ts), so note it for as long as it is outstanding.
      void timeout.catch(() => {
        trackWedged(work);
      });
      return await Promise.race([work, timeout]);
    } catch (e) {
      if (e instanceof KeyringUnavailableError) throw e;
      throw new KeyringUnavailableError(`The system keyring failed a ${what}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    } finally {
      clearTimeout(timer);
    }
  }
}

/** The real backend. The native module is imported lazily so a missing binary is just "unavailable".
 * It is only reached when a record says `keyring` or login probes it: file-stored logins never load it. */
export function nativeBackend(): KeyringBackend {
  // One entry per login, built on first use: the constructor talks to the bus, and a write,
  // its read-back and a delete would otherwise each pay for it.
  const entries = new Map<string, Promise<AsyncEntry>>();
  const entry = (service: string, account: string) => {
    const key = `${service}\0${account}`;
    let e = entries.get(key);
    if (!e) {
      e = import("@napi-rs/keyring").then(({ AsyncEntry }) => new AsyncEntry(service, account, { linux: { store: "secret-service" } }));
      entries.set(key, e);
    }
    return e;
  };
  return {
    async get(service, account) {
      return (await entry(service, account)).getPassword();
    },
    async set(service, account, secret) {
      await (await entry(service, account)).setPassword(secret);
    },
    async delete(service, account) {
      return (await entry(service, account)).deletePassword();
    },
  };
}
