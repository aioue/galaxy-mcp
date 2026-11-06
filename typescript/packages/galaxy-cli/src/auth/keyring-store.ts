import type { BaseUrl } from "./types";

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

  delete(baseUrl: BaseUrl, account: string): Promise<boolean> {
    return this.call("delete", () => this.backend.delete(keyringService(baseUrl), account));
  }

  private async call<T>(what: string, fn: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new KeyringUnavailableError(`The system keyring did not answer a ${what} within ${this.timeoutMs} ms.`)),
        this.timeoutMs,
      );
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

/** The real backend. The native module is imported lazily so a missing binary is just "unavailable". */
export function nativeBackend(): KeyringBackend {
  const entry = async (service: string, account: string) => {
    const { AsyncEntry } = await import("@napi-rs/keyring");
    return new AsyncEntry(service, account, { linux: { store: "secret-service" } });
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
