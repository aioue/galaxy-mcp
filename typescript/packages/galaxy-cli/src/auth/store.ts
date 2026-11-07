import { homedir } from "node:os";
import { FileStore, type HostRecord } from "./file-store";
import { KeyringStore, noKeyringBackend } from "./keyring-store";
import { configDir } from "./paths";
import { AuthError, type BaseUrl, type CredentialStore, type LoginSummary, type PutResult, type StoredLogin, type StorageKind } from "./types";

/**
 * Metadata always lives in `hosts.yml`; the token lives in the system keyring when that
 * works, else in `hosts.yml` too (with a warning). The metadata's `storage` field says
 * which, so `get` never has to guess, and a login kept in the file never touches the keyring.
 * It is the split gh makes, with the same plaintext fallback and an `--insecure-storage` of
 * the same name. What is added here: a keyring write must read back, and an admin token never
 * falls back to the file on its own.
 */
export class CombinedStore implements CredentialStore {
  constructor(
    private readonly file: FileStore,
    private readonly keyring: KeyringStore,
  ) {}

  async get(baseUrl: BaseUrl): Promise<(StoredLogin & { storage: StorageKind }) | null> {
    const rec = await this.file.get(baseUrl);
    if (!rec) return null;
    const { token: fileToken, ...summary } = rec;
    if (rec.storage === "file") return { ...summary, token: fileToken ?? "" };
    let token: string | null;
    try {
      token = await this.keyring.get(baseUrl, rec.username);
    } catch (e) {
      // `not_logged_in` (exit 77): the record exists but its token cannot be reached, which for
      // whoever is asking comes to the same thing as having no login.
      throw new AuthError("not_logged_in", `The token for ${baseUrl} is in the system keyring, which is not available: ${(e as Error).message}`, { cause: e });
    }
    // The record says the token is in the keyring and it is not there: that is a login we
    // cannot use, not "no login", and callers must not read it as a clean slate.
    if (token === null) {
      throw new AuthError(
        "not_logged_in",
        `The login record for ${baseUrl} says its token is in the system keyring, but the keyring has none. Log in again to replace it.`,
      );
    }
    return { ...summary, token };
  }

  async put(login: StoredLogin, opts: { insecureStorage?: boolean; requireKeyring?: boolean } = {}): Promise<PutResult> {
    const { token, ...summary } = login;
    // Read first: what the old record points at decides what must be cleaned up afterwards.
    const prior = await this.file.get(login.baseUrl);
    let storage: StorageKind = "file";
    let warning: string | undefined;
    if (!opts.insecureStorage) {
      try {
        await this.keyring.set(login.baseUrl, login.username, token);
        // Read it back: a backend that accepts writes it cannot serve is no keyring at all.
        if ((await this.keyring.get(login.baseUrl, login.username)) !== token) {
          throw new Error("the token did not read back");
        }
        storage = "keyring";
      } catch (e) {
        // The write may have landed even though it did not read back (or the read threw). Take
        // it out, best effort, so no copy of the token lives outside the record that is about
        // to say "file", unless an existing record points at that very entry.
        if (!(prior?.storage === "keyring" && prior.username === login.username)) {
          await this.keyring.delete(login.baseUrl, login.username).catch(() => {});
        }
        if (opts.requireKeyring) {
          // Nothing has been written to the file yet (it is only touched below), so refusing is clean.
          // `denied` is exit 77 (EX_NOPERM): the store declined by policy, nothing else broke. An
          // admin token is the one credential never left in plaintext as a side effect.
          throw new AuthError(
            "denied",
            `No system keyring here, so nothing was stored. Rerun with --insecure-storage to keep it in ${this.file.path} (readable only by you), or use GALAXY_API_KEY for this session.`,
            { cause: e },
          );
        }
        // Said aloud, never silent: a fallback nobody hears about is a plaintext token that the
        // user believes is in the keyring.
        warning = `No system keyring available; token saved in plain text at ${this.file.path} (readable only by you)`;
      }
    }
    const record: HostRecord = storage === "file" ? { ...summary, storage, token } : { ...summary, storage };
    // Metadata (and so the plaintext token, if any, being dropped) is replaced in one atomic write.
    try {
      await this.file.put(record);
    } catch (e) {
      // The secret is in the keyring but no record points at it: take it back out, best effort,
      // unless it overwrote the entry an existing record still points at.
      if (storage === "keyring" && !(prior?.storage === "keyring" && prior.username === login.username)) {
        await this.keyring.delete(login.baseUrl, login.username).catch(() => {});
      }
      throw e;
    }
    // Clean up what the new record no longer points at.
    if (prior?.storage === "keyring" && (storage === "file" || prior.username !== login.username)) {
      await this.keyring.delete(login.baseUrl, prior.username).catch(() => {});
    }
    return warning ? { storage, warning } : { storage };
  }

  async delete(baseUrl: BaseUrl): Promise<boolean> {
    const rec = await this.file.get(baseUrl);
    if (!rec) return false;
    let leftover: unknown;
    if (rec.storage === "keyring") {
      try {
        await this.keyring.delete(baseUrl, rec.username);
      } catch (e) {
        leftover = e;
      }
    }
    // The local record goes either way: a login that cannot be found cannot be used by mistake.
    await this.file.delete(baseUrl);
    if (leftover) {
      throw new AuthError(
        "unsupported",
        `The login record was removed, but the system keyring could not confirm that the secret for ${baseUrl} is gone, so it may remain there: ${(leftover as Error).message}`,
        { cause: leftover },
      );
    }
    return true;
  }

  /** Reads `hosts.yml` only, so `status` and host resolution still work when the keyring is wedged. */
  async list(): Promise<LoginSummary[]> {
    return (await this.file.list()).map(({ token: _token, ...s }) => s);
  }
}

/**
 * The real store, the only one: config dir from the environment, the native keyring unless
 * `GXY_NO_KEYRING` is set (to anything but "", "0" or "false"). One factory, so the auth
 * commands and operations (`config.ts`) cannot disagree about where logins live. Warnings go to
 * stderr, because stdout carries only what a pipe or `eval` may read.
 */
export function createCredentialStore(
  env: Record<string, string | undefined> = process.env,
  home: string = homedir(),
  warn: (message: string) => void = (m) => process.stderr.write(`warning: ${m}\n`),
): CredentialStore {
  const off = env.GXY_NO_KEYRING && env.GXY_NO_KEYRING !== "0" && env.GXY_NO_KEYRING.toLowerCase() !== "false";
  return new CombinedStore(new FileStore(configDir(env, home), undefined, warn), new KeyringStore(off ? noKeyringBackend : undefined));
}
