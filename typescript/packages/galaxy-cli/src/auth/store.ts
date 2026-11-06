import { homedir } from "node:os";
import { FileStore, type HostRecord } from "./file-store";
import { KeyringStore } from "./keyring-store";
import { configDir } from "./paths";
import { AuthError, type BaseUrl, type CredentialStore, type LoginSummary, type PutResult, type StoredLogin, type StorageKind } from "./types";

/**
 * Metadata always lives in `hosts.yml`; the token lives in the system keyring when that
 * works, else in `hosts.yml` too (with a warning). The metadata's `storage` field says
 * which, so `get` never has to guess.
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
      throw new AuthError("not_logged_in", `The token for ${baseUrl} is in the system keyring, which is not available: ${(e as Error).message}`, { cause: e });
    }
    if (token === null) return null;
    return { ...summary, token };
  }

  async put(login: StoredLogin, opts: { insecureStorage?: boolean; requireKeyring?: boolean } = {}): Promise<PutResult> {
    const { token, ...summary } = login;
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
        if (opts.requireKeyring) {
          // Nothing has been written yet (the file is only touched below), so refusing is clean.
          await this.keyring.delete(login.baseUrl, login.username).catch(() => {});
          throw new AuthError(
            "denied",
            `No system keyring here, so nothing was stored. Rerun with --insecure-storage to keep it in ${this.file.path} (readable only by you), or use GALAXY_API_KEY for this session.`,
            { cause: e },
          );
        }
        warning = `No system keyring available; token saved in plain text at ${this.file.path} (readable only by you)`;
      }
    }
    const record: HostRecord = storage === "file" ? { ...summary, storage, token } : { ...summary, storage };
    // Metadata (and so the plaintext token, if any, being dropped) is replaced in one atomic write.
    await this.file.put(record);
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

  async list(): Promise<LoginSummary[]> {
    return (await this.file.list()).map(({ token: _token, ...s }) => s);
  }
}

/** The real store: config dir from the environment, the native keyring. */
export function createCredentialStore(
  env: Record<string, string | undefined> = process.env,
  home: string = homedir(),
  warn: (message: string) => void = (m) => process.stderr.write(`warning: ${m}\n`),
): CredentialStore {
  return new CombinedStore(new FileStore(configDir(env, home), undefined, warn), new KeyringStore());
}
