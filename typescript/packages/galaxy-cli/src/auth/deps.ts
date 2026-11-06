import { homedir } from "node:os";
import { loadSources } from "../config";
import { openBrowser, canOpenBrowser } from "./browser";
import { FileStore } from "./file-store";
import { resolveHost } from "./host";
import { KeyringStore, KeyringUnavailableError, type KeyringBackend } from "./keyring-store";
import { discover } from "./oauth";
import { configDir } from "./paths";
import { CombinedStore, createCredentialStore } from "./store";
import type { AuthDeps, CredentialStore } from "./types";
import { withUserAgent } from "./user-agent";
import { createWhoami } from "./whoami";

/** A keyring that is never there, for `GXY_NO_KEYRING=1`: tokens go to the file, as on a headless box. */
const noKeyring: KeyringBackend = {
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

/** The store `auth` and the other commands share: the real keyring unless `GXY_NO_KEYRING` is set. */
export function createStore(
  env: Record<string, string | undefined> = process.env,
  home: string = homedir(),
  warn: (message: string) => void = (m) => process.stderr.write(`warning: ${m}\n`),
): CredentialStore {
  if (!env.GXY_NO_KEYRING) return createCredentialStore(env, home, warn);
  return new CombinedStore(new FileStore(configDir(env, home), undefined, warn), new KeyringStore(noKeyring));
}

/** The real wiring of `auth`, built once per invocation (so `--help` never touches any of it). */
export function createAuthDeps(commandName: string): AuthDeps {
  const env = process.env;
  const store = createStore(env);
  const fetchWithUa = withUserAgent();
  return {
    store,
    discover: (baseUrl) => discover(baseUrl, { clientId: env.GXY_OAUTH_CLIENT_ID || undefined, fetch: fetchWithUa }),
    whoami: createWhoami(),
    resolveHost: (explicit) => resolveHost({ explicit, env, dotenv: loadSources().dotenv, store, commandName }),
    openBrowser: (url) => openBrowser(url, env),
    canOpenBrowser: () => canOpenBrowser(env),
    now: () => new Date(),
    env,
    io: {
      stdin: process.stdin,
      stdout: process.stdout,
      stderr: process.stderr,
      interactive: Boolean(process.stdin.isTTY && process.stderr.isTTY),
    },
    commandName,
  };
}
