import { loadSources } from "../config";
import { openBrowser, canOpenBrowser } from "./browser";
import { resolveHost } from "./host";
import { discover } from "./oauth";
import { createCredentialStore } from "./store";
import type { AuthDeps } from "./types";
import { withUserAgent } from "./user-agent";
import { createWhoami } from "./whoami";

/** The real wiring of `auth`, built once per invocation (so `--help` never touches any of it). */
export function createAuthDeps(commandName: string): AuthDeps {
  const env = process.env;
  const store = createCredentialStore(env);
  const fetchWithUa = withUserAgent();
  return {
    store,
    discover: (baseUrl, signal) =>
      discover(baseUrl, { clientId: env.GXY_OAUTH_CLIENT_ID || undefined, fetch: fetchWithUa, signal }),
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
