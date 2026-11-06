import { loadSources } from "../config";
import { openBrowser, canOpenBrowser } from "./browser";
import { resolveHost } from "./host";
import { discover } from "./oauth";
import { createCredentialStore } from "./store";
import type { AuthDeps } from "./types";
import { withUserAgent } from "./user-agent";
import { createWhoami } from "./whoami";

/** The real wiring of `auth`, built once per invocation (so `--help` never touches any of it). */
export function createAuthDeps(commandName: string, globals: () => { url?: string; profile?: string } = () => ({})): AuthDeps {
  const env = process.env;
  const store = createCredentialStore(env);
  const fetchWithUa = withUserAgent();
  return {
    store,
    discover: (baseUrl, signal) =>
      discover(baseUrl, { clientId: env.GXY_OAUTH_CLIENT_ID || undefined, fetch: fetchWithUa, signal }),
    whoami: createWhoami(),
    // The same rule operations use (config.ts), so the two cannot pick different Galaxies. The
    // global `--url` counts as the flag and `--profile` supplies its planemo URL; login ignores
    // `.env` and the profile (see pickHost).
    resolveHost: (explicit, purpose) => {
      const g = globals();
      const src = loadSources();
      return resolveHost({
        explicit: explicit ?? g.url,
        env,
        dotenv: src.dotenv,
        profileUrl: g.profile ? src.profiles[g.profile]?.galaxy_url : undefined,
        forLogin: purpose === "login",
        store,
        commandName,
      });
    },
    ignoredLoginHost: () => {
      const src = loadSources();
      const dotenv = src.dotenv.GALAXY_URL;
      if (dotenv) return { source: "dotenv", url: dotenv };
      const profile = globals().profile ? src.profiles[globals().profile!]?.galaxy_url : undefined;
      return profile ? { source: "profile", url: profile } : undefined;
    },
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
