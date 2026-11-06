import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { normalizeBaseUrl } from "./auth/base-url";
import { createCredentialStore } from "./auth/store";
import { AuthError, type BaseUrl, type CredentialStore, type StoredLogin } from "./auth/types";

/** `warning` is set when a usable key was found but something the user should know about was not. */
export interface Connection { baseUrl: string; apiKey: string; warning?: string; }
export interface GlobalFlags { url?: string; apiKey?: string; profile?: string; }
interface PlanemoProfile { galaxy_url?: string; galaxy_user_key?: string; galaxy_admin_key?: string; }
export interface Sources {
  env: Record<string, string | undefined>;
  dotenv: Record<string, string | undefined>;
  profiles: Record<string, PlanemoProfile>;
  /** Base URLs of every stored login (`gxy auth login`), loaded before resolving. */
  storedBaseUrls?: BaseUrl[];
  /** The stored login for the Galaxy being used (or the only one), with its token. */
  storedLogin?: StoredLogin;
  /** The clock, for judging whether `storedLogin` has expired. */
  now?: Date;
  /** Set when the credential store could not be read (corrupt file, keyring locked). */
  storeProblem?: string;
}

/** Pure resolver -- sources injected so it is fully testable. */
export function resolveConnection(flags: GlobalFlags, src: Sources): Connection {
  const prof = flags.profile ? src.profiles[flags.profile] : undefined;
  const stored = src.storedBaseUrls ?? [];
  const configuredUrl = flags.url ?? src.env.GALAXY_URL ?? src.dotenv.GALAXY_URL ?? prof?.galaxy_url;
  if (!configuredUrl && stored.length > 1) {
    throw new AuthError(
      "ambiguous_host",
      `Logged in to several Galaxies; say which with --url or GALAXY_URL:\n${stored.map((u) => `  ${u}`).join("\n")}`,
    );
  }
  const baseUrl = configuredUrl ?? (stored.length === 1 ? stored[0] : undefined);

  // An explicit key always wins, exactly as before stored logins existed.
  const explicitKey = flags.apiKey ?? src.env.GALAXY_API_KEY;
  const otherKey = src.dotenv.GALAXY_API_KEY ?? prof?.galaxy_user_key ?? prof?.galaxy_admin_key;
  const login = baseUrl && !explicitKey ? matchingLogin(baseUrl, src.storedLogin) : undefined;
  const expired = login && login.expiresAt !== null && Date.parse(login.expiresAt) <= (src.now ?? new Date()).getTime();

  let apiKey: string | undefined = explicitKey;
  let warning: string | undefined = src.storeProblem;
  if (!apiKey && login && !expired) apiKey = login.token;
  if (!apiKey) apiKey = otherKey;
  if (!apiKey && expired) {
    throw new AuthError(
      "not_logged_in",
      `Your login to ${login.baseUrl} expired at ${login.expiresAt}; run gxy auth login --host ${login.baseUrl}`,
    );
  }
  if (expired && apiKey) {
    warning = `Your login to ${login.baseUrl} expired at ${login.expiresAt}; using another key instead. Run gxy auth login --host ${login.baseUrl} to renew it.`;
  }
  if (!baseUrl || !apiKey) {
    throw new Error(
      "No Galaxy credentials. Set GALAXY_URL and GALAXY_API_KEY (env, a .env file, or --url/--api-key), " +
        "or pass --profile <name> for a ~/.planemo.yml profile, or run gxy auth login." +
        (src.storeProblem ? ` (${src.storeProblem})` : ""),
    );
  }
  return warning ? { baseUrl, apiKey, warning } : { baseUrl, apiKey };
}

function matchingLogin(baseUrl: string, login: StoredLogin | undefined): StoredLogin | undefined {
  if (!login) return undefined;
  try {
    return normalizeBaseUrl(baseUrl) === login.baseUrl ? login : undefined;
  } catch {
    return undefined;
  }
}

/** Read the real sources from disk/env (kept separate from the pure resolver). */
export function loadSources(): Sources {
  return { env: process.env, dotenv: readDotenv(), profiles: readPlanemoProfiles() };
}

/**
 * Like `loadSources`, plus the stored login for the Galaxy these flags point at. The store
 * is only touched when no explicit key is given, so a broken keyring or hosts.yml never
 * gets in the way of `--api-key` or `GALAXY_API_KEY`.
 */
export async function loadSourcesAsync(
  flags: GlobalFlags = {},
  opts: { store?: CredentialStore; now?: Date; base?: Sources } = {},
): Promise<Sources> {
  const src = opts.base ?? loadSources();
  const now = opts.now ?? new Date();
  if (flags.apiKey || src.env.GALAXY_API_KEY) return { ...src, now };
  try {
    const store = opts.store ?? createCredentialStore(src.env);
    const prof = flags.profile ? src.profiles[flags.profile] : undefined;
    const url = flags.url ?? src.env.GALAXY_URL ?? src.dotenv.GALAXY_URL ?? prof?.galaxy_url;
    const summaries = await store.list();
    const storedBaseUrls = summaries.map((s) => s.baseUrl);
    let target: BaseUrl | undefined;
    if (url) {
      try {
        target = normalizeBaseUrl(url);
      } catch {
        target = undefined;
      }
    } else if (storedBaseUrls.length === 1) {
      target = storedBaseUrls[0];
    }
    const storedLogin = target && storedBaseUrls.includes(target) ? ((await store.get(target)) ?? undefined) : undefined;
    return { ...src, storedBaseUrls, ...(storedLogin ? { storedLogin } : {}), now };
  } catch (e) {
    return { ...src, now, storeProblem: e instanceof Error ? e.message : String(e) };
  }
}

function readDotenv(): Record<string, string | undefined> {
  try {
    const text = readFileSync(join(process.cwd(), ".env"), "utf8");
    const out: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
      if (m?.[1] !== undefined && m[2] !== undefined) out[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
    return out;
  } catch {
    return {};
  }
}

function readPlanemoProfiles(): Record<string, PlanemoProfile> {
  try {
    const doc = parseYaml(readFileSync(join(homedir(), ".planemo.yml"), "utf8")) as Record<string, unknown>;
    // planemo stores named profiles under `profiles:`; also accept top-level galaxy_url/key as "default".
    const profiles = (doc?.profiles as Record<string, PlanemoProfile>) ?? {};
    if (doc?.galaxy_url) profiles.default = { galaxy_url: String(doc.galaxy_url), galaxy_user_key: doc.galaxy_user_key as string | undefined };
    return profiles;
  } catch {
    return {};
  }
}
