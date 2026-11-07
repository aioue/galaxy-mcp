import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { normalizeBaseUrl } from "./auth/base-url";
import { NoHostError, pickHost } from "./auth/host";
import { createCredentialStore } from "./auth/store";
import { describeExpiry, isExpired } from "./auth/expiry";
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

/**
 * Which Galaxy an operation talks to: `auth/host.ts`'s one rule, fed from these sources.
 *
 * `forLogin` is left off. An operation has always read `.env` and the profile, and a stored token
 * only goes to a host that matches a stored login, so those files cannot send one anywhere; it is
 * `auth login` that must not take its host from them.
 */
function pickOperationHost(flags: GlobalFlags, src: Sources): string {
  const prof = flags.profile ? src.profiles[flags.profile] : undefined;
  return pickHost({
    flag: flags.url,
    env: src.env,
    dotenv: src.dotenv,
    profileUrl: prof?.galaxy_url,
    storedBaseUrls: src.storedBaseUrls ?? [],
  }).url;
}

/** Pure resolver -- sources injected so it is fully testable. */
export function resolveConnection(flags: GlobalFlags, src: Sources): Connection {
  const prof = flags.profile ? src.profiles[flags.profile] : undefined;
  // The same rule as `gxy auth *` (auth/host.ts). With nothing named and nothing stored the
  // generic "no credentials" error below says what to do, so that case is not an error here.
  let baseUrl: string | undefined;
  try {
    baseUrl = pickOperationHost(flags, src);
  } catch (e) {
    if (!(e instanceof NoHostError)) throw e;
  }

  // An explicit key always wins, exactly as before stored logins existed.
  const explicitKey = flags.apiKey ?? src.env.GALAXY_API_KEY;
  const otherKey = src.dotenv.GALAXY_API_KEY ?? prof?.galaxy_user_key ?? prof?.galaxy_admin_key;
  const login = baseUrl && !explicitKey ? matchingLogin(baseUrl, src.storedLogin) : undefined;
  const now = src.now ?? new Date();
  // An unreadable expiry counts as expired, and so does one within a minute of running out.
  const expired = login && isExpired(login.expiresAt, now);

  let apiKey: string | undefined = explicitKey;
  let warning: string | undefined = src.storeProblem;
  let usedStored = false;
  if (!apiKey && login && !expired) {
    apiKey = login.token;
    usedStored = true;
  }
  if (!apiKey) apiKey = otherKey;
  if (!apiKey && expired) {
    throw new AuthError(
      "not_logged_in",
      `Your login to ${login.baseUrl} ${describeExpiry(login.expiresAt!, now)}; run gxy auth login --host ${login.baseUrl}`,
    );
  }
  if (expired && apiKey) {
    warning = `Your login to ${login.baseUrl} ${describeExpiry(login.expiresAt!, now)}; using another key instead. Run gxy auth login --host ${login.baseUrl} to renew it.`;
  }
  if (!baseUrl || !apiKey) {
    throw new Error(
      "No Galaxy credentials. Set GALAXY_URL and GALAXY_API_KEY (env, a .env file, or --url/--api-key), " +
        "or pass --profile <name> for a ~/.planemo.yml profile, or run gxy auth login." +
        (src.storeProblem ? ` (${src.storeProblem})` : ""),
    );
  }
  // The key goes to the vetted form of the URL it was stored for, not to the raw string
  // (which may carry a query or an odd path) that merely normalises to it.
  const target = usedStored ? login!.baseUrl : baseUrl;
  return warning ? { baseUrl: target, apiKey, warning } : { baseUrl: target, apiKey };
}

/** The stored login, if it is for this very Galaxy: compared as normalised, never as typed. */
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
    const summaries = await store.list();
    const storedBaseUrls = summaries.map((s) => s.baseUrl);
    let target: BaseUrl | undefined;
    try {
      // Only a host that matches a stored login exactly gets its token: a `.env` or profile
      // that names another Galaxy finds no login here, so nothing is sent there.
      target = normalizeBaseUrl(pickOperationHost(flags, { ...src, storedBaseUrls }));
    } catch (e) {
      // Ambiguity is reported by resolveConnection; an unparsable URL has no stored login.
      if (!(e instanceof AuthError)) throw e;
      target = undefined;
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
