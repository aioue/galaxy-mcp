import { exitCodeForAuthError, EX_SOFTWARE } from "../../exit";
import { sanitize } from "../sanitize";
import { AuthError, type AuthDeps, type BaseUrl, type StoredLogin, type StorageKind } from "../types";

export { sanitize };

/**
 * Print a failure for a person and map it to an exit code. Never includes a token: messages
 * are ours. They can still quote the server (an OAuth error text, a whoami failure), so
 * terminal control characters are stripped on the way out.
 */
export function fail(deps: AuthDeps, e: unknown): number {
  if (e instanceof AuthError) {
    deps.io.stderr.write(`${sanitize(e.message, { keepNewlines: true })}\n`);
    return exitCodeForAuthError(e.kind);
  }
  deps.io.stderr.write(`Unexpected error: ${sanitize(e instanceof Error ? e.message : String(e), { keepNewlines: true })}\n`);
  return EX_SOFTWARE;
}

export function hostOf(baseUrl: string): string {
  try {
    return new URL(baseUrl).host + (new URL(baseUrl).pathname.replace(/\/+$/, ""));
  } catch {
    return baseUrl;
  }
}

export function isExpired(expiresAt: string | null, now: Date): boolean {
  return expiresAt !== null && new Date(expiresAt).getTime() <= now.getTime();
}

/** "2026-11-06 18:42 UTC" */
export function formatExpiry(iso: string): string {
  return `${new Date(iso).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** "7h 58m", "2d 3h", "12m", "under a minute". */
export function formatTimeLeft(ms: number): string {
  const mins = Math.floor(ms / 60_000);
  if (mins < 1) return "under a minute";
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** "14:52" */
export function formatCountdown(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Keep the last four characters so a person can tell tokens apart; hide the rest. */
export function maskToken(token: string): string {
  return token.length > 12 ? `${"*".repeat(8)}${token.slice(-4)}` : "*".repeat(8);
}

export function describeStorage(kind: StorageKind): string {
  return kind === "keyring" ? "system keyring" : "plaintext file (readable only by you)";
}

/**
 * The stored, unexpired login for the host a command means, or an AuthError that says
 * how to log in. No network: `token`, `env` and `headers` are called by helpers.
 */
export async function requireLogin(deps: AuthDeps, explicitHost?: string): Promise<StoredLogin> {
  return requireLoginAt(deps, await deps.resolveHost(explicitHost));
}

/** `requireLogin` for a Galaxy the caller has already settled on. */
export async function requireLoginAt(deps: AuthDeps, baseUrl: BaseUrl): Promise<StoredLogin> {
  const login = await deps.store.get(baseUrl);
  const hint = `${deps.commandName} auth login --host ${baseUrl}`;
  if (!login) throw new AuthError("not_logged_in", `Not logged in to ${baseUrl}. Run: ${hint}`);
  if (isExpired(login.expiresAt, deps.now())) {
    throw new AuthError("not_logged_in", `Your login to ${baseUrl} expired at ${formatExpiry(login.expiresAt!)}. Run: ${hint}`);
  }
  return login;
}
