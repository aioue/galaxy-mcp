import { sanitize } from "./sanitize";

/**
 * A login counts as expired this long before `expiresAt`, so a token that passes the check
 * here is still good for the operation (or the Claude Code session) it is handed to.
 */
export const EXPIRY_MARGIN_MS = 60_000;

export type Expiry =
  | { state: "none" }
  | { state: "valid"; at: Date }
  /** Within the margin or past. */
  | { state: "expired"; at: Date }
  /** `expires_at` is not a time (a hand-edited or corrupt `hosts.yml`). Never trusted as "no expiry". */
  | { state: "unreadable" };

export function checkExpiry(expiresAt: string | null | undefined, now: Date): Expiry {
  if (expiresAt === null || expiresAt === undefined) return { state: "none" };
  const ms = Date.parse(expiresAt);
  if (Number.isNaN(ms)) return { state: "unreadable" };
  const at = new Date(ms);
  return { state: ms - EXPIRY_MARGIN_MS <= now.getTime() ? "expired" : "valid", at };
}

/** True when the login must not be used: expired, about to expire, or with an unreadable expiry. */
export function isExpired(expiresAt: string | null | undefined, now: Date): boolean {
  const s = checkExpiry(expiresAt, now).state;
  return s === "expired" || s === "unreadable";
}

/** "2026-11-06 18:42 UTC"; never throws. */
export function formatExpiry(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return `an unreadable time (${sanitize(String(iso)).slice(0, 40)})`;
  return `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** Why a login cannot be used, as a clause: "expired at …", "expires in under a minute (at …)", "has an unreadable expiry …". */
export function describeExpiry(expiresAt: string, now: Date): string {
  const e = checkExpiry(expiresAt, now);
  if (e.state === "unreadable") return `has an unreadable expiry time (${sanitize(String(expiresAt)).slice(0, 40)}), so it cannot be trusted`;
  if (e.state === "expired" && e.at.getTime() > now.getTime()) return `is about to expire (at ${formatExpiry(expiresAt)})`;
  return `expired at ${formatExpiry(expiresAt)}`;
}
