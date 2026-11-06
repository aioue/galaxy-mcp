import type { GalaxyErrorKind } from "@galaxyproject/galaxy-ops";
import type { AuthErrorKind } from "./auth/types";

export const EX_USAGE = 64;
export const EX_DATAERR = 65;
export const EX_NOINPUT = 66;
export const EX_UNAVAILABLE = 69;
export const EX_SOFTWARE = 70;
export const EX_PROTOCOL = 76;
export const EX_NOPERM = 77;

const MAP: Record<GalaxyErrorKind, number> = {
  auth: EX_NOPERM,
  not_found: EX_NOINPUT,
  validation: EX_USAGE,
  connection: EX_UNAVAILABLE,
  // "remote error in protocol": the server we reached does not speak a new enough Galaxy.
  version: EX_PROTOCOL,
  tool_request_rejected: EX_DATAERR,
  job_failed: EX_SOFTWARE,
  unknown: EX_SOFTWARE,
};

export function exitCodeFor(kind?: GalaxyErrorKind): number {
  if (!kind) return 0;
  return MAP[kind] ?? EX_SOFTWARE;
}

/** Exit codes for `auth` failures, by kind (docs: "Exit codes"). */
const AUTH_MAP: Record<AuthErrorKind, number> = {
  usage: EX_USAGE,
  ambiguous_host: EX_USAGE,
  network: EX_UNAVAILABLE,
  unsupported: EX_PROTOCOL,
  protocol: EX_PROTOCOL,
  insecure: EX_PROTOCOL,
  not_logged_in: EX_NOPERM,
  denied: EX_NOPERM,
  expired: EX_NOPERM,
};

export function exitCodeForAuthError(kind: AuthErrorKind): number {
  return AUTH_MAP[kind] ?? EX_SOFTWARE;
}
