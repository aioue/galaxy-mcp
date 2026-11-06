import type { AuthDeps, StoredLogin } from "../types";
import { fail, formatExpiry, hostOf, sanitize } from "./common";

export interface LogoutOptions {
  host?: string;
}

/** Revoke on the server first (device logins only), then delete locally whatever happens. */
export async function logoutCommand(opts: LogoutOptions, deps: AuthDeps): Promise<number> {
  const err = (s: string) => deps.io.stderr.write(`${s}\n`);
  try {
    const baseUrl = await deps.resolveHost(opts.host);
    const host = hostOf(baseUrl);
    // The record (no secret) decides whether there is anything to remove. Reading the token is
    // only needed to revoke it, and must not stand between the person and removing the record:
    // the keyring may be down or the secret gone, which is when cleaning up matters most.
    const summary = (await deps.store.list()).find((s) => s.baseUrl === baseUrl);
    if (!summary) {
      err(`Not logged in to ${host}; nothing to remove.`);
      return 0;
    }
    let login: StoredLogin | null = null;
    let unreadable: string | null = null;
    try {
      login = await deps.store.get(baseUrl);
      if (!login) unreadable = "the token is not in the store";
    } catch (e) {
      unreadable = sanitize(e instanceof Error ? e.message : String(e));
    }

    let revoked = false;
    let revokeProblem: string | null = null;
    if (!login) {
      revokeProblem = `the stored token could not be read: ${unreadable}`;
    } else if (login.method === "device") {
      try {
        const server = await deps.discover(baseUrl);
        if (!server.supportsRevocation) {
          revokeProblem = `${host} does not offer token revocation`;
        } else {
          await server.revoke(login.token);
          revoked = true;
        }
      } catch (e) {
        revokeProblem = sanitize(e instanceof Error ? e.message : String(e));
      }
    }

    // Local removal is attempted whatever the server said, and its own failure is reported
    // too: a secret that may remain in the keyring is something the person must know.
    let deleteProblem: string | null = null;
    try {
      await deps.store.delete(baseUrl);
    } catch (e) {
      deleteProblem = sanitize(e instanceof Error ? e.message : String(e), { keepNewlines: true });
    }

    if (summary.method === "pasted") {
      err(`✓ Removed the stored API key for ${host}`);
      err(`! The key itself was not revoked and still works. Manage it in Galaxy's user preferences: ${baseUrl}/user/api_key`);
    } else if (revoked) {
      err(`✓ Revoked the token on ${host}`);
      err(`✓ Removed the stored login for ${host}`);
    } else {
      err(`✓ Removed the stored login for ${host}`);
      const until = summary.expiresAt ? `until it expires (${formatExpiry(summary.expiresAt)})` : "until it is revoked in Galaxy";
      err(`! Could not revoke the token on the server (${revokeProblem}). It stays valid ${until}.`);
    }
    if (deleteProblem) {
      err(`! ${deleteProblem}`);
      return 1;
    }
    return 0;
  } catch (e) {
    return fail(deps, e);
  }
}
