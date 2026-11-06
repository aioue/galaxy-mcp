import { AuthError, type AuthDeps, type StoredLogin, type StorageKind } from "../types";
import { fail, formatExpiry, formatTimeLeft, hostOf, isExpired, maskToken, describeStorage } from "./common";

export interface StatusOptions {
  host?: string;
  json?: boolean;
  showToken?: boolean;
}

type State = "ok" | "expired" | "invalid" | "error";

interface Checked {
  login: StoredLogin & { storage: StorageKind };
  state: State;
  username: string;
  problem?: string;
}

export async function statusCommand(opts: StatusOptions, deps: AuthDeps): Promise<number> {
  const err = (s: string) => deps.io.stderr.write(`${s}\n`);
  try {
    const logins: (StoredLogin & { storage: StorageKind })[] = [];
    if (opts.host) {
      const baseUrl = await deps.resolveHost(opts.host);
      const one = await deps.store.get(baseUrl);
      if (one) logins.push(one);
      else if (!opts.json) {
        err(`Not logged in to ${hostOf(baseUrl)}. Run: ${deps.commandName} auth login --host ${baseUrl}`);
        return 77;
      }
    } else {
      for (const s of await deps.store.list()) {
        const full = await deps.store.get(s.baseUrl);
        if (full) logins.push(full);
      }
      if (logins.length === 0 && !opts.json) {
        err(`No stored logins. Run: ${deps.commandName} auth login --host <url>`);
        return 77;
      }
    }

    const now = deps.now();
    const checked: Checked[] = [];
    for (const login of logins) {
      if (isExpired(login.expiresAt, now)) {
        checked.push({ login, state: "expired", username: login.username, problem: `expired at ${formatExpiry(login.expiresAt!)}` });
        continue;
      }
      try {
        const who = await deps.whoami(login.baseUrl, login.token);
        checked.push({ login, state: "ok", username: who.username });
      } catch (e) {
        const invalid = e instanceof AuthError && e.kind === "not_logged_in";
        checked.push({
          login,
          state: invalid ? "invalid" : "error",
          username: login.username,
          problem: e instanceof Error ? e.message : String(e),
        });
      }
    }

    if (opts.json) {
      const out = checked.map((c) => ({
        base_url: c.login.baseUrl,
        username: c.username,
        storage: c.login.storage,
        method: c.login.method,
        scopes: c.login.scopes,
        obtained_at: c.login.obtainedAt,
        expires_at: c.login.expiresAt,
        status: c.state,
        ...(c.problem ? { error: c.problem } : {}),
        ...(opts.showToken ? { token: c.login.token } : {}),
      }));
      deps.io.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
      return 0;
    }

    const envKey = deps.env.GALAXY_API_KEY;
    for (const c of checked) {
      const l = c.login;
      err(hostOf(l.baseUrl));
      if (c.state === "ok") err(`  ✓ Logged in as ${c.username}`);
      else if (c.state === "expired") err(`  ✗ Login expired at ${formatExpiry(l.expiresAt!)}. Run: ${deps.commandName} auth login --host ${l.baseUrl}`);
      else err(`  ✗ ${c.problem}`);
      err(`  Storage  ${describeStorage(l.storage)}`);
      err(`  Method   ${l.method === "device" ? "device login" : "pasted API key"}`);
      err(`  Scopes   ${l.scopes.length ? l.scopes.join(" ") : l.method === "pasted" ? "full access (API key)" : "server default"}`);
      if (l.expiresAt && c.state !== "expired") {
        err(`  Expires  in ${formatTimeLeft(new Date(l.expiresAt).getTime() - now.getTime())} (${formatExpiry(l.expiresAt)})`);
      } else if (!l.expiresAt) {
        err("  Expires  no expiry");
      }
      err(`  Token    ${opts.showToken ? l.token : maskToken(l.token)}`);
    }
    if (envKey) err("\nGALAXY_API_KEY is set and takes precedence over stored logins.");
    return checked.some((c) => c.state !== "ok") ? 1 : 0;
  } catch (e) {
    return fail(deps, e);
  }
}
