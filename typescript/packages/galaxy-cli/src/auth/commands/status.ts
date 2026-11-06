import { checkExpiry, describeExpiry } from "../expiry";
import { AuthError, type AuthDeps, type LoginSummary, type StoredLogin } from "../types";
import { fail, formatExpiry, formatTimeLeft, hostOf, isExpired, maskToken, describeStorage, sanitize } from "./common";

export interface StatusOptions {
  host?: string;
  json?: boolean;
  showToken?: boolean;
  /** Aborted on Ctrl-C by the caller (commands don't touch process signals). */
  signal?: AbortSignal;
  /** Per host; a slow Galaxy is that host's failure, not the whole command's. */
  timeoutMs?: number;
}

const CHECK_TIMEOUT_MS = 10_000;
const EX_INTERRUPTED = 130;

/** Settle with `p`, or reject as soon as `signal` aborts (the work behind `p` is left to end on its own). */
function abortable<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

/** `unavailable`: the record is there but its token cannot be read (keyring down, secret gone). */
type State = "ok" | "expired" | "invalid" | "error" | "unavailable";

interface Checked {
  /** Without a token when it could not be read; `login` is then the record alone. */
  login: LoginSummary & { token?: string };
  state: State;
  username: string;
  /** From the live check; undefined when the check did not run or did not say. */
  isAdmin?: boolean;
  problem?: string;
}

export async function statusCommand(opts: StatusOptions, deps: AuthDeps): Promise<number> {
  const err = (s: string) => deps.io.stderr.write(`${s}\n`);
  try {
    let summaries = await deps.store.list();
    if (opts.host) {
      const baseUrl = await deps.resolveHost(opts.host);
      summaries = summaries.filter((s) => s.baseUrl === baseUrl);
      if (summaries.length === 0 && !opts.json) {
        err(`Not logged in to ${hostOf(baseUrl)}. Run: ${deps.commandName} auth login --host ${baseUrl}`);
        return 77;
      }
    } else if (summaries.length === 0 && !opts.json) {
      err(`No stored logins. Run: ${deps.commandName} auth login --host <url>`);
      return 77;
    }

    const now = deps.now();
    const checked: Checked[] = [];
    for (const summary of summaries) {
      // Each host on its own: one unreadable token must not hide the others.
      let login: (StoredLogin & { storage: LoginSummary["storage"] }) | null = null;
      let unreadable: string;
      try {
        login = await deps.store.get(summary.baseUrl);
        unreadable = "the token is not in the store";
      } catch (e) {
        unreadable = e instanceof Error ? e.message : String(e);
      }
      if (!login) {
        checked.push({ login: summary, state: "unavailable", username: summary.username, problem: `token unavailable: ${sanitize(unreadable)}` });
        continue;
      }
      const expiry = checkExpiry(login.expiresAt, now);
      if (expiry.state === "expired" || expiry.state === "unreadable") {
        checked.push({ login, state: "expired", username: login.username, problem: describeExpiry(login.expiresAt!, now) });
        continue;
      }
      const timeoutMs = opts.timeoutMs ?? CHECK_TIMEOUT_MS;
      const timeout = AbortSignal.timeout(timeoutMs);
      const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
      try {
        const who = await abortable(deps.whoami(login.baseUrl, login.token, signal), signal);
        checked.push({ login, state: "ok", username: who.username, ...(who.isAdmin !== undefined ? { isAdmin: who.isAdmin } : {}) });
      } catch (e) {
        if (opts.signal?.aborted) return EX_INTERRUPTED;
        if (timeout.aborted) {
          checked.push({
            login,
            state: "error",
            username: login.username,
            problem: `No answer from ${hostOf(login.baseUrl)} within ${Math.round(timeoutMs / 1000)} s.`,
          });
          continue;
        }
        const invalid = e instanceof AuthError && e.kind === "not_logged_in";
        checked.push({
          login,
          state: invalid ? "invalid" : "error",
          username: login.username,
          problem: sanitize(e instanceof Error ? e.message : String(e)),
        });
      }
    }

    if (opts.json) {
      const out = checked.map((c) => ({
        base_url: c.login.baseUrl,
        username: sanitize(c.username),
        is_admin: c.isAdmin ?? null,
        storage: c.login.storage,
        method: c.login.method,
        scopes: c.login.scopes.map((s) => sanitize(s)),
        obtained_at: c.login.obtainedAt,
        expires_at: c.login.expiresAt,
        status: c.state,
        ...(c.problem ? { error: c.problem } : {}),
        ...(opts.showToken && c.login.token !== undefined ? { token: c.login.token } : {}),
      }));
      deps.io.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
      return 0;
    }

    const envKey = deps.env.GALAXY_API_KEY;
    for (const c of checked) {
      const l = c.login;
      err(sanitize(hostOf(l.baseUrl)));
      if (c.state === "ok") err(`  ✓ Logged in as ${sanitize(c.username)}`);
      else if (c.state === "expired") err(`  ✗ Login ${c.problem}. Run: ${deps.commandName} auth login --host ${l.baseUrl}`);
      else if (c.state === "unavailable") err(`  ✗ ${c.problem}. Run: ${deps.commandName} auth login --host ${l.baseUrl}`);
      else err(`  ✗ ${c.problem}`);
      err(`  Storage  ${describeStorage(l.storage)}`);
      err(`  Method   ${l.method === "device" ? "device login" : "pasted API key"}`);
      err(`  Scopes   ${l.scopes.length ? sanitize(l.scopes.join(" ")) : l.method === "pasted" ? "full access (API key)" : "server default"}`);
      const expiry = checkExpiry(l.expiresAt, now);
      if (expiry.state === "valid") {
        err(`  Expires  in ${formatTimeLeft(expiry.at.getTime() - now.getTime())} (${formatExpiry(l.expiresAt!)})`);
      } else if (expiry.state === "none") {
        err("  Expires  no expiry");
      }
      // Masked on stderr always: the secret itself, when asked for, goes to stdout.
      err(`  Token    ${l.token === undefined ? "unavailable" : maskToken(l.token)}`);
      if (c.isAdmin) err(`  ! This token carries full admin rights on ${hostOf(l.baseUrl)}. Treat it like a password.`);
      if (l.expiresAt === null && l.token !== undefined) err("  ! This token has no expiry: it works until you revoke it in Galaxy's user preferences.");
    }
    if (opts.showToken) {
      for (const c of checked) if (c.login.token !== undefined) deps.io.stdout.write(`${c.login.baseUrl}\t${c.login.token}\n`);
    }
    if (envKey) err("\nGALAXY_API_KEY is set and takes precedence over stored logins.");
    return checked.some((c) => c.state !== "ok") ? 1 : 0;
  } catch (e) {
    return fail(deps, e);
  }
}
