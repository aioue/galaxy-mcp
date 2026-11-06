import { createInterface } from "node:readline";
import { isLoopback, normalizeBaseUrl } from "../base-url";
import { InputCancelled, isRawCapable, readPiped, readSecret } from "../stdin";
import { AuthError, type AuthDeps, type AuthServer, type BaseUrl, type PutResult, type StoredLogin, type TokenGrant, type WhoAmI } from "../types";
import { fail, formatCountdown, formatExpiry, hostOf, sanitize } from "./common";

export interface LoginOptions {
  host?: string;
  scopes?: string[];
  /** `--no-browser` sets this false. */
  browser?: boolean;
  withToken?: boolean;
  insecureStorage?: boolean;
  /** Aborted on Ctrl-C by the caller (commands don't touch process signals). */
  signal?: AbortSignal;
}

/** Same Galaxy, however the URL was written; an unparsable one never matches. */
function sameGalaxy(a: string, b: string): boolean {
  try {
    return normalizeBaseUrl(a) === b;
  } catch {
    return false;
  }
}

const EX_INTERRUPTED = 130;
const REVOKE_TIMEOUT_MS = 5000;

/** Lines from stdin, one at a time; readline buffers what arrives between reads. */
function lineReader(stdin: NodeJS.ReadableStream) {
  const rl = createInterface({ input: stdin, terminal: false });
  const lines = rl[Symbol.asyncIterator]();
  return {
    async next(): Promise<string | null> {
      const r = await lines.next();
      return r.done ? null : r.value;
    },
    close: () => rl.close(),
  };
}

/** Settle with `p`, or reject as soon as `signal` aborts (the work behind `p` is left to finish on its own). */
function abortable<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    p.catch(() => undefined);
    return Promise.reject(signal.reason);
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

/**
 * Where a person may be sent to approve the code: https (or http to this machine) on the
 * Galaxy's own origin. The server picks this URL and we print and open it, so a Galaxy
 * behind a misconfigured proxy must not be able to point people at another host.
 */
function isTrustedVerificationUri(uri: string, baseUrl: string): boolean {
  try {
    const u = new URL(uri);
    if (u.origin !== new URL(baseUrl).origin) return false;
    return u.protocol === "https:" || (u.protocol === "http:" && isLoopback(u.hostname));
  } catch {
    return false;
  }
}

/** Printed before the token is stored, so it shows even when storing is refused. */
function adminWarning(host: string, who: WhoAmI): string | undefined {
  return who.isAdmin ? `! This token carries full admin rights on ${host}. Treat it like a password.` : undefined;
}

/** Warnings a person should see after a fresh login is stored (the admin one came earlier). */
function tokenWarnings(expiresAt: string | null): string[] {
  return expiresAt === null ? ["! This token has no expiry: it works until you revoke it in Galaxy's user preferences."] : [];
}

/** One wording and hint for every way a Galaxy can lack device login. */
function noDeviceLogin(deps: AuthDeps, host: string, baseUrl: string, why: string): AuthError {
  return new AuthError(
    "unsupported",
    `${host} does not offer device login yet (${why}). Paste an API key instead: ${deps.commandName} auth login --host ${baseUrl} --with-token`,
  );
}

function storedMessage(storage: "keyring" | "file", expiresAt: string | null): string {
  const where = storage === "keyring" ? "the system keyring" : "a file readable only by you";
  return `✓ Token stored in ${where} (${expiresAt ? `expires ${formatExpiry(expiresAt)}` : "no expiry"})`;
}

/** Best effort: a short wait, and say what happened either way, since the person may need to revoke it by hand. */
async function revokeAfterFailure(server: AuthServer, token: string, host: string, err: (s: string) => void): Promise<void> {
  if (!server.supportsRevocation) {
    err(`! ${host} issued a token that could not be kept, and it cannot be revoked from here. Revoke it in Galaxy's user preferences.`);
    return;
  }
  try {
    await Promise.race([
      server.revoke(token),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timed out")), REVOKE_TIMEOUT_MS).unref()),
    ]);
    err(`! The token ${host} issued could not be kept, so it was revoked.`);
  } catch {
    err(`! ${host} issued a token that could not be kept, and revoking it failed. Revoke it in Galaxy's user preferences.`);
  }
}

export async function loginCommand(opts: LoginOptions, deps: AuthDeps): Promise<number> {
  const err = (s: string) => deps.io.stderr.write(`${s}\n`);
  // One signal for the whole command: every step below either takes it or is raced against it.
  const signal = opts.signal ?? new AbortController().signal;
  let reader: ReturnType<typeof lineReader> | undefined;
  try {
    // 1. Which Galaxy.
    let baseUrl: BaseUrl;
    if (opts.host) {
      baseUrl = await abortable(deps.resolveHost(opts.host, "login"), signal);
    } else {
      try {
        baseUrl = await abortable(deps.resolveHost(undefined, "login"), signal);
      } catch (e) {
        if (!(e instanceof AuthError && e.kind === "usage") || !deps.io.interactive || opts.withToken) throw e;
        reader = lineReader(deps.io.stdin);
        deps.io.stderr.write("Galaxy URL (for example https://usegalaxy.org): ");
        const answer = await abortable(reader.next(), signal);
        if (!answer?.trim()) throw new AuthError("usage", "No Galaxy URL given. Pass --host <url>.");
        baseUrl = normalizeBaseUrl(answer);
      }
    }
    const host = hostOf(baseUrl);
    // Login never takes its host from `.env` or a profile (see pickHost); say so when one disagrees.
    if (!opts.host) {
      const ignored = deps.ignoredLoginHost?.();
      if (ignored && !sameGalaxy(ignored.url, baseUrl)) {
        err(
          ignored.source === "dotenv"
            ? `Ignoring GALAXY_URL from .env (${ignored.url}): login only uses --host or GALAXY_URL from the environment.`
            : `Ignoring galaxy_url from the --profile (${ignored.url}): login only uses --host or GALAXY_URL from the environment.`,
        );
      }
    }
    // Before a key is read or a code is requested: the person sees where it is going.
    err(`Logging in to ${host}`);

    if (deps.env.GALAXY_API_KEY) {
      err("! GALAXY_API_KEY is set and will take precedence over the login stored now. Unset it to use the stored login.");
    }

    // 2a. A key pasted on stdin, or typed at a terminal.
    if (opts.withToken) {
      let typed: string;
      if (deps.io.interactive && isRawCapable(deps.io.stdin)) {
        deps.io.stderr.write("Paste your Galaxy API key: ");
        typed = await readSecret(deps.io.stdin, signal);
        deps.io.stderr.write("\n");
      } else {
        typed = await readPiped(deps.io.stdin, signal);
      }
      const raw = typed.trim();
      if (!raw) throw new AuthError("usage", "No API key on stdin. Pipe it in: printf %s \"$KEY\" | " + `${deps.commandName} auth login --host ${baseUrl} --with-token`);
      if (/[\r\n]/.test(raw)) throw new AuthError("usage", "Expected a single-line API key on stdin, got several lines.");
      const who = await abortable(deps.whoami(baseUrl, raw, signal), signal);
      const login: StoredLogin = {
        baseUrl,
        username: who.username,
        ...(who.email ? { email: who.email } : {}),
        token: raw,
        method: "pasted",
        scopes: [],
        expiresAt: null,
        obtainedAt: deps.now().toISOString(),
      };
      // The write is atomic and short, so it is not interrupted; this is the last point to cancel.
      signal.throwIfAborted();
      // An admin's token is never written to the plaintext file unless asked for by flag.
      const adminWarn = adminWarning(host, who);
      if (adminWarn) err(adminWarn);
      const put = await deps.store.put(login, { insecureStorage: opts.insecureStorage, ...(who.isAdmin ? { requireKeyring: true } : {}) });
      if (put.warning) err(`! ${put.warning}`);
      err(`✓ Logged in to ${host} as ${sanitize(who.username)}`);
      err(storedMessage(put.storage, null));
      for (const w of tokenWarnings(null)) err(w);
      return 0;
    }

    // 2b. The device flow.
    let server: AuthServer;
    try {
      server = await abortable(deps.discover(baseUrl, signal), signal);
    } catch (e) {
      // Discovery says "unsupported" only when there is no usable metadata (404, not JSON).
      if (e instanceof AuthError && e.kind === "unsupported") throw noDeviceLogin(deps, host, baseUrl, "it publishes no OAuth metadata");
      throw e;
    }
    if (!server.supportsDeviceFlow) throw noDeviceLogin(deps, host, baseUrl, "it may be switched off by its admins");
    const scopes = opts.scopes ?? [];
    // A cancel during discovery must not create a code on the server.
    signal.throwIfAborted();
    const pending = await abortable(server.startDeviceLogin(scopes.length ? scopes : undefined), signal);

    if (!isTrustedVerificationUri(pending.verificationUri, baseUrl)) {
      throw new AuthError(
        "protocol",
        `${host} asked for the code to be entered at ${sanitize(pending.verificationUri)}, which is not an https page on ${host}. ` +
          "That could send you to another site, so the login was stopped. Paste an API key instead: " +
          `${deps.commandName} auth login --host ${baseUrl} --with-token`,
      );
    }

    err(`Requesting access to ${host}`);
    err(`  Scopes  ${scopes.length ? sanitize(scopes.join(" ")) : "server default"}`);
    err("");
    err("! Only approve this code if you ran this command yourself.");
    err(`  One-time code: ${sanitize(pending.userCode)}`);
    err(`  Enter it at ${sanitize(pending.verificationUri)}`);

    const canOpen = opts.browser !== false && deps.io.interactive && (deps.canOpenBrowser?.() ?? true);
    if (canOpen) {
      err("Press Enter to open that page in your browser…");
      reader ??= lineReader(deps.io.stdin);
      // Polling starts at once: approving on another device must not wait for Enter.
      void reader.next().then(async (line) => {
        if (line === null || signal.aborted) return;
        if (!(await deps.openBrowser(pending.verificationUri))) err("Could not open a browser. Open the page yourself.");
      });
    }
    err(`Waiting for approval (code expires in ${formatCountdown(pending.expiresAt.getTime() - deps.now().getTime())})…`);
    const grant: TokenGrant = await pending.waitForApproval(signal);

    // The server has issued a token. If it cannot be checked or kept, nothing local points at
    // it, so it would stay valid (an admin's too) until it expires: take it back.
    let who: WhoAmI;
    let put: PutResult;
    let expiresAt: string | null;
    try {
      who = await abortable(deps.whoami(baseUrl, grant.accessToken, signal), signal);
      const now = deps.now();
      expiresAt = grant.expiresIn !== undefined ? new Date(now.getTime() + grant.expiresIn * 1000).toISOString() : null;
      signal.throwIfAborted();
      const adminWarn = adminWarning(host, who);
      if (adminWarn) err(adminWarn);
      put = await deps.store.put(
        {
          baseUrl,
          username: who.username,
          ...(who.email ? { email: who.email } : {}),
          token: grant.accessToken,
          method: "device",
          scopes: grant.scopes,
          expiresAt,
          obtainedAt: now.toISOString(),
        },
        { insecureStorage: opts.insecureStorage, ...(who.isAdmin ? { requireKeyring: true } : {}) },
      );
    } catch (e) {
      await revokeAfterFailure(server, grant.accessToken, host, err);
      throw e;
    }
    if (put.warning) err(`! ${put.warning}`);
    err(`✓ Logged in to ${host} as ${sanitize(who.username)}`);
    err(storedMessage(put.storage, expiresAt));
    for (const w of tokenWarnings(expiresAt)) err(w);
    return 0;
  } catch (e) {
    if (signal.aborted || e instanceof InputCancelled) {
      err("Cancelled.");
      return EX_INTERRUPTED;
    }
    return fail(deps, e);
  } finally {
    reader?.close();
  }
}
