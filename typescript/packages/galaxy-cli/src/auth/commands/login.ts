import { createInterface } from "node:readline";
import { normalizeBaseUrl } from "../base-url";
import { AuthError, type AuthDeps, type BaseUrl, type StoredLogin, type TokenGrant } from "../types";
import { fail, formatCountdown, formatExpiry, hostOf } from "./common";

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

const EX_INTERRUPTED = 130;

/** Lines from stdin, one at a time, without losing what arrives between reads. */
class LineReader {
  private queue: string[] = [];
  private waiters: ((line: string | null) => void)[] = [];
  private closed = false;
  private rl: ReturnType<typeof createInterface>;

  constructor(stdin: NodeJS.ReadableStream) {
    this.rl = createInterface({ input: stdin, terminal: false });
    this.rl.on("line", (line) => {
      const w = this.waiters.shift();
      if (w) w(line);
      else this.queue.push(line);
    });
    this.rl.on("close", () => {
      this.closed = true;
      for (const w of this.waiters.splice(0)) w(null);
    });
  }

  next(): Promise<string | null> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  close(): void {
    this.rl.close();
  }
}

async function readAll(stdin: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks).toString("utf8");
}

function storedMessage(storage: "keyring" | "file", expiresAt: string | null): string {
  const where = storage === "keyring" ? "the system keyring" : "a file readable only by you";
  return `✓ Token stored in ${where} (${expiresAt ? `expires ${formatExpiry(expiresAt)}` : "no expiry"})`;
}

export async function loginCommand(opts: LoginOptions, deps: AuthDeps): Promise<number> {
  const err = (s: string) => deps.io.stderr.write(`${s}\n`);
  let reader: LineReader | undefined;
  try {
    // 1. Which Galaxy.
    let baseUrl: BaseUrl;
    if (opts.host) {
      baseUrl = await deps.resolveHost(opts.host);
    } else {
      try {
        baseUrl = await deps.resolveHost();
      } catch (e) {
        if (!(e instanceof AuthError && e.kind === "usage") || !deps.io.interactive || opts.withToken) throw e;
        reader = new LineReader(deps.io.stdin);
        deps.io.stderr.write("Galaxy URL (for example https://usegalaxy.org): ");
        const answer = await reader.next();
        if (!answer?.trim()) throw new AuthError("usage", "No Galaxy URL given. Pass --host <url>.");
        baseUrl = normalizeBaseUrl(answer);
      }
    }
    const host = hostOf(baseUrl);

    if (deps.env.GALAXY_API_KEY) {
      err("! GALAXY_API_KEY is set and will take precedence over the login stored now. Unset it to use the stored login.");
    }

    // 2a. A key pasted on stdin.
    if (opts.withToken) {
      const raw = (await readAll(deps.io.stdin)).trim();
      if (!raw) throw new AuthError("usage", "No API key on stdin. Pipe it in: printf %s \"$KEY\" | " + `${deps.commandName} auth login --host ${baseUrl} --with-token`);
      if (/[\r\n]/.test(raw)) throw new AuthError("usage", "Expected a single-line API key on stdin, got several lines.");
      const who = await deps.whoami(baseUrl, raw);
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
      const put = await deps.store.put(login, { insecureStorage: opts.insecureStorage });
      if (put.warning) err(`! ${put.warning}`);
      err(`✓ Logged in to ${host} as ${who.username}`);
      err(storedMessage(put.storage, null));
      return 0;
    }

    // 2b. The device flow.
    const server = await deps.discover(baseUrl);
    if (!server.supportsDeviceFlow) {
      throw new AuthError(
        "unsupported",
        `${host} does not offer device login (it may be switched off by its admins). Paste an API key instead: ${deps.commandName} auth login --host ${baseUrl} --with-token`,
      );
    }
    const scopes = opts.scopes ?? [];
    const pending = await server.startDeviceLogin(scopes.length ? scopes : undefined);

    err(`Requesting access to ${host}`);
    err(`  Scopes  ${scopes.length ? scopes.join(" ") : "server default"}`);
    err("");
    err("! Only approve this code if you ran this command yourself.");
    err(`  One-time code: ${pending.userCode}`);
    err(`  Enter it at ${pending.verificationUri}`);

    const canOpen = opts.browser !== false && deps.io.interactive && (deps.canOpenBrowser?.() ?? true);
    const ac = new AbortController();
    const abort = () => ac.abort();
    opts.signal?.addEventListener("abort", abort, { once: true });
    if (opts.signal?.aborted) ac.abort();

    let grant: TokenGrant;
    try {
      if (canOpen) {
        err("Press Enter to open that page in your browser…");
        reader ??= new LineReader(deps.io.stdin);
        const r = reader;
        // Polling starts at once: approving on another device must not wait for Enter.
        void r.next().then(async (line) => {
          if (line === null || ac.signal.aborted) return;
          if (!(await deps.openBrowser(pending.verificationUri))) err("Could not open a browser. Open the page yourself.");
        });
      }
      err(`Waiting for approval (code expires in ${formatCountdown(pending.expiresAt.getTime() - deps.now().getTime())})…`);
      grant = await pending.waitForApproval(ac.signal);
    } catch (e) {
      if (ac.signal.aborted) {
        err("Cancelled.");
        return EX_INTERRUPTED;
      }
      throw e;
    } finally {
      opts.signal?.removeEventListener("abort", abort);
    }

    const who = await deps.whoami(baseUrl, grant.accessToken);
    const now = deps.now();
    const expiresAt = grant.expiresIn !== undefined ? new Date(now.getTime() + grant.expiresIn * 1000).toISOString() : null;
    const put = await deps.store.put(
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
      { insecureStorage: opts.insecureStorage },
    );
    if (put.warning) err(`! ${put.warning}`);
    err(`✓ Logged in to ${host} as ${who.username}`);
    err(storedMessage(put.storage, expiresAt));
    return 0;
  } catch (e) {
    return fail(deps, e);
  } finally {
    reader?.close();
  }
}
