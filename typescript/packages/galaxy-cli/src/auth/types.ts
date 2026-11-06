/**
 * The seams between the parts of `auth`: where a login is kept, how one is obtained
 * from Galaxy, and what the commands are given to do their work.
 *
 * Every command takes an `AuthDeps` rather than reaching for the filesystem, the
 * network, the clock or the terminal itself, so each one can be tested with fakes and
 * the real implementations are wired together in one place (`deps.ts`).
 */

/** The OAuth client id this CLI presents. Galaxy registers it as a public client (no secret). */
export const CLIENT_ID = "galaxy-cli";

/**
 * A Galaxy's base URL in the form logins are keyed by: scheme, host, port and path
 * prefix, without a trailing slash or query (`https://usegalaxy.org`,
 * `https://example.org/galaxy`). Produced by `normalizeBaseUrl`; never compared raw.
 */
export type BaseUrl = string & { readonly __brand: "BaseUrl" };

/** Where a token is kept. `file` is the plaintext fallback, readable only by the owner. */
export type StorageKind = "keyring" | "file";

/** How a token was obtained, which decides whether `logout` can revoke it on the server. */
export type LoginMethod = "device" | "pasted";

/** One login to one Galaxy, as stored. */
export interface StoredLogin {
  baseUrl: BaseUrl;
  /** Galaxy username from `/api/users/current`, at login time. */
  username: string;
  email?: string;
  token: string;
  method: LoginMethod;
  /** Scopes the server granted (empty for a pasted API key, which carries the user's full power). */
  scopes: string[];
  /** ISO 8601, or null when the server gave no expiry (always null for a pasted API key). */
  expiresAt: string | null;
  /** ISO 8601. */
  obtainedAt: string;
}

/** A stored login without its secret, safe to print or list. */
export type LoginSummary = Omit<StoredLogin, "token"> & { storage: StorageKind };

export interface PutResult {
  storage: StorageKind;
  /** Set when the keyring could not be used and the token went to the file instead. */
  warning?: string;
}

export interface CredentialStore {
  /** The login for this Galaxy, or null if there is none. Never throws for "not found". */
  get(baseUrl: BaseUrl): Promise<(StoredLogin & { storage: StorageKind }) | null>;
  /** Store or replace the login for `login.baseUrl`. `insecureStorage` skips the keyring. */
  put(login: StoredLogin, opts?: { insecureStorage?: boolean }): Promise<PutResult>;
  /** Remove the login for this Galaxy from every place it is kept. Returns false if there was none. */
  delete(baseUrl: BaseUrl): Promise<boolean>;
  /** Every stored login, without tokens, sorted by base URL. */
  list(): Promise<LoginSummary[]>;
}

/** What the server returned when the user approved. */
export interface TokenGrant {
  accessToken: string;
  /** Seconds, as sent; absent when the server gave no expiry. */
  expiresIn?: number;
  /** Granted scopes (the token response's `scope`, split on spaces); may be fewer than requested. */
  scopes: string[];
}

/** A device login in progress: what to show the user, and the wait for their approval. */
export interface PendingDeviceLogin {
  userCode: string;
  verificationUri: string;
  /** When the code stops working. */
  expiresAt: Date;
  /**
   * Poll the token endpoint until the user approves, denies or the code expires,
   * honouring `interval` and `slow_down`. Rejects with an `AuthError`.
   */
  waitForApproval(signal?: AbortSignal): Promise<TokenGrant>;
}

/** A Galaxy that issues tokens through the device flow (found by RFC 8414 discovery). */
export interface AuthServer {
  readonly issuer: string;
  /** False when the metadata lists no device endpoint (the instance has the device flow off). */
  readonly supportsDeviceFlow: boolean;
  /** False when the metadata lists no revocation endpoint. */
  readonly supportsRevocation: boolean;
  startDeviceLogin(scopes?: string[]): Promise<PendingDeviceLogin>;
  /** RFC 7009. Resolves when the server accepted the request. */
  revoke(token: string): Promise<void>;
}

export type AuthErrorKind =
  /** The Galaxy publishes no OAuth metadata, or has the device flow switched off. */
  | "unsupported"
  /** The user denied the request on the approval page. */
  | "denied"
  /** The user code expired before anyone approved it. */
  | "expired"
  /** No stored login for this Galaxy, or it has expired, or Galaxy rejected the token. */
  | "not_logged_in"
  /** Several stored logins and no way to tell which Galaxy was meant. */
  | "ambiguous_host"
  /** Plain http to a host other than loopback, or an issuer that is not this Galaxy. */
  | "insecure"
  /** The server answered, but not as the RFCs say it should. */
  | "protocol"
  /** The server could not be reached. */
  | "network"
  /** A flag or argument the user can fix. */
  | "usage";

export class AuthError extends Error {
  constructor(
    readonly kind: AuthErrorKind,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "AuthError";
  }
}

/** The user Galaxy says a token belongs to. */
export interface WhoAmI {
  username: string;
  email?: string;
}

export interface AuthIo {
  stdin: NodeJS.ReadableStream;
  /** Machine-readable output only: a token, `export` lines, a JSON object. */
  stdout: { write(s: string): void };
  /** Everything meant for a person. */
  stderr: { write(s: string): void };
  /** stdin and stderr are both terminals, so it is safe to prompt and wait for Enter. */
  interactive: boolean;
}

export interface AuthDeps {
  store: CredentialStore;
  /** RFC 8414 discovery against the Galaxy at `baseUrl`. Rejects with an `AuthError`. */
  discover(baseUrl: BaseUrl): Promise<AuthServer>;
  /**
   * Ask Galaxy whose token this is (`GET /api/users/current` through galaxy-ops' `get_user`).
   * Rejects with `AuthError("not_logged_in")` when Galaxy refuses the token or answers with
   * the anonymous user (no username), which is what it does for a session without a valid key.
   */
  whoami(baseUrl: BaseUrl, token: string): Promise<WhoAmI>;
  /**
   * Which Galaxy a command means: the explicit `--host`, else `GALAXY_URL`, else the only
   * stored login. Rejects with `AuthError("ambiguous_host")` listing the stored hosts when
   * several are stored and none was named, and `AuthError("usage")` when none is stored.
   */
  resolveHost(explicit?: string): Promise<BaseUrl>;
  /** Open a URL in the user's browser. Resolves false when there is no browser to open. */
  openBrowser(url: string): Promise<boolean>;
  /** Whether `openBrowser` has any chance (a display exists). Absent means "assume yes". */
  canOpenBrowser?(): boolean;
  now(): Date;
  env: Record<string, string | undefined>;
  io: AuthIo;
  /** The name the user typed (`gxy` or `galaxy-cli`), for messages like "run gxy auth login". */
  commandName: string;
}
