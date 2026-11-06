/**
 * A fake Galaxy for testing `gxy auth`: an RFC 8414 authorization server (device flow,
 * token, revocation) plus `GET /api/users/current`, on a `node:http` server bound to
 * 127.0.0.1 with an OS-assigned port. It speaks the contract proposed to Galaxy upstream:
 *
 * - metadata at `/.well-known/oauth-authorization-server<prefix>` (RFC 8414 path
 *   insertion, so a Galaxy under `/galaxy` is found at `.../oauth-authorization-server/galaxy`);
 *   the issuer is the base URL
 * - public client `galaxy-cli` (no secret; `token_endpoint_auth_methods_supported: ["none"]`)
 * - RFC 8628 device authorization, without `verification_uri_complete`
 * - a token endpoint answering `authorization_pending`, `slow_down`, `access_denied`,
 *   `expired_token`, or the token
 * - RFC 7009 revocation
 * - `/api/users/current`, which knows a user only by a token this server issued and has not
 *   revoked or expired; any other key gets what Galaxy gives a session without a valid key
 *
 * Everything a test needs to steer is a method on the returned object (approve, deny,
 * expire, slowDown, ...), and every request is recorded in `requests`. Tokens are obviously
 * fake (`fake-access-token-N`).
 *
 *   const galaxy = await startFakeGalaxy();
 *   const code = galaxy.pendingCodes()[0];   // after startDeviceLogin
 *   galaxy.approve(code, { scopes: ["read"], expiresIn: 3600 });
 *   ...
 *   await galaxy.close();
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeGalaxyOptions {
  /** Serve Galaxy under this path prefix, e.g. `/galaxy`. Default none. */
  pathPrefix?: string;
  /** Seconds the server asks clients to wait between polls. Fractions are fine for fast tests. Default 0.01. */
  interval?: number;
  /** Seconds a user code lives. Default 600. */
  deviceExpiresIn?: number;
  /** Start with the device flow off (metadata has no `device_authorization_endpoint`). */
  deviceFlow?: boolean;
  /** Start with no `revocation_endpoint` in the metadata. */
  revocationEndpoint?: boolean;
}

export interface Approval {
  /** Scopes granted; `undefined` makes the token response omit `scope`. Default `[]`. */
  scopes?: string[];
  /** Token lifetime in seconds; `null` omits `expires_in`. Default 3600. */
  expiresIn?: number | null;
  username?: string;
  email?: string;
  /** Make `/api/users/current` report `is_admin: true` for this token. */
  admin?: boolean;
}

export interface RecordedRequest {
  method: string;
  /** Path and query as sent, including any prefix. */
  url: string;
  /** Lower-cased header names. */
  headers: Record<string, string | string[] | undefined>;
  /** Raw body. */
  body: string;
  /** The body parsed as `application/x-www-form-urlencoded` (empty when there is none). */
  form: Record<string, string>;
  /** `performance.now()` at arrival, for asserting poll intervals. */
  at: number;
}

/** How `/.well-known/oauth-authorization-server...` answers. */
export type VersionMode = "ok" | "redirect" | "html";

export type MetadataMode = "ok" | "not-found" | "not-json" | "malformed" | "wrong-issuer";

export interface FakeGalaxy {
  /** `http://127.0.0.1:<port><pathPrefix>`: the Galaxy base URL and the issuer. */
  readonly baseUrl: string;
  readonly requests: RecordedRequest[];
  /** Requests whose URL ends with `suffix` (a path such as `/oauth/token`). */
  requestsTo(suffix: string): RecordedRequest[];
  /** User codes issued and not yet approved, denied or expired, oldest first. */
  pendingCodes(): string[];
  /** The most recent user code issued. */
  lastUserCode(): string;
  approve(userCode: string, approval?: Approval): void;
  deny(userCode: string): void;
  /** The code stops working: the token endpoint answers `expired_token`. */
  expire(userCode: string): void;
  /** The next `n` token polls answer `slow_down` (before anything else). */
  slowDown(n: number): void;
  setDeviceFlow(on: boolean): void;
  setRevocationEndpoint(on: boolean): void;
  setMetadataMode(mode: MetadataMode): void;
  /** What `/api/users/current` says for an unknown key: 200 with the anonymous shape (default), or 403. */
  /** What `/api/version` answers: the version (default), a 302 to another origin, or an HTML page. */
  setVersionMode(mode: VersionMode): void;
  setInvalidKeyResponse(kind: "anonymous" | "forbidden"): void;
  /** Make the device authorization endpoint answer this response instead (e.g. malformed JSON). */
  setDeviceAuthorizationOverride(r: { status: number; body: string; contentType?: string } | null): void;
  /** Make the token endpoint answer this response whenever the code is not otherwise resolved. */
  setTokenOverride(r: { status: number; body: string; contentType?: string } | null): void;
  /** Revoke from the server side, as an admin or expiry would. */
  revokeToken(token: string): void;
  /** Tokens issued so far, in order. */
  issuedTokens(): string[];
  /** Whether this token would be accepted by `/api/users/current` right now. */
  isTokenValid(token: string): boolean;
  /** The metadata URL a client should fetch, for assertions. */
  readonly metadataUrl: string;
  close(): Promise<void>;
}

interface DeviceEntry {
  userCode: string;
  deviceCode: string;
  expiresAtMs: number;
  state: "pending" | "approved" | "denied" | "expired";
  approval?: Approval;
  consumed: boolean;
}

interface TokenEntry {
  token: string;
  username: string;
  email: string;
  admin: boolean;
  expiresAtMs: number | null;
  revoked: boolean;
}

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

export async function startFakeGalaxy(options: FakeGalaxyOptions = {}): Promise<FakeGalaxy> {
  const prefix = (options.pathPrefix ?? "").replace(/\/+$/, "");
  const interval = options.interval ?? 0.01;
  const deviceExpiresIn = options.deviceExpiresIn ?? 600;
  let deviceFlow = options.deviceFlow ?? true;
  let revocation = options.revocationEndpoint ?? true;
  let metadataMode: MetadataMode = "ok";
  let versionMode: VersionMode = "ok";
  let invalidKey: "anonymous" | "forbidden" = "anonymous";
  let deviceOverride: { status: number; body: string; contentType?: string } | null = null;
  let tokenOverride: { status: number; body: string; contentType?: string } | null = null;
  let slowDowns = 0;

  const requests: RecordedRequest[] = [];
  const devices = new Map<string, DeviceEntry>(); // by user code
  const tokens = new Map<string, TokenEntry>();
  let counter = 0;
  let baseUrl = "";

  const json = (res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...extra });
    res.end(JSON.stringify(body));
  };
  const raw = (res: ServerResponse, r: { status: number; body: string; contentType?: string }) => {
    res.writeHead(r.status, { "content-type": r.contentType ?? "application/json" });
    res.end(r.body);
  };

  const metadata = () => ({
    issuer: metadataMode === "wrong-issuer" ? "https://not-this-galaxy.example" : baseUrl,
    ...(deviceFlow ? { device_authorization_endpoint: `${baseUrl}/oauth/device_authorization` } : {}),
    token_endpoint: `${baseUrl}/oauth/token`,
    ...(revocation ? { revocation_endpoint: `${baseUrl}/oauth/revoke` } : {}),
    grant_types_supported: deviceFlow ? [DEVICE_GRANT] : [],
    scopes_supported: ["read", "write"],
    token_endpoint_auth_methods_supported: ["none"],
  });

  const tokenIsValid = (t: TokenEntry | undefined): t is TokenEntry =>
    !!t && !t.revoked && (t.expiresAtMs === null || t.expiresAtMs > Date.now());

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString("utf8");
    const form: Record<string, string> = {};
    if ((req.headers["content-type"] ?? "").includes("application/x-www-form-urlencoded")) {
      for (const [k, v] of new URLSearchParams(body)) form[k] = v;
    }
    requests.push({ method: req.method ?? "GET", url: req.url ?? "", headers: { ...req.headers }, body, form, at: performance.now() });

    const path = new URL(req.url ?? "/", "http://x").pathname;
    const method = req.method ?? "GET";

    if (method === "GET" && path === `/.well-known/oauth-authorization-server${prefix}`) {
      switch (metadataMode) {
        case "not-found":
          return json(res, 404, { err_msg: "Not found" });
        case "not-json":
          res.writeHead(200, { "content-type": "text/html" });
          return void res.end("<html>Galaxy</html>");
        case "malformed":
          res.writeHead(200, { "content-type": "application/json" });
          return void res.end("{not json");
        default:
          return json(res, 200, metadata());
      }
    }
    if (!path.startsWith(prefix + "/") && path !== prefix) return json(res, 404, { err_msg: "Not found" });
    const local = path.slice(prefix.length);

    if (method === "POST" && local === "/oauth/device_authorization") {
      if (!deviceFlow) return json(res, 404, { err_msg: "Not found" });
      if (deviceOverride) return raw(res, deviceOverride);
      if (!form.client_id) return json(res, 400, { error: "invalid_client" });
      counter += 1;
      const entry: DeviceEntry = {
        userCode: `FAKE-${String(counter).padStart(4, "0")}`,
        deviceCode: `fake-device-code-${counter}`,
        expiresAtMs: Date.now() + deviceExpiresIn * 1000,
        state: "pending",
        consumed: false,
      };
      devices.set(entry.userCode, entry);
      return json(res, 200, {
        device_code: entry.deviceCode,
        user_code: entry.userCode,
        verification_uri: `${baseUrl}/oauth/device`,
        expires_in: deviceExpiresIn,
        interval,
      });
    }

    if (method === "POST" && local === "/oauth/token") {
      if (form.grant_type !== DEVICE_GRANT) return json(res, 400, { error: "unsupported_grant_type" });
      const entry = [...devices.values()].find((d) => d.deviceCode === form.device_code);
      if (!entry) return json(res, 400, { error: "invalid_grant" });
      if (slowDowns > 0) {
        slowDowns -= 1;
        return json(res, 400, { error: "slow_down" });
      }
      if (entry.state === "pending" && Date.now() >= entry.expiresAtMs) entry.state = "expired";
      if (entry.state === "pending") {
        if (tokenOverride) return raw(res, tokenOverride);
        return json(res, 400, { error: "authorization_pending" });
      }
      if (entry.state === "denied") return json(res, 400, { error: "access_denied" });
      if (entry.state === "expired") return json(res, 400, { error: "expired_token" });
      if (entry.consumed) return json(res, 400, { error: "invalid_grant" });
      entry.consumed = true;
      const a = entry.approval ?? {};
      const expiresIn = a.expiresIn === undefined ? 3600 : a.expiresIn;
      const token = `fake-access-token-${tokens.size + 1}`;
      tokens.set(token, {
        token,
        username: a.username ?? "fake-user",
        email: a.email ?? "fake-user@example.org",
        admin: a.admin ?? false,
        expiresAtMs: expiresIn === null ? null : Date.now() + expiresIn * 1000,
        revoked: false,
      });
      return json(res, 200, {
        access_token: token,
        token_type: "Bearer",
        ...(expiresIn === null ? {} : { expires_in: expiresIn }),
        ...(a.scopes === undefined ? {} : { scope: a.scopes.join(" ") }),
      });
    }

    if (method === "POST" && local === "/oauth/revoke") {
      if (!revocation) return json(res, 404, { err_msg: "Not found" });
      const t = tokens.get(form.token ?? "");
      if (t) t.revoked = true;
      // RFC 7009 §2.2: 200 even for tokens the server does not know.
      res.writeHead(200, { "content-length": "0" });
      return void res.end();
    }

    if (method === "GET" && local === "/api/version") {
      if (versionMode === "redirect") return void (res.writeHead(302, { location: "https://elsewhere.example/api/version" }), res.end());
      if (versionMode === "html") {
        res.writeHead(200, { "content-type": "text/html" });
        return void res.end("<html>Please log in</html>");
      }
      return json(res, 200, { version_major: "24.2", version_minor: "0" });
    }

    if (method === "GET" && local === "/api/users/current") {
      const key = req.headers["x-api-key"];
      const t = typeof key === "string" ? tokens.get(key) : undefined;
      if (tokenIsValid(t)) return json(res, 200, { id: `fake-id-${t.username}`, username: t.username, email: t.email, is_admin: t.admin });
      if (invalidKey === "forbidden") return json(res, 403, { err_code: 403001, err_msg: "API authentication required for this request" });
      return json(res, 200, { total_disk_usage: 0, nice_total_disk_usage: "0 bytes", quota_percent: null });
    }

    return json(res, 404, { err_msg: "Not found" });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      res.writeHead(500);
      res.end(String(err));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}${prefix}`;

  const entryFor = (userCode: string): DeviceEntry => {
    const e = devices.get(userCode);
    if (!e) throw new Error(`fake galaxy: unknown user code ${userCode}`);
    return e;
  };

  return {
    baseUrl,
    requests,
    requestsTo: (suffix) => requests.filter((r) => new URL(r.url, "http://x").pathname.endsWith(suffix)),
    pendingCodes: () => [...devices.values()].filter((d) => d.state === "pending").map((d) => d.userCode),
    lastUserCode: () => [...devices.keys()].at(-1) ?? "",
    approve(userCode, approval = {}) {
      const e = entryFor(userCode);
      e.state = "approved";
      e.approval = { scopes: [], ...approval };
    },
    deny: (userCode) => void (entryFor(userCode).state = "denied"),
    expire: (userCode) => void (entryFor(userCode).state = "expired"),
    slowDown: (n) => void (slowDowns = n),
    setDeviceFlow: (on) => void (deviceFlow = on),
    setRevocationEndpoint: (on) => void (revocation = on),
    setMetadataMode: (m) => void (metadataMode = m),
    setVersionMode: (m) => void (versionMode = m),
    setInvalidKeyResponse: (k) => void (invalidKey = k),
    setDeviceAuthorizationOverride: (r) => void (deviceOverride = r),
    setTokenOverride: (r) => void (tokenOverride = r),
    revokeToken(token) {
      const t = tokens.get(token);
      if (t) t.revoked = true;
    },
    issuedTokens: () => [...tokens.keys()],
    isTokenValid: (token) => tokenIsValid(tokens.get(token)),
    get metadataUrl() {
      return `${new URL(baseUrl).origin}/.well-known/oauth-authorization-server${prefix}`;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
