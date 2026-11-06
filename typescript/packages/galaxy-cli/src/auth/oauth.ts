import * as client from "openid-client";
import { isLoopback } from "./base-url";
import { describeNetworkError, isTlsError } from "./network";
import { sanitize } from "./sanitize";
import { AuthError, CLIENT_ID, type AuthServer, type BaseUrl, type PendingDeviceLogin, type TokenGrant } from "./types";

export interface DiscoverOptions {
  /** OAuth client id to present. Default `CLIENT_ID`; callers feed `GXY_OAUTH_CLIENT_ID` here. */
  clientId?: string;
  /** Replaces `fetch` for every request (tests, proxies). */
  fetch?: typeof fetch;
  /** Cancels every request made through the returned server, discovery included. */
  signal?: AbortSignal;
}

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

/** The endpoints that carry a token or a device code, and so must be on the issuer's own origin. */
const ENDPOINTS_ON_ISSUER_ORIGIN = ["device_authorization_endpoint", "token_endpoint", "revocation_endpoint"] as const;

/**
 * `fetch` with two guards of our own. Plain http goes only to a loopback address, however
 * the library was configured (its `allowInsecureRequests` is all-or-nothing). And the
 * caller's signal cancels every request.
 */
function guardedFetch(base: typeof fetch, signal: AbortSignal | undefined): typeof fetch {
  return (input, init) => {
    const target = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (target.protocol === "http:" && !isLoopback(target.hostname)) {
      return Promise.reject(new AuthError("insecure", `Refusing plain http to ${target.host}: a token would cross the network unencrypted.`));
    }
    const combined = signal && init?.signal ? AbortSignal.any([signal, init.signal]) : (signal ?? init?.signal ?? undefined);
    return base(input, { ...init, signal: combined });
  };
}

/** Transient failures worth another poll: no answer, a timeout, a 5xx or a 429. Never TLS trouble. */
function transientDelayMs(err: unknown): number | undefined {
  const retryAfter = (response: Response | undefined): number => {
    const v = Number(response?.headers.get("retry-after"));
    return Number.isFinite(v) && v > 0 ? v * 1000 : 0;
  };
  const retryableStatus = (r: Response | undefined) => r !== undefined && (r.status >= 500 || r.status === 429);
  if (err instanceof client.ResponseBodyError) return retryableStatus(err.response) ? retryAfter(err.response) : undefined;
  if (err instanceof client.ClientError) {
    const response = err.cause instanceof Response ? err.cause : undefined;
    return retryableStatus(response) ? retryAfter(response) : undefined;
  }
  if (err instanceof TypeError) return isTlsError(err) ? undefined : 0;
  if (err instanceof Error && err.name === "TimeoutError") return 0;
  return undefined;
}

/** Sleep that ends early, rejecting, when the signal aborts. */
function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      done();
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      done();
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * RFC 8414 discovery against the Galaxy at `baseUrl` (its issuer), returning the device flow
 * and revocation as an `AuthServer`.
 *
 * The client is public: it holds no secret and says so (`None()`), so there is nothing to leak
 * to a server that asks. Plain http is allowed only to a loopback host, for a Galaxy on this
 * machine; `normalizeBaseUrl` already refuses it elsewhere, and this checks again because a
 * token is what is at stake.
 *
 * Every failure is an `AuthError`; see `types.ts` for what each kind means.
 */
export async function discover(baseUrl: BaseUrl, options: DiscoverOptions = {}): Promise<AuthServer> {
  const url = new URL(baseUrl);
  const loopback = isLoopback(url.hostname);
  if (url.protocol === "http:" && !loopback) {
    throw new AuthError("insecure", `Refusing plain http to ${url.host}: a token would cross the network unencrypted.`);
  }
  const clientId = options.clientId || CLIENT_ID;

  const fetchImpl = guardedFetch(options.fetch ?? globalThis.fetch, options.signal);
  let config: client.Configuration;
  try {
    config = await client.discovery(url, clientId, undefined, client.None(), {
      algorithm: "oauth2",
      [client.customFetch]: fetchImpl,
      // The library applies this to every request; `guardedFetch` narrows it to loopback URLs.
      ...(loopback ? { execute: [client.allowInsecureRequests] } : {}),
    });
  } catch (err) {
    if (options.signal?.aborted) throw options.signal.reason ?? err;
    throw mapError(err, "discovery", baseUrl);
  }

  const meta = config.serverMetadata();
  // Logout sends the token to `revocation_endpoint` and polling sends the device code to
  // `token_endpoint`: none may point anywhere but the Galaxy that was asked.
  for (const name of ENDPOINTS_ON_ISSUER_ORIGIN) {
    const value = meta[name];
    if (typeof value !== "string") continue;
    let origin: string | undefined;
    try {
      origin = new URL(value).origin;
    } catch {
      /* falls through to the refusal */
    }
    if (origin !== url.origin) {
      throw new AuthError("insecure", `${baseUrl} publishes its ${name} on another origin (${sanitize(origin ?? "not a URL")}), so no token or code was sent.`);
    }
  }
  const supportsDeviceFlow = typeof meta.device_authorization_endpoint === "string";
  const supportsRevocation = typeof meta.revocation_endpoint === "string";

  return {
    issuer: meta.issuer,
    supportsDeviceFlow,
    supportsRevocation,

    async startDeviceLogin(scopes) {
      if (!supportsDeviceFlow) {
        throw new AuthError("unsupported", `${baseUrl} does not offer the device login flow.`);
      }
      // A cancel during discovery must not leave a code waiting on the server.
      options.signal?.throwIfAborted();
      const requested = scopes ?? [];
      let response: Awaited<ReturnType<typeof client.initiateDeviceAuthorization>>;
      try {
        response = await client.initiateDeviceAuthorization(config, requested.length ? { scope: requested.join(" ") } : {});
      } catch (err) {
        if (options.signal?.aborted) throw options.signal.reason ?? err;
        throw mapError(err, "device", baseUrl);
      }
      const expiresAt = new Date(Date.now() + response.expires_in * 1000);

      const pending: PendingDeviceLogin = {
        userCode: response.user_code,
        verificationUri: response.verification_uri,
        expiresAt,
        async waitForApproval(signal) {
          // openid-client's default deadline is expires_in, but giving it a signal replaces
          // that, so the deadline is ours: either the caller aborts or the code expires.
          // A plain timer, cleared below, rather than `AbortSignal.timeout`: tests can fake it.
          const deadlineControl = new AbortController();
          const deadlineTimer = setTimeout(() => deadlineControl.abort(), Math.max(0, expiresAt.getTime() - Date.now()));
          const deadline = deadlineControl.signal;
          const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
          // RFC 8628 §3.5: poll every `interval` seconds (default 5), 5 more after `slow_down`.
          // The loop is ours, not openid-client's, because its waits ignore the signal for up
          // to 5 s and its timers keep the process alive after a Ctrl-C.
          let intervalMs = (response.interval ?? 5) * 1000;
          let failures = 0;
          let delayMs = intervalMs;
          try {
            for (;;) {
              try {
                await sleep(delayMs, combined);
              } catch (e) {
                if (signal?.aborted) throw signal.reason ?? e;
                throw new AuthError("expired", "The login code expired before it was approved.", { cause: e });
              }
              try {
                const tokens = await client.genericGrantRequest(config, DEVICE_GRANT, { device_code: response.device_code });
                return toGrant(tokens, requested);
              } catch (err) {
                if (signal?.aborted) throw signal.reason ?? err;
                if (deadline.aborted) throw new AuthError("expired", "The login code expired before it was approved.", { cause: err });
                if (err instanceof client.ResponseBodyError && (err.error === "authorization_pending" || err.error === "slow_down")) {
                  if (err.error === "slow_down") intervalMs += 5000;
                  failures = 0;
                  delayMs = intervalMs;
                  continue;
                }
                const transient = transientDelayMs(err);
                if (transient === undefined) throw mapError(err, "poll", baseUrl);
                failures += 1;
                // Modest exponential backoff, and never sooner than the server asked.
                delayMs = Math.max(intervalMs, transient, Math.min(60_000, intervalMs * 2 ** failures));
              }
            }
          } finally {
            clearTimeout(deadlineTimer);
          }
        },
      };
      return pending;
    },

    async revoke(token) {
      if (!supportsRevocation) {
        throw new AuthError("unsupported", `${baseUrl} does not publish a revocation endpoint.`);
      }
      try {
        await client.tokenRevocation(config, token, { token_type_hint: "access_token" });
      } catch (err) {
        throw mapError(err, "revoke", baseUrl);
      }
    },
  };
}

function toGrant(tokens: client.TokenEndpointResponse, requested: string[]): TokenGrant {
  if (typeof tokens.access_token !== "string" || !tokens.access_token) {
    throw new AuthError("protocol", "The token response had no access token.");
  }
  // RFC 6749 §5.1: `scope` is omitted when it equals what was requested.
  const scopes = typeof tokens.scope === "string" ? tokens.scope.split(/\s+/).filter(Boolean) : [...requested];
  return {
    accessToken: tokens.access_token,
    ...(typeof tokens.expires_in === "number" ? { expiresIn: tokens.expires_in } : {}),
    scopes,
  };
}

type Phase = "discovery" | "device" | "poll" | "revoke";

/** Turn whatever openid-client threw into an `AuthError` of the right kind. */
function mapError(err: unknown, phase: Phase, baseUrl: string): AuthError {
  if (err instanceof AuthError) return err;
  // Server text reaches these messages (error texts, response excerpts), and they get printed.
  const detail = sanitize(err instanceof Error ? err.message : String(err));

  if (err instanceof client.ResponseBodyError) {
    switch (err.error) {
      case "access_denied":
        return new AuthError("denied", "The login was denied on the approval page.", { cause: err });
      case "expired_token":
        return new AuthError("expired", "The login code expired before it was approved.", { cause: err });
      default:
        return new AuthError("protocol", `${baseUrl} refused the request: ${sanitize(err.error)}${err.error_description ? ` (${sanitize(err.error_description)})` : ""}.`, { cause: err });
    }
  }

  if (err instanceof client.ClientError) {
    switch (err.code) {
      case "OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED":
        return new AuthError("insecure", `${baseUrl} publishes OAuth metadata for a different issuer, so it cannot be trusted.`, { cause: err });
      case "OAUTH_HTTP_REQUEST_FORBIDDEN":
      case "OAUTH_REQUEST_PROTOCOL_FORBIDDEN":
        return new AuthError("insecure", `Refusing plain http to ${baseUrl}.`, { cause: err });
      case "OAUTH_RESPONSE_IS_NOT_CONFORM":
      case "OAUTH_RESPONSE_IS_NOT_JSON":
        if (phase === "discovery") {
          return new AuthError("unsupported", `${baseUrl} publishes no OAuth metadata (${detail}).`, { cause: err });
        }
        return new AuthError("protocol", `${baseUrl} answered unexpectedly (${detail}).`, { cause: err });
      default:
        return new AuthError("protocol", `${baseUrl} sent a response that does not follow the OAuth specs (${detail}).`, { cause: err });
    }
  }

  // fetch failures (refused, DNS, reset, timeout) surface as TypeError or a timeout DOMException.
  if (err instanceof TypeError || (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError"))) {
    return new AuthError("network", describeNetworkError(err, baseUrl), { cause: err });
  }
  return new AuthError("protocol", `Unexpected failure talking to ${baseUrl}: ${detail}.`, { cause: err });
}
