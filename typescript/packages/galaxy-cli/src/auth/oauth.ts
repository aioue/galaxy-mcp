import * as client from "openid-client";
import { isLoopback } from "./base-url";
import { describeNetworkError } from "./network";
import { sanitize } from "./sanitize";
import { AuthError, CLIENT_ID, type AuthServer, type BaseUrl, type PendingDeviceLogin, type TokenGrant } from "./types";

export interface DiscoverOptions {
  /** OAuth client id to present. Default `CLIENT_ID`; callers feed `GXY_OAUTH_CLIENT_ID` here. */
  clientId?: string;
  /** Replaces `fetch` for every request (tests, proxies). */
  fetch?: typeof fetch;
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

  let config: client.Configuration;
  try {
    config = await client.discovery(url, clientId, undefined, client.None(), {
      algorithm: "oauth2",
      ...(options.fetch ? { [client.customFetch]: options.fetch } : {}),
      ...(loopback ? { execute: [client.allowInsecureRequests] } : {}),
    });
  } catch (err) {
    throw mapError(err, "discovery", baseUrl);
  }

  const meta = config.serverMetadata();
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
      const requested = scopes ?? [];
      let response: Awaited<ReturnType<typeof client.initiateDeviceAuthorization>>;
      try {
        response = await client.initiateDeviceAuthorization(config, requested.length ? { scope: requested.join(" ") } : {});
      } catch (err) {
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
          const deadline = AbortSignal.timeout(Math.max(0, expiresAt.getTime() - Date.now()));
          const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
          try {
            // openid-client waits `interval` before each poll and adds 5 s on `slow_down`.
            const tokens = await client.pollDeviceAuthorizationGrant(config, response, undefined, { signal: combined });
            return toGrant(tokens, requested);
          } catch (err) {
            if (signal?.aborted) throw signal.reason ?? err;
            if (deadline.aborted) throw new AuthError("expired", "The login code expired before it was approved.", { cause: err });
            throw mapError(err, "poll", baseUrl);
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
