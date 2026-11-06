import { createGalaxyContext, getUser } from "@galaxyproject/galaxy-ops";
import { AuthError, type BaseUrl, type WhoAmI } from "./types";
import { USER_AGENT } from "./user-agent";

type FetchImpl = typeof fetch;

const PROBE_TIMEOUT_MS = 15_000;

/**
 * Check, with no credentials at all, that `baseUrl` is a Galaxy's API before any token is
 * sent there. A Galaxy behind a `remote_user` proxy answers an HTML login page, and a wrong
 * URL often redirects (http to https, a missing path prefix): sending a key along would hand
 * it to whatever answers. Redirects are never followed; the `Location` is offered as a fix.
 */
export async function probeGalaxy(baseUrl: BaseUrl, fetchImpl: FetchImpl = globalThis.fetch): Promise<void> {
  const url = `${baseUrl}/api/version`;
  let res: Response;
  try {
    res = await fetchImpl(url, {
      redirect: "manual",
      headers: { accept: "application/json", "user-agent": USER_AGENT },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
  } catch (e) {
    const cause = e instanceof Error && e.cause instanceof Error ? e.cause.message : e instanceof Error ? e.message : String(e);
    throw new AuthError("network", `Could not reach ${baseUrl}: ${cause}.`, { cause: e });
  }
  if (res.status >= 300 && res.status < 400) {
    const where = res.headers.get("location");
    throw new AuthError(
      "protocol",
      `${baseUrl} redirects (HTTP ${res.status}) instead of answering, so no token was sent.` +
        (where ? ` Did you mean the address it points to: ${stripToApiBase(where, baseUrl)}?` : ""),
    );
  }
  let version: unknown;
  try {
    version = ((await res.json()) as { version_major?: unknown }).version_major;
  } catch {
    version = undefined;
  }
  if (!res.ok || typeof version !== "string") {
    throw new AuthError(
      "protocol",
      `${baseUrl} does not look like a Galaxy API (GET /api/version gave HTTP ${res.status} without a Galaxy version). ` +
        "Check the address, including any path prefix. No token was sent.",
    );
  }
}

/** A redirect target as a base URL suggestion: resolved against the request, `/api/version` removed. */
function stripToApiBase(location: string, baseUrl: string): string {
  try {
    const u = new URL(location, `${baseUrl}/api/version`);
    return `${u.origin}${u.pathname.replace(/\/api\/version\/?$/, "").replace(/\/+$/, "")}`;
  } catch {
    return "(unreadable)";
  }
}

const NOT_LOGGED_IN =
  "Galaxy did not accept the token: it may be invalid, replaced by a newer API key, expired, or belong to a deactivated account.";

/**
 * Ask Galaxy whose token this is, through galaxy-ops' `get_user` (`GET /api/users/current`,
 * which never follows a redirect). Galaxy answers 200 with an anonymous record when no key
 * counts, so success means a real user: JSON with an `id` and a `username` or `email`.
 * The version probe runs first, once per Galaxy, so a token never reaches a non-Galaxy.
 */
export function createWhoami(fetchImpl: FetchImpl = globalThis.fetch) {
  const probed = new Map<string, Promise<void>>();
  return async function whoami(baseUrl: BaseUrl, token: string): Promise<WhoAmI> {
    let probe = probed.get(baseUrl);
    if (!probe) {
      probe = probeGalaxy(baseUrl, fetchImpl);
      probed.set(baseUrl, probe);
      probe.catch(() => probed.delete(baseUrl));
    }
    await probe;

    const ctx = createGalaxyContext({
      baseUrl,
      apiKey: token,
      fetchImpl: (input, init) => {
        const req = new Request(input, init);
        req.headers.set("user-agent", USER_AGENT);
        return fetchImpl(req);
      },
    });
    let user: Awaited<ReturnType<typeof getUser>>;
    try {
      user = await getUser({}, ctx);
    } catch (e) {
      throw mapFailure(e, baseUrl);
    }
    const u = user as { id?: unknown; username?: unknown; email?: unknown; is_admin?: unknown };
    const name = typeof u.username === "string" && u.username ? u.username : typeof u.email === "string" ? u.email : "";
    if (typeof u.id !== "string" || !u.id || !name) throw new AuthError("not_logged_in", NOT_LOGGED_IN);
    return {
      username: name,
      ...(typeof u.email === "string" && u.email ? { email: u.email } : {}),
      isAdmin: u.is_admin === true,
    };
  };
}

function mapFailure(e: unknown, baseUrl: string): AuthError {
  const err = e as { kind?: string; status?: number; http?: { status: number | null } };
  if (err.kind === "connection") {
    const status = err.status ?? err.http?.status;
    if (status == null) return new AuthError("network", `Could not reach ${baseUrl}: ${(e as Error).message}.`, { cause: e });
    if (status >= 500) return new AuthError("network", `${baseUrl} answered HTTP ${status}.`, { cause: e });
  }
  // Auth refusals, redirects, HTML or non-JSON bodies, anything else that is not a user record.
  return new AuthError("not_logged_in", NOT_LOGGED_IN, { cause: e });
}
