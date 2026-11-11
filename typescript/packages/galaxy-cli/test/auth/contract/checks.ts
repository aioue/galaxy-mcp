/**
 * The server contract for `gxy auth`'s device login, as checks over HTTP. Each check throws a
 * `ContractViolation` that names the RFC and says what the server did, and returns normally when
 * the server meets the contract. They use plain `fetch` and nothing from `src/`, so they judge a
 * server, not our client: a server that passes can be logged in to by any RFC 8628 client, and a
 * failure is the server's to fix.
 *
 * Three things are checked, each one a place a server can fail an RFC client that the rest of our
 * tests (which run against a fake that behaves) cannot show:
 *
 * 1. The metadata is where RFC 8414 §3 says (`fetchMetadata`).
 * 2. The metadata advertises `revocation_endpoint`, and RFC 7009 revocation of a token works
 *    (`checkRevocationAdvertised`, `checkRevocationWorks`).
 * 3. `token_type` is honest: the scheme it names is one the token is accepted in
 *    (`checkTokenTypeHonest`).
 *
 * `device-flow-server.contract.test.ts` runs them against the fake Galaxy, or against a real one.
 */

/** A server that does not meet the contract. The message starts with the RFC it breaks. */
export class ContractViolation extends Error {
  override name = "ContractViolation";
}

export interface Metadata {
  issuer: string;
  device_authorization_endpoint?: string;
  token_endpoint?: string;
  revocation_endpoint?: string;
  [key: string]: unknown;
}

/** A token response, as far as the checks read it. */
export interface Grant {
  access_token: string;
  token_type?: string;
}

const WELL_KNOWN = "/.well-known/oauth-authorization-server";
const CLIENT_ID = "galaxy-cli";

const form = (fields: Record<string, string>) => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(fields).toString(),
});

/**
 * Where RFC 8414 §3.1 says the metadata of `baseUrl` lives: `/.well-known/oauth-authorization-server`
 * with the issuer's path appended, so a Galaxy at `https://host/galaxy` has it at
 * `https://host/.well-known/oauth-authorization-server/galaxy`.
 */
export function metadataUrl(baseUrl: string): string {
  const u = new URL(baseUrl);
  return `${u.origin}${WELL_KNOWN}${u.pathname.replace(/\/+$/, "")}`;
}

/**
 * Contract 1. The metadata is served at the RFC 8414 location for the issuer, including the
 * path-inserted form for a Galaxy under a prefix, and its `issuer` is the Galaxy's own URL.
 */
export async function fetchMetadata(baseUrl: string): Promise<Metadata> {
  const url = metadataUrl(baseUrl);
  const hint = new URL(baseUrl).pathname.replace(/\/+$/, "")
    ? ` The issuer has a path, so RFC 8414 §3.1 inserts it after the well-known string; serving the document only inside the prefix (${baseUrl.replace(/\/+$/, "")}${WELL_KNOWN}) leaves every RFC 8414 client unable to find it.`
    : "";
  let res: Response;
  try {
    res = await fetch(url, {
      redirect: "manual",
      headers: { accept: "application/json" },
    });
  } catch (e) {
    throw new ContractViolation(
      `RFC 8414 §3.1: could not reach the metadata at ${url}: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (res.status !== 200)
    throw new ContractViolation(
      `RFC 8414 §3.1: expected the authorization server metadata at ${url}, got HTTP ${res.status}.${hint}`,
    );
  let metadata: Metadata;
  try {
    metadata = (await res.json()) as Metadata;
  } catch {
    throw new ContractViolation(`RFC 8414 §3.2: ${url} answered 200, but not with JSON.`);
  }
  if (typeof metadata.issuer !== "string")
    throw new ContractViolation(`RFC 8414 §2: the metadata at ${url} has no "issuer".`);
  // §3.3: the issuer in the document must be the one the document was fetched for.
  if (metadata.issuer.replace(/\/+$/, "") !== baseUrl.replace(/\/+$/, ""))
    throw new ContractViolation(
      `RFC 8414 §3.3: the metadata at ${url} says issuer "${metadata.issuer}", not "${baseUrl.replace(/\/+$/, "")}".`,
    );
  for (const field of ["device_authorization_endpoint", "token_endpoint"] as const)
    if (typeof metadata[field] !== "string")
      throw new ContractViolation(
        `RFC 8628 §4: the metadata at ${url} has no "${field}", so a client cannot start a device login.`,
      );
  return metadata;
}

/** Contract 2a. The metadata advertises where a token is revoked. */
export function checkRevocationAdvertised(metadata: Metadata): void {
  if (typeof metadata.revocation_endpoint !== "string")
    throw new ContractViolation(
      `RFC 8414 §2 / RFC 7009 §2: the metadata has no "revocation_endpoint", so a client cannot take a token back. \`gxy auth logout\` can then only forget the token locally, which stays valid on the server.`,
    );
}

/** The user a key identifies, or `null` when Galaxy takes it for nobody (an anonymous 200, or a refusal). */
export async function whoami(
  baseUrl: string,
  headers: Record<string, string>,
): Promise<string | null> {
  const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/api/users/current`, {
    headers,
    redirect: "manual",
  });
  if (res.status !== 200) return null;
  const body = (await res.json().catch(() => ({}))) as { username?: unknown };
  return typeof body.username === "string" ? body.username : null;
}

/** The token is one `gxy` can use: Galaxy takes it in `x-api-key`, the only header the client sends. */
async function requireUsableAsApiKey(baseUrl: string, token: string): Promise<void> {
  if ((await whoami(baseUrl, { "x-api-key": token })) === null)
    // Not a verdict on the server: the suite was given a token Galaxy does not know.
    throw new Error(
      `Galaxy does not know the token as x-api-key, so nothing can be checked with it.`,
    );
}

/**
 * Contract 2b. RFC 7009 revocation of an issued token succeeds (200, §2.2) and the token is
 * rejected afterwards. This kills the token it is given.
 */
export async function checkRevocationWorks(
  baseUrl: string,
  metadata: Metadata,
  grant: Grant,
): Promise<void> {
  checkRevocationAdvertised(metadata);
  await requireUsableAsApiKey(baseUrl, grant.access_token);
  const res = await fetch(
    metadata.revocation_endpoint!,
    form({
      token: grant.access_token,
      token_type_hint: "access_token",
      client_id: CLIENT_ID,
    }),
  );
  if (res.status !== 200)
    throw new ContractViolation(
      `RFC 7009 §2.2: revoking a valid token at ${metadata.revocation_endpoint} answered HTTP ${res.status}, not 200.`,
    );
  if ((await whoami(baseUrl, { "x-api-key": grant.access_token })) !== null)
    throw new ContractViolation(
      `RFC 7009 §2.2: the token still identifies a user after the revocation endpoint accepted it.`,
    );
}

/**
 * Contract 3. `token_type` is present (RFC 6749 §5.1) and names a scheme the token works in. For
 * `Bearer`, that is `Authorization: Bearer <token>` (RFC 6750 §2.1). A token that works only as
 * `x-api-key` has to say so, or a client that does what the response says is refused.
 */
export async function checkTokenTypeHonest(baseUrl: string, grant: Grant): Promise<void> {
  await requireUsableAsApiKey(baseUrl, grant.access_token);
  if (typeof grant.token_type !== "string")
    throw new ContractViolation(
      `RFC 6749 §5.1: the token response has no "token_type", which it must have.`,
    );
  if (grant.token_type.toLowerCase() !== "bearer")
    throw new ContractViolation(
      `RFC 6749 §7.1: the token response says token_type "${grant.token_type}", a scheme this suite cannot present. Only Bearer is defined for Galaxy.`,
    );
  const user = await whoami(baseUrl, {
    authorization: `Bearer ${grant.access_token}`,
  });
  if (user === null)
    throw new ContractViolation(
      `RFC 6750 §2.1: the token response says token_type "${grant.token_type}", but Galaxy does not accept the token as "Authorization: Bearer <token>" (it does as x-api-key). A client that sends what token_type says is refused.`,
    );
}

/**
 * Run the RFC 8628 device flow with plain `fetch` and return the token response. `onUserCode`
 * is told the user code and where to enter it, and has to get it approved (a person in a browser,
 * or the fake's `approve`).
 */
export async function obtainGrant(
  metadata: Metadata,
  onUserCode: (d: { user_code: string; verification_uri: string }) => void | Promise<void>,
  { timeoutMs = 15 * 60_000 }: { timeoutMs?: number } = {},
): Promise<Grant> {
  const started = await fetch(
    metadata.device_authorization_endpoint!,
    form({ client_id: CLIENT_ID }),
  );
  if (started.status !== 200)
    throw new ContractViolation(
      `RFC 8628 §3.2: the device authorization request answered HTTP ${started.status}, not 200.`,
    );
  const device = (await started.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    interval?: number;
  };
  await onUserCode(device);
  let intervalMs = Math.max(device.interval ?? 5, 0.01) * 1000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, intervalMs));
    const res = await fetch(
      metadata.token_endpoint!,
      form({
        client_id: CLIENT_ID,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: device.device_code,
      }),
    );
    const body = (await res.json()) as Grant & { error?: string };
    if (res.status === 200) return body;
    if (body.error === "authorization_pending") continue;
    if (body.error === "slow_down") {
      intervalMs += 5000;
      continue;
    }
    throw new ContractViolation(
      `RFC 8628 §3.5: the token request answered HTTP ${res.status} "${String(body.error)}" instead of a token.`,
    );
  }
  throw new ContractViolation(`the device login was not approved in time.`);
}
