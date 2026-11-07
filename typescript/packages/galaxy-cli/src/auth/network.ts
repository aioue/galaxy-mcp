import { sanitize } from "./sanitize";

const TLS_CODES = /^(CERT_|ERR_TLS_|UNABLE_TO_(GET_ISSUER_CERT|VERIFY_LEAF|GET_CRL)|SELF_SIGNED_CERT|DEPTH_ZERO_SELF_SIGNED|HOSTNAME_MISMATCH|ERR_SSL_)/;

function codeOf(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

/** Walk `cause` links: fetch hides the real error (ECONNREFUSED, a certificate failure) one or two levels down. */
function rootCause(err: Error): Error {
  let e: Error = err;
  for (let i = 0; i < 5 && e.cause instanceof Error; i++) e = e.cause;
  return e;
}

/** Whether a failed request died on certificate or TLS trouble: retrying cannot fix that. */
export function isTlsError(err: Error): boolean {
  const cause = rootCause(err);
  const code = codeOf(cause);
  return (code !== undefined && TLS_CODES.test(code)) || /certificate|self.signed|TLS|SSL/i.test(cause.message);
}

/**
 * The message for a request that never got an answer, naming the fixes that exist.
 *
 * A certificate failure usually means a private CA (set `NODE_EXTRA_CA_CERTS` to its PEM
 * file). The proxy advice is not here: it depends on the environment, so `fail` in
 * commands/common.ts adds it. The advice never includes turning certificate checking off.
 */
export function describeNetworkError(err: Error, target: string): string {
  const cause = rootCause(err);
  const detail = sanitize(cause.message || err.message);
  if (isTlsError(err)) {
    return (
      `Could not make a secure connection to ${target}: ${detail}. ` +
      "If it uses a certificate from a private CA, set NODE_EXTRA_CA_CERTS to the CA's PEM file and try again."
    );
  }
  return `Could not reach ${target}: ${detail}. For a private CA, set NODE_EXTRA_CA_CERTS.`;
}
