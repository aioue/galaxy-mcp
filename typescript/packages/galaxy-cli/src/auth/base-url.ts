import { AuthError, type BaseUrl } from "./types";

/**
 * The one form a Galaxy's URL is stored and compared in.
 *
 * A bare host is taken as https. The path prefix is kept, because a Galaxy can be served
 * under one (`https://example.org/galaxy`) and two prefixes on one host are two Galaxies.
 * Query, fragment and trailing slashes are dropped, the host is lower-cased by URL itself,
 * and default ports vanish the same way.
 *
 * Plain http is refused except to loopback: a token sent in the clear is a token handed
 * out, and the only honest use for http here is a Galaxy on this machine.
 */
export function normalizeBaseUrl(input: string): BaseUrl {
  const raw = input.trim();
  if (!raw) throw new AuthError("usage", "No Galaxy URL given.");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new AuthError("usage", `Not a URL: ${input}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new AuthError("usage", `Galaxy URLs are http or https, not ${url.protocol.replace(/:$/, "")}: ${input}`);
  }
  if (url.username || url.password) {
    throw new AuthError("usage", `Leave credentials out of the Galaxy URL: ${url.host}`);
  }
  if (url.protocol === "http:" && !isLoopback(url.hostname)) {
    throw new AuthError("insecure", `Refusing plain http to ${url.host}: a token would cross the network unencrypted. Use https.`);
  }
  const path = url.pathname.replace(/\/+$/, "");
  return `${url.protocol}//${url.host}${path}` as BaseUrl;
}

export function isLoopback(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}
