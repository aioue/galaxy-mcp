/**
 * A token goes into an HTTP header and, for `auth env`, into a shell. Real Galaxy keys and
 * OAuth access tokens are printable ASCII with no whitespace; anything else (control or
 * format characters, curly quotes, non-ASCII) is a broken paste or a hostile server, and is
 * refused before it is stored or sent. Callers must not echo the token in their message.
 */
export function isPlainToken(token: string): boolean {
  return /^[\x21-\x7e]+$/.test(token);
}
