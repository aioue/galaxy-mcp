/**
 * Make a server-supplied string safe to print on a terminal. A hostile or compromised
 * server controls `user_code`, `verification_uri`, error texts and usernames; an escape
 * sequence in one of them can retitle the window, clear the screen over a warning, or
 * (in some terminals) type into the prompt. So every C0 control (ESC, BEL, CR, LF, tab ...),
 * DEL and every C1 control (which includes the 8-bit CSI) is removed, not escaped, because
 * nothing legitimate in these fields needs one. The bytes that follow an ESC stay as
 * harmless text.
 *
 * `keepNewlines` is for our own multi-line messages, which carry server text only after
 * it has been sanitised at its source.
 */
export function sanitize(value: string, options: { keepNewlines?: boolean } = {}): string {
  const pattern = options.keepNewlines ? /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g : /[\u0000-\u001f\u007f-\u009f]/g;
  return value.replace(pattern, "");
}
