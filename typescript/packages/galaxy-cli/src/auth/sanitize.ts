const FORMAT = "\\p{Cf}\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff";
const EVERYTHING = new RegExp(`[\\u0000-\\u001f\\u007f-\\u009f${FORMAT}]`, "gu");
const WITH_NEWLINES = new RegExp(`[\\u0000-\\u0009\\u000b-\\u001f\\u007f-\\u009f${FORMAT}]`, "gu");

/**
 * Make a server-supplied string safe to print on a terminal. A hostile or compromised
 * server controls `user_code`, `verification_uri`, error texts and usernames; an escape
 * sequence in one of them can retitle the window, clear the screen over a warning, or
 * (in some terminals) type into the prompt. So every C0 control (ESC, BEL, CR, LF, tab ...),
 * DEL and every C1 control (which includes the 8-bit CSI) is removed, not escaped, because
 * nothing legitimate in these fields needs one. Unicode format characters (Cf: bidi
 * overrides and isolates, zero-width and joiner characters, the BOM) go too: they reorder or
 * hide text, so `evil\u202Egpj.exe`-style tricks and invisible look-alikes cannot pass.
 * Ordinary letters, accented or not, stay. The bytes that follow an ESC stay as
 * harmless text.
 *
 * `keepNewlines` is for our own multi-line messages, which carry server text only after
 * it has been sanitised at its source.
 */
export function sanitize(value: string, options: { keepNewlines?: boolean } = {}): string {
  const pattern = options.keepNewlines ? WITH_NEWLINES : EVERYTHING;
  return value.replace(pattern, "");
}
