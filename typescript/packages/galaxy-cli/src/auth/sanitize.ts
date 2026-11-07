const FORMAT = "\\p{Cf}\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff";
const EVERYTHING = new RegExp(`[\\u0000-\\u001f\\u007f-\\u009f${FORMAT}]`, "gu");
const WITH_NEWLINES = new RegExp(`[\\u0000-\\u0009\\u000b-\\u001f\\u007f-\\u009f${FORMAT}]`, "gu");

/**
 * Make a server-supplied string safe to print on a terminal.
 *
 * A hostile or compromised server controls `user_code`, `verification_uri`, error texts and
 * usernames. An escape sequence in one of them can retitle the window, clear the screen over a
 * warning, or (in some terminals) type into the prompt. So every C0 control (ESC, BEL, CR, LF,
 * tab ...), DEL and every C1 control (which includes the 8-bit CSI, `\u009b`) is removed, not
 * escaped, because nothing legitimate in these fields needs one. What follows an ESC is left
 * behind as inert text: `\u001b[2J` becomes `[2J`.
 *
 * Unicode format characters (Cf) go too: bidi overrides and isolates, zero-width spaces and
 * joiners, the soft hyphen and the BOM. They reorder or hide text, so an `evil\u202Egpj.exe`
 * trick or an invisible look-alike in a username cannot pass. The cost is that the ZWNJ some
 * scripts need and ZWJ emoji sequences lose their joiner, which is acceptable in identifiers
 * and one-line messages. Ordinary letters, accented or not, stay.
 *
 * `keepNewlines` keeps `\n` only, for our own multi-line messages, which carry server text
 * only after it has been sanitised at its source. CR is still removed: a bare CR returns the
 * cursor to column 0, so the rest of a line could overwrite the start of it.
 */
export function sanitize(value: string, options: { keepNewlines?: boolean } = {}): string {
  const pattern = options.keepNewlines ? WITH_NEWLINES : EVERYTHING;
  return value.replace(pattern, "");
}
