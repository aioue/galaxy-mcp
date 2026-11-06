import { AuthError } from "./types";
import { isPlainToken } from "./token-shape";

/** An API key is tens of characters; anything near this is not one. */
export const MAX_KEY_BYTES = 16 * 1024;

const TOO_LARGE = `That is more than ${MAX_KEY_BYTES / 1024} KiB, which is not an API key. Pass the key alone.`;

/** The person pressed Ctrl-C at the key prompt (raw mode turns it into a character, not SIGINT). */
export class InputCancelled extends Error {
  constructor() {
    super("Cancelled.");
    this.name = "InputCancelled";
  }
}

const NOT_PLAIN = "That is not an API key: it has spaces or characters outside printable ASCII. Paste the key alone.";

/** Refuse a key that cannot be one, without repeating it. Several lines are left to the caller's own message. */
function checkKeyShape(text: string): string {
  const key = text.trim();
  if (key && !/[\r\n]/.test(key) && !isPlainToken(key)) throw new AuthError("usage", NOT_PLAIN);
  return text;
}

/** Everything piped on stdin, up to `MAX_KEY_BYTES`; stops reading, rejecting, when `signal` aborts. */
export function readPiped(stdin: NodeJS.ReadableStream, signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const cleanup = () => {
      stdin.removeListener("data", onData);
      stdin.removeListener("end", onEnd);
      stdin.removeListener("error", onError);
      signal.removeEventListener("abort", onAbort);
    };
    const settle = (fn: () => void) => {
      cleanup();
      stdin.pause();
      fn();
    };
    const onData = (chunk: Buffer | string) => {
      const buf = Buffer.from(chunk);
      size += buf.length;
      if (size > MAX_KEY_BYTES) return settle(() => reject(new AuthError("usage", TOO_LARGE)));
      chunks.push(buf);
    };
    const onEnd = () => {
      cleanup();
      try {
        resolve(checkKeyShape(Buffer.concat(chunks).toString("utf8")));
      } catch (e) {
        reject(e);
      }
    };
    const onError = (e: Error) => settle(() => reject(e));
    const onAbort = () => settle(() => reject(signal.reason));
    if (signal.aborted) return onAbort();
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.on("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export type RawStdin = NodeJS.ReadableStream & { setRawMode(mode: boolean): unknown };

export function isRawCapable(stdin: NodeJS.ReadableStream): stdin is RawStdin {
  return typeof (stdin as Partial<RawStdin>).setRawMode === "function";
}

/**
 * One line typed at a terminal without echo. Raw mode is always switched off again, whatever
 * ends the read. Enter or Ctrl-D finishes, Ctrl-C cancels, backspace works.
 */
export function readSecret(stdin: RawStdin, signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    let typed = "";
    const ok = (t: string) => !t.trim() || isPlainToken(t.trim());
    const cleanup = () => {
      stdin.removeListener("data", onData);
      signal.removeEventListener("abort", onAbort);
      stdin.setRawMode(false);
      stdin.pause();
    };
    const settle = (fn: () => void) => {
      cleanup();
      fn();
    };
    const onAbort = () => settle(() => reject(signal.reason));
    const onData = (chunk: Buffer | string) => {
      // Strip escape sequences (bracketed paste markers, arrow keys) rather than store them.
      const text = Buffer.from(chunk).toString("utf8").replace(/\x1b\[[0-9;?]*[~A-Za-z]/g, "");
      for (const ch of text) {
        if (ch === "\x03") return settle(() => reject(new InputCancelled()));
        if (ch === "\r" || ch === "\n" || ch === "\x04") return settle(() => (ok(typed) ? resolve(typed) : reject(new AuthError("usage", NOT_PLAIN))));
        if (ch === "\x7f" || ch === "\b") typed = typed.slice(0, -1);
        else if (ch >= " ") typed += ch;
        if (typed.length > MAX_KEY_BYTES) return settle(() => reject(new AuthError("usage", TOO_LARGE)));
      }
    };
    if (signal.aborted) return reject(signal.reason);
    stdin.setRawMode(true);
    stdin.on("data", onData);
    stdin.resume();
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
