import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { InputCancelled, MAX_KEY_BYTES, readPiped, readSecret, type RawStdin } from "../../src/auth/stdin";
import { AuthError } from "../../src/auth/types";

const NOT_KEYS = [["a space", "fake key"], ["a curly quote", "fake‘key"], ["a non-ASCII letter", "fakékey"]];

describe("readPiped", () => {
  const signal = () => new AbortController().signal;
  const piped = (text: string) => {
    const s = new PassThrough();
    s.end(text);
    return s;
  };

  it("returns what was piped", async () => {
    await expect(readPiped(piped("fake-key-1\n"), signal())).resolves.toBe("fake-key-1\n");
  });

  it.each(NOT_KEYS)("refuses a key with %s as a usage error, without echoing it", async (_what, bad) => {
    const e = await readPiped(piped(`${bad}\n`), signal()).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(AuthError);
    expect((e as AuthError).kind).toBe("usage");
    expect((e as AuthError).message).not.toContain(bad);
  });

  it("accepts input right at the size cap and refuses one byte more", async () => {
    await expect(readPiped(piped("k".repeat(MAX_KEY_BYTES)), signal())).resolves.toHaveLength(MAX_KEY_BYTES);
    const e = await readPiped(piped("k".repeat(MAX_KEY_BYTES + 1)), signal()).catch((x: unknown) => x);
    expect((e as AuthError).kind).toBe("usage");
  });

  it("stops reading, leaving no listener behind, when the signal aborts", async () => {
    const s = new PassThrough();
    const ac = new AbortController();
    const p = readPiped(s, ac.signal);
    ac.abort(new Error("ctrl-c"));
    await expect(p).rejects.toThrow("ctrl-c");
    expect(s.listenerCount("data")).toBe(0);
  });
});

describe("readSecret", () => {
  function terminal() {
    const raw: boolean[] = [];
    const s = Object.assign(new PassThrough(), { setRawMode: (m: boolean) => void raw.push(m) });
    return { s, raw, stdin: s as unknown as RawStdin };
  }
  const signal = () => new AbortController().signal;

  it("reads a line without echo and puts the terminal back", async () => {
    const { s, raw, stdin } = terminal();
    const p = readSecret(stdin, signal());
    s.write("fake-key\r");
    await expect(p).resolves.toBe("fake-key");
    expect(raw[0]).toBe(true);
    expect(raw.at(-1)).toBe(false);
  });

  it("finishes on Ctrl-D too", async () => {
    const { s, stdin } = terminal();
    const p = readSecret(stdin, signal());
    s.write("fake-key\x04");
    await expect(p).resolves.toBe("fake-key");
  });

  it("honours backspace and ignores the escape sequences of a bracketed paste", async () => {
    const { s, stdin } = terminal();
    const p = readSecret(stdin, signal());
    s.write("\x1b[200~abXX\x7f\x7fc\x1b[201~\n");
    await expect(p).resolves.toBe("abc");
  });

  it("is cancelled by Ctrl-C, which raw mode delivers as a character", async () => {
    const { s, raw, stdin } = terminal();
    const p = readSecret(stdin, signal());
    s.write("fake\x03");
    await expect(p).rejects.toBeInstanceOf(InputCancelled);
    expect(raw.at(-1)).toBe(false);
  });

  it("puts the terminal back when the signal aborts", async () => {
    const { raw, stdin } = terminal();
    const ac = new AbortController();
    const p = readSecret(stdin, ac.signal);
    ac.abort(new Error("ctrl-c"));
    await expect(p).rejects.toThrow("ctrl-c");
    expect(raw.at(-1)).toBe(false);
  });

  it.each(NOT_KEYS)("refuses a key with %s, without echoing it", async (_what, bad) => {
    const { s, stdin } = terminal();
    const p = readSecret(stdin, signal()).catch((x: unknown) => x);
    s.write(`${bad}\r`);
    const e = await p;
    expect(e).toBeInstanceOf(AuthError);
    expect((e as AuthError).message).not.toContain(bad);
  });
});
