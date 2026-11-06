import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { exitQuietlyOnEpipe } from "../../src/auth/epipe";
import { statusCommand } from "../../src/auth/commands/status";
import { quoteFor } from "../../src/auth/commands/env";
import { toGrant } from "../../src/auth/oauth";
import { parseScopes } from "../../src/auth/register";
import { sanitize } from "../../src/auth/sanitize";
import { readPiped, readSecret, type RawStdin } from "../../src/auth/stdin";
import { AuthError } from "../../src/auth/types";
import { buildProgram } from "../../src/program";
import { OTHER, fakeLogin, harness } from "./fakes";

const epipe = () => Object.assign(new Error("write EPIPE"), { code: "EPIPE" });

describe("C4: EPIPE", () => {
  it("on stdout exits quietly with 0", () => {
    const [stdout, stderr] = [new PassThrough(), new PassThrough()];
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout, stderr }, (c) => void codes.push(c));
    stdout.emit("error", epipe());
    expect(codes).toEqual([0]);
  });

  it("on stderr does not exit, and silences later stderr writes", () => {
    const [stdout, stderr] = [new PassThrough(), new PassThrough()];
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout, stderr }, (c) => void codes.push(c));
    expect(() => stderr.emit("error", epipe())).not.toThrow();
    expect(codes).toEqual([]);
    expect(stderr.write("more\n")).toBe(true);
    expect(stderr.read()).toBeNull();
    // Other errors still surface.
    expect(() => stderr.emit("error", Object.assign(new Error("disk"), { code: "EIO" }))).toThrow("disk");
  });
});

describe("C3: status bounds each host's check", () => {
  it("reports a hung host as its failure and still reports the others", async () => {
    const h = harness({ stored: [fakeLogin(), fakeLogin({ baseUrl: OTHER, username: "bob" })] });
    h.deps.whoami = async (baseUrl) => {
      if (baseUrl !== OTHER) return new Promise(() => {}); // never answers, ignores the signal
      return { username: "bob", isAdmin: false };
    };
    const code = await statusCommand({ timeoutMs: 50 }, h.deps);
    expect(code).toBe(1);
    expect(h.cap.err).toMatch(/No answer from dev\.galaxy\.example\.org within/);
    expect(h.cap.err).toContain("Logged in as bob");
  });

  it("stops on Ctrl-C with 130", async () => {
    const h = harness({ stored: [fakeLogin()] });
    h.deps.whoami = () => new Promise(() => {});
    const ac = new AbortController();
    const p = statusCommand({ signal: ac.signal }, h.deps);
    ac.abort();
    expect(await p).toBe(130);
  });
});

describe("K2: --scopes accumulates", () => {
  it("de-duplicates in order across values and separators", () => {
    expect(parseScopes("b", parseScopes("a"))).toEqual(["a", "b"]);
    expect(parseScopes("b c,a", ["a", "b"])).toEqual(["a", "b", "c"]);
  });

  it("works through the program", async () => {
    const h = harness();
    process.exitCode = 0;
    await buildProgram({ makeAuthDeps: () => h.deps, invokedAs: "gxy" }).parseAsync([
      "node", "gxy", "auth", "login", "--host", "https://dev.galaxy.example.org", "--scopes", "a", "--scopes", "b,c", "--scopes", "a d",
    ]);
    process.exitCode = 0;
    expect(h.cap.err).toContain("Scopes  a b c d");
  });
});

describe("S3: sanitize strips format characters", () => {
  it.each(["\u061c", "\u200b", "\u200e", "\u200f", "\u202a", "\u202e", "\u2060", "\u2064", "\u2066", "\u2069", "\ufeff", "\u00ad", "\u200d"])(
    "removes %j",
    (c) => {
      expect(sanitize(`a${c}b`)).toBe("ab");
      expect(sanitize(`a${c}b`, { keepNewlines: true })).toBe("ab");
    },
  );
  it("keeps ordinary non-ASCII letters", () => {
    expect(sanitize("José Müller Łukasz 李")).toBe("José Müller Łukasz 李");
  });
});

describe("S4: tokens are printable ASCII", () => {
  it("rejects a non-plain token from the token grant, without echoing it", () => {
    for (const bad of ["abc def", "abc\u2018def", "tok\u0000en", "t\u00f6k\u00e9n"]) {
      let err: unknown;
      try {
        toGrant({ access_token: bad, token_type: "bearer" } as never, []);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(AuthError);
      expect((err as AuthError).kind).toBe("protocol");
      expect((err as AuthError).message).not.toContain(bad);
    }
    expect(toGrant({ access_token: "fake-ok_token.1", token_type: "bearer" } as never, []).accessToken).toBe("fake-ok_token.1");
  });

  it("rejects a pasted key with a space or non-ASCII, without echoing it", async () => {
    for (const bad of ["fake key", "fake\u2018key", "fak\u00e9key"]) {
      const s = new PassThrough();
      s.end(`${bad}\n`);
      const err = await readPiped(s, new AbortController().signal).catch((e) => e);
      expect(err).toBeInstanceOf(AuthError);
      expect(err.kind).toBe("usage");
      expect(err.message).not.toContain(bad);
    }
    const ok = new PassThrough();
    ok.end("fake-key-1\n");
    await expect(readPiped(ok, new AbortController().signal)).resolves.toBe("fake-key-1\n");
  });

  it("rejects the same at a terminal prompt", async () => {
    const s = Object.assign(new PassThrough(), { setRawMode: () => true }) as unknown as RawStdin;
    const p = readSecret(s, new AbortController().signal).catch((e) => e);
    (s as unknown as PassThrough).write("fake\u2018key\r");
    const err = await p;
    expect(err).toBeInstanceOf(AuthError);
    expect(err.message).not.toContain("fake");
  });

  it("PowerShell quoting doubles the curly single quotes", () => {
    expect(quoteFor("powershell", "a'b")).toBe("'a''b'");
    for (const q of ["\u2018", "\u2019", "\u201a", "\u201b"]) expect(quoteFor("powershell", `a${q}b`)).toBe(`'a${q}${q}b'`);
    expect(quoteFor("powershell", "a\u201cb")).toBe("'a\u201cb'");
  });
});
