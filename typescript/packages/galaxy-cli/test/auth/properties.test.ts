// Property tests (fast-check) where a canonical form or a round trip is the contract.
// Fixed seed and bounded runs keep them deterministic and quick; a failure prints the
// counterexample and the seed, so it can be replayed and then pinned as an example.
import { spawnSync } from "node:child_process";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { normalizeBaseUrl } from "../../src/auth/base-url";
import { quoteFor } from "../../src/auth/commands/env";
import { sanitize } from "../../src/auth/sanitize";
import { AuthError } from "../../src/auth/types";

const params = { seed: 20260707, numRuns: 200 };

// Small generators: a mix of well-formed URLs and the awkward pieces that matter to the key.
const host = fc.constantFrom("host.example", "HOST.Example:443", "h.example:8443", "localhost:8080", "127.0.0.1", "[::1]:9", "evil.example");
const segment = fc.constantFrom("api", "galaxy", "apiary", "v2", "", "%61pi");
const pathPart = fc.array(segment, { maxLength: 4 }).map((parts) => parts.map((p) => `/${p}`).join(""));
const tail = fc.constantFrom("", "/", "//", "?x=1", "#f", "/?q#f");
const scheme = fc.constantFrom("", "https://", "http://", "HTTPS://", "ftp://", "user@", "https://u:p@");
const urlish = fc.oneof(
  fc.tuple(scheme, host, pathPart, tail).map(([s, h, p, t]) => `${s}${h}${p}${t}`),
  fc.string({ maxLength: 30 }),
);

const attempt = (input: string) => {
  try {
    return normalizeBaseUrl(input);
  } catch (e) {
    if (!(e instanceof AuthError)) throw e; // anything but an AuthError escaping fails the property
    return undefined;
  }
};

describe("normalizeBaseUrl properties", () => {
  it("throws only AuthError, and the key has no userinfo, query, fragment or trailing slash, and is http only for loopback", () => {
    fc.assert(
      fc.property(urlish, (input) => {
        const key = attempt(input);
        if (key === undefined) return;
        const url = new URL(key);
        expect(url.username + url.password + url.search + url.hash).toBe("");
        expect(key.endsWith("/")).toBe(false);
        expect(key).not.toMatch(/[?#]/);
        if (url.protocol === "http:") expect(url.hostname).toMatch(/^(localhost|\[::1\]|127(\.\d{1,3}){3})$/);
        else expect(url.protocol).toBe("https:");
      }),
      params,
    );
  });

  it("is idempotent: a stored key normalises to itself", () => {
    fc.assert(
      fc.property(urlish, (input) => {
        const key = attempt(input);
        if (key !== undefined) expect(normalizeBaseUrl(key)).toBe(key);
      }),
      params,
    );
  });
});

describe("quoteFor", () => {
  // Spawns a real sh per run, so the run count stays low.
  it.skipIf(process.platform === "win32")("sh quoting round-trips any printable ASCII through a real sh", () => {
    const printable = fc.string({ unit: fc.integer({ min: 0x20, max: 0x7e }).map((c) => String.fromCharCode(c)), maxLength: 40 });
    fc.assert(
      fc.property(printable, (value) => {
        const r = spawnSync("sh", ["-c", `printf %s ${quoteFor("sh", value)}`], { encoding: "utf8" });
        expect(r.stdout).toBe(value);
      }),
      { ...params, numRuns: 50 },
    );
  });
});

describe("sanitize", () => {
  // Code points up to U+20FF cover C0, C1 and the common Cf ranges; the extras are Cf characters beyond them.
  const unit = fc.oneof(fc.integer({ min: 0, max: 0x20ff }).map((c) => String.fromCodePoint(c)), fc.constantFrom("\ufeff", "\u{e0041}", "\u{1d173}"));

  it("leaves no control or format characters, and is idempotent", () => {
    fc.assert(
      fc.property(fc.string({ unit, maxLength: 40 }), fc.boolean(), (value, keepNewlines) => {
        const once = sanitize(value, { keepNewlines });
        expect(keepNewlines ? once.replace(/\n/g, "") : once).not.toMatch(/[\p{Cc}\p{Cf}]/u);
        expect(sanitize(once, { keepNewlines })).toBe(once);
      }),
      params,
    );
  });
});
