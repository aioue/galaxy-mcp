import { describe, expect, it } from "vitest";
import { EXPIRY_MARGIN_MS, checkExpiry, describeExpiry, formatExpiry, isExpired } from "../../src/auth/expiry";
import { DAY } from "./harness";

const now = new Date(DAY);
const at = (ms: number) => new Date(now.getTime() + ms).toISOString();

describe("expiry helper", () => {
  it("treats a login as expired 60 s before expiresAt", () => {
    expect(EXPIRY_MARGIN_MS).toBe(60_000);
    expect(isExpired(at(61_000), now)).toBe(false);
    expect(isExpired(at(60_000), now)).toBe(true);
    expect(isExpired(at(30_000), now)).toBe(true);
    expect(isExpired(at(-1), now)).toBe(true);
    expect(isExpired(null, now)).toBe(false);
  });
  it("treats an unparseable expiresAt as expired, never as non-expiring", () => {
    expect(checkExpiry("tomorrow", now)).toEqual({ state: "unreadable" });
    expect(isExpired("tomorrow", now)).toBe(true);
  });
  it("formatExpiry never throws", () => {
    expect(formatExpiry("tomorrow")).toContain("unreadable");
    expect(formatExpiry("\u001b[2Jx")).not.toContain("\u001b");
    expect(formatExpiry("2026-11-06T18:42:00.000Z")).toBe("2026-11-06 18:42 UTC");
  });
  it("describes the three cases", () => {
    expect(describeExpiry(at(-5000), now)).toMatch(/^expired at /);
    expect(describeExpiry(at(20_000), now)).toMatch(/^is about to expire/);
    expect(describeExpiry("tomorrow", now)).toMatch(/unreadable expiry/);
  });
});
