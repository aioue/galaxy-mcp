import { describe, expect, it } from "vitest";
import { normalizeBaseUrl } from "../../src/auth/base-url";
import { AuthError } from "../../src/auth/types";

describe("normalizeBaseUrl", () => {
  it.each([
    ["Host.EXAMPLE", "https://host.example"],
    ["host.example:443", "https://host.example"],
    ["HOST.Example:443/", "https://host.example"],
    ["host.example/", "https://host.example"],
    ["host.example/api", "https://host.example"],
    ["host.example/api/", "https://host.example"],
    ["https://host.example/galaxy/api/", "https://host.example/galaxy"],
    ["host.example/galaxy", "https://host.example/galaxy"],
    ["https://host.example/galaxy//", "https://host.example/galaxy"],
    ["https://host.example/?x=1#frag", "https://host.example"],
    ["  https://host.example  ", "https://host.example"],
    ["http://127.0.0.1:8080/api", "http://127.0.0.1:8080"],
    ["https://bücher.example", "https://xn--bcher-kva.example"],
    ["https://host.example:8443", "https://host.example:8443"],
  ])("%s -> %s", (input, expected) => {
    expect(normalizeBaseUrl(input)).toBe(expected);
  });

  it("keeps only an exact /api suffix: a longer segment is a different Galaxy", () => {
    expect(normalizeBaseUrl("https://host.example/apiary")).toBe("https://host.example/apiary");
    expect(normalizeBaseUrl("https://host.example/api/v2")).toBe("https://host.example/api/v2");
  });

  it.each(["host.example\r", "host.example\n", "host.\u001bexample", "host.example\u0000", "ho st.example", "host.example/a b", "\u0085host.example"])(
    "refuses control characters and whitespace: %j",
    (input) => {
      expect(() => normalizeBaseUrl(input)).toThrow(AuthError);
    },
  );

  it("refuses userinfo, whatever the form", () => {
    expect(() => normalizeBaseUrl("https://user:pw@host.example")).toThrow(/credentials/);
    expect(() => normalizeBaseUrl("user@host.example")).toThrow(/credentials/);
  });

  it("refuses plain http except to loopback, and other schemes", () => {
    expect(() => normalizeBaseUrl("http://host.example")).toThrow(expect.objectContaining({ kind: "insecure" }));
    expect(() => normalizeBaseUrl("ftp://host.example")).toThrow(AuthError);
  });

  it("is exact: a prefix of another base URL is a different one", () => {
    expect(normalizeBaseUrl("https://host.example")).not.toBe(normalizeBaseUrl("https://host.example/galaxy"));
    expect(normalizeBaseUrl("https://host.example")).not.toBe(normalizeBaseUrl("https://host.example.evil.example"));
  });
});
