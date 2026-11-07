// Small pure modules of the auth surface, one section each.
import { describe, expect, it } from "vitest";
import { configDir, hostsFile } from "../../src/auth/paths";
import { EXPIRY_MARGIN_MS, checkExpiry, describeExpiry, formatExpiry, isExpired } from "../../src/auth/expiry";
import { DAY } from "./harness";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { exitQuietlyOnEpipe } from "../../src/auth/epipe";
import { normalizeBaseUrl } from "../../src/auth/base-url";
import { AuthError } from "../../src/auth/types";

describe("configDir", () => {
  it("prefers GXY_CONFIG_DIR, then XDG_CONFIG_HOME, then ~/.config", () => {
    expect(configDir({ GXY_CONFIG_DIR: "/x", XDG_CONFIG_HOME: "/xdg" }, "/home/u")).toBe("/x");
    expect(configDir({ XDG_CONFIG_HOME: "/xdg" }, "/home/u")).toBe("/xdg/gxy");
    expect(configDir({}, "/home/u")).toBe("/home/u/.config/gxy");
  });
  it("treats empty and relative values as unset", () => {
    expect(configDir({ GXY_CONFIG_DIR: "", XDG_CONFIG_HOME: "rel" }, "/home/u")).toBe("/home/u/.config/gxy");
  });
});

describe("hostsFile", () => {
  it("is hosts.yml in the config directory", () => {
    expect(hostsFile("/x/gxy")).toBe("/x/gxy/hosts.yml");
  });
});

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

const epipe = () => Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
const eio = () => Object.assign(new Error("disk"), { code: "EIO" });

describe("exitQuietlyOnEpipe", () => {
  it("on stdout exits quietly with 0, and rethrows any other error", () => {
    const stdout = new PassThrough();
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout, stderr: new PassThrough() }, (c) => void codes.push(c));
    stdout.emit("error", epipe());
    expect(codes).toEqual([0]);
    expect(() => stdout.emit("error", eio())).toThrow("disk");
  });

  it("on stderr does not exit, silences later stderr writes, and rethrows any other error", () => {
    const [stdout, stderr] = [new PassThrough(), new PassThrough()];
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout, stderr }, (c) => void codes.push(c));
    expect(() => stderr.emit("error", epipe())).not.toThrow();
    expect(codes).toEqual([]);
    expect(stderr.write("more\n")).toBe(true);
    expect(stderr.read()).toBeNull();
    expect(() => stderr.emit("error", eio())).toThrow("disk");
  });

  // The one test with a real pipe. It needs bash and head, and Node able to load the module's
  // TypeScript source directly (Node 22.19 or later, which `engines` requires).
  it.skipIf(process.platform === "win32")("a real closed pipe ends the process quietly, with no stack trace", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gxy-epipe-"));
    try {
      const script = join(dir, "writer.mjs");
      const errFile = join(dir, "err");
      await writeFile(
        script,
        `import { exitQuietlyOnEpipe } from ${JSON.stringify(new URL("../../src/auth/epipe.ts", import.meta.url).href)};
exitQuietlyOnEpipe();
const chunk = "fake-token-".repeat(100000);
for (let i = 0; i < 50; i++) process.stdout.write(chunk);
process.stdout.write("\\n");`,
      );
      const r = spawnSync("bash", ["-c", `node ${JSON.stringify(script)} 2>${JSON.stringify(errFile)} | head -c1 >/dev/null; echo \${PIPESTATUS[0]}`], {
        encoding: "utf8",
        timeout: 20_000,
      });
      expect(r.stdout.trim()).toBe("0");
      expect(await readFile(errFile, "utf8")).toBe("");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

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
});
