import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { spawn } from "node:child_process";
import { access, chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SPAWN_TIMEOUT_MS, canOpenBrowser, openBrowser } from "../../src/auth/browser";
import { useTempDir } from "./harness";

function fakeSpawn(outcome: "spawn" | "error" | "throw") {
  const calls: { cmd: string; args: string[]; opts: unknown }[] = [];
  const impl = ((cmd: string, args: string[], opts: unknown) => {
    calls.push({ cmd, args, opts });
    if (outcome === "throw") throw new Error("boom");
    const child = Object.assign(new EventEmitter(), { unref() {} });
    queueMicrotask(() => child.emit(outcome === "spawn" ? "spawn" : "error", new Error("ENOENT")));
    return child;
  }) as unknown as typeof spawn;
  return { impl, calls };
}

const URL_ = "https://dev.galaxy.example.org/login/device?user_code=A&b=c";

describe("openBrowser", () => {
  it("runs xdg-open with the URL as one argument, detached from this process, stdio ignored", async () => {
    const s = fakeSpawn("spawn");
    expect(await openBrowser(URL_, { DISPLAY: ":0" }, "linux", s.impl)).toBe(true);
    expect(s.calls).toEqual([{ cmd: "xdg-open", args: [URL_], opts: { detached: true, stdio: "ignore" } }]);
  });

  it("returns false without a display on Linux, and does not spawn", async () => {
    const s = fakeSpawn("spawn");
    expect(await openBrowser(URL_, {}, "linux", s.impl)).toBe(false);
    expect(s.calls).toEqual([]);
    expect(canOpenBrowser({ WAYLAND_DISPLAY: "wayland-0" }, "linux")).toBe(true);
  });

  it("returns false when the spawn fails or throws", async () => {
    expect(await openBrowser(URL_, { DISPLAY: ":0" }, "linux", fakeSpawn("error").impl)).toBe(false);
    expect(await openBrowser(URL_, { DISPLAY: ":0" }, "linux", fakeSpawn("throw").impl)).toBe(false);
  });

  it("uses open on darwin and a shell-free handler on win32", async () => {
    const d = fakeSpawn("spawn");
    await openBrowser(URL_, {}, "darwin", d.impl);
    expect(d.calls[0]).toMatchObject({ cmd: "open", args: [URL_] });
    const w = fakeSpawn("spawn");
    await openBrowser(URL_, {}, "win32", w.impl);
    expect(w.calls[0]).toMatchObject({ cmd: "rundll32", args: ["url.dll,FileProtocolHandler", URL_] });
  });

  it("refuses a non-http URL", async () => {
    const s = fakeSpawn("spawn");
    expect(await openBrowser("file:///etc/passwd", { DISPLAY: ":0" }, "linux", s.impl)).toBe(false);
    expect(s.calls).toEqual([]);
  });
});

describe("$BROWSER", () => {
  it("counts as a way to open a browser even with no display (VS Code's forwarding helper)", () => {
    expect(canOpenBrowser({ BROWSER: "/vscode/bin/helpers/browser.sh" }, "linux")).toBe(true);
    expect(canOpenBrowser({ BROWSER: ":" }, "linux")).toBe(false);
  });

  it("is run first, with the URL as its one argument and no shell, even without DISPLAY", async () => {
    const s = fakeSpawn("spawn");
    expect(await openBrowser(URL_, { BROWSER: "/vscode/bin/helpers/browser.sh" }, "linux", s.impl)).toBe(true);
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]).toMatchObject({ cmd: "/vscode/bin/helpers/browser.sh", args: [URL_] });
  });

  it("goes before xdg-open, and falls through a colon-separated list on failure", async () => {
    const calls: string[] = [];
    const impl = ((cmd: string) => {
      calls.push(cmd);
      const child = Object.assign(new EventEmitter(), { unref() {} });
      queueMicrotask(() => (cmd === "third" || cmd === "xdg-open" ? child.emit("spawn") : child.emit("error", new Error("ENOENT"))));
      return child;
    }) as unknown as typeof spawn;
    expect(await openBrowser(URL_, { BROWSER: "first:second::third", DISPLAY: ":0" }, "linux", impl)).toBe(true);
    expect(calls).toEqual(["first", "second", "third"]);
    calls.length = 0;
    expect(await openBrowser(URL_, { BROWSER: "first", DISPLAY: ":0" }, "linux", impl)).toBe(true);
    expect(calls).toEqual(["first", "xdg-open"]);
  });

  it("substitutes %s without a shell, and puts the URL last otherwise", async () => {
    const a = fakeSpawn("spawn");
    await openBrowser(URL_, { BROWSER: "mybrowser --new-tab %s" }, "linux", a.impl);
    expect(a.calls[0]).toMatchObject({ cmd: "mybrowser", args: ["--new-tab", URL_] });
    const b = fakeSpawn("spawn");
    await openBrowser(URL_, { BROWSER: "mybrowser --new-tab" }, "linux", b.impl);
    expect(b.calls[0]).toMatchObject({ cmd: "mybrowser", args: ["--new-tab", URL_] });
  });

  it("does not use a $BROWSER for a non-http URL", async () => {
    const s = fakeSpawn("spawn");
    expect(await openBrowser("javascript:alert(1)", { BROWSER: "b" }, "linux", s.impl)).toBe(false);
    expect(s.calls).toEqual([]);
  });

  it("never waits forever for a launcher that neither starts nor fails", async () => {
    vi.useFakeTimers();
    try {
      const hang = (() => Object.assign(new EventEmitter(), { unref() {} })) as unknown as typeof spawn;
      const p = openBrowser(URL_, { BROWSER: "stuck" }, "linux", hang);
      await vi.advanceTimersByTimeAsync(SPAWN_TIMEOUT_MS + 1);
      expect(await p).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});

// The fake `spawn` tests above prove what is handed to `spawn`. These run a real launcher, so they
// prove what the operating system hands it: the URL arrives as one argv entry, and no shell
// ever sees it.
describe.skipIf(process.platform === "win32")("a real $BROWSER launcher", () => {
  const tmp = useTempDir("gxy-browser-");

  /** A launcher that writes its argument count, then its arguments one per line, to `argv.txt`. */
  async function stub(): Promise<{ path: string; argvFile: string; readArgv: () => Promise<string[]> }> {
    const path = join(tmp.path, "stub-browser");
    const argvFile = join(tmp.path, "argv.txt");
    await writeFile(path, `#!/bin/sh\nprintf '%s\\n' "$#" "$@" > "${argvFile}.part" && mv "${argvFile}.part" "${argvFile}"\n`);
    await chmod(path, 0o755);
    // The launcher is detached and `openBrowser` resolves when it starts, not when it finishes.
    const readArgv = async () => {
      await vi.waitFor(() => access(argvFile), { timeout: 5000, interval: 20 });
      return (await readFile(argvFile, "utf8")).split("\n").slice(0, -1);
    };
    return { path, argvFile, readArgv };
  }

  /** A URL with every character a shell would act on. Running it through a shell would create `pwned-*`. */
  const evilUrl = () => `https://x.example/?q=a b&c=$(touch ${tmp.path}/pwned-sub);d=\`touch ${tmp.path}/pwned-tick\`;touch ${tmp.path}/pwned-semi`;
  const pwned = async () => (await Promise.all(["sub", "tick", "semi"].map((n) => access(join(tmp.path, `pwned-${n}`)).then(() => n, () => null)))).filter(Boolean);

  it("receives the URL as exactly one argument, with nothing run by a shell", async () => {
    const s = await stub();
    const url = evilUrl();
    expect(await openBrowser(url, { BROWSER: s.path }, "linux")).toBe(true);
    expect(await s.readArgv()).toEqual(["1", url]);
    expect(await pwned()).toEqual([]);
  });

  it("with %s, receives its own arguments and then the URL as one more", async () => {
    const s = await stub();
    const url = evilUrl();
    expect(await openBrowser(url, { BROWSER: `${s.path} --new-tab %s` }, "linux")).toBe(true);
    expect(await s.readArgv()).toEqual(["2", "--new-tab", url]);
    expect(await pwned()).toEqual([]);
  });
});
