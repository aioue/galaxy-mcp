import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { spawn } from "node:child_process";
import { SPAWN_TIMEOUT_MS, canOpenBrowser, openBrowser } from "../../src/auth/browser";

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
  it("runs xdg-open with the URL as one argument, detached, stdio ignored", async () => {
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
    expect(s.calls).toEqual([{ cmd: "/vscode/bin/helpers/browser.sh", args: [URL_], opts: { detached: true, stdio: "ignore" } }]);
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
