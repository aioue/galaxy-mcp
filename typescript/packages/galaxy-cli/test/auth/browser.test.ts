import { describe, it, expect } from "vitest";
import { EventEmitter } from "node:events";
import type { spawn } from "node:child_process";
import { canOpenBrowser, openBrowser } from "../../src/auth/browser";

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
