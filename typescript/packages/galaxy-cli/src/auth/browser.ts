import { spawn } from "node:child_process";

type Env = Record<string, string | undefined>;

/** Whether there is any chance of opening a browser: always off Linux, a display on it. */
export function canOpenBrowser(env: Env = process.env, platform: NodeJS.Platform = process.platform): boolean {
  if (platform === "linux") return Boolean(env.DISPLAY || env.WAYLAND_DISPLAY);
  return true;
}

/**
 * Open a URL in the user's browser, detached. The URL is an argv entry, never part of a
 * shell string. On Windows, `rundll32 url.dll,FileProtocolHandler` takes it the same way;
 * `cmd /c start` would hand `&` in a URL to cmd's parser.
 */
export function openBrowser(
  url: string,
  env: Env = process.env,
  platform: NodeJS.Platform = process.platform,
  spawnImpl: typeof spawn = spawn,
): Promise<boolean> {
  if (!/^https?:\/\//i.test(url) || !canOpenBrowser(env, platform)) return Promise.resolve(false);
  const [cmd, args] =
    platform === "darwin"
      ? ["open", [url]]
      : platform === "win32"
        ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
        : ["xdg-open", [url]];
  return new Promise((resolve) => {
    try {
      const child = spawnImpl(cmd, args, { detached: true, stdio: "ignore" });
      child.once("error", () => resolve(false));
      child.once("spawn", () => {
        child.unref();
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}
