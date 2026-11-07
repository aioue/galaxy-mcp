import { spawn } from "node:child_process";

type Env = Record<string, string | undefined>;

/** How long a launcher gets to start before we stop waiting; login never blocks on a browser. */
export const SPAWN_TIMEOUT_MS = 3000;

/** `$BROWSER` as the convention has it: a colon-separated list of commands to try in order. */
function browserCandidates(env: Env): string[] {
  return (env.BROWSER ?? "").split(":").map((c) => c.trim()).filter(Boolean);
}

/**
 * Whether there is any chance of opening a browser: `$BROWSER` set, else always off Linux,
 * and on Linux a display. `$BROWSER` comes first because VS Code's remote and devcontainer
 * sessions set it to a helper that forwards the URL to the browser on the user's own
 * machine, where there is often no `DISPLAY` at all.
 */
export function canOpenBrowser(env: Env = process.env, platform: NodeJS.Platform = process.platform): boolean {
  if (browserCandidates(env).length > 0) return true;
  if (platform === "linux") return Boolean(env.DISPLAY || env.WAYLAND_DISPLAY);
  return true;
}

/**
 * Open a URL in the user's browser, detached. The URL is an argv entry, never part of a
 * shell string: it came from the server, and a `;` or a backtick in it must not become a
 * command. On Windows, `rundll32 url.dll,FileProtocolHandler` takes it the same way;
 * `cmd /c start` would hand `&` in a URL to cmd's parser.
 *
 * Order: each `$BROWSER` candidate (a `%s` in one is replaced by the URL, otherwise the URL
 * is appended; no shell is involved), then the platform opener. The first launcher that
 * starts wins. Resolves false when none did, and never waits longer than
 * `SPAWN_TIMEOUT_MS` for any one of them.
 */
export async function openBrowser(
  url: string,
  env: Env = process.env,
  platform: NodeJS.Platform = process.platform,
  spawnImpl: typeof spawn = spawn,
): Promise<boolean> {
  // Only web pages: a launcher given `file:` or an app's own scheme would run whatever handles it.
  if (!/^https?:\/\//i.test(url)) return false;
  const launchers: [string, string[]][] = browserCandidates(env).map((candidate) => {
    const parts = candidate.split(/\s+/);
    return candidate.includes("%s")
      ? [parts[0]!, parts.slice(1).map((p) => p.replaceAll("%s", url))]
      : [parts.length === 1 ? candidate : parts[0]!, parts.length === 1 ? [url] : [...parts.slice(1), url]];
  });
  if (platform !== "linux" || env.DISPLAY || env.WAYLAND_DISPLAY) {
    launchers.push(
      platform === "darwin"
        ? ["open", [url]]
        : platform === "win32"
          ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
          : ["xdg-open", [url]],
    );
  }
  for (const [cmd, args] of launchers) {
    if (await launch(spawnImpl, cmd, args)) return true;
  }
  return false;
}

function launch(spawnImpl: typeof spawn, cmd: string, args: string[]): Promise<boolean> {
  return new Promise((resolve) => {
    let timer: NodeJS.Timeout | undefined;
    const done = (ok: boolean) => {
      clearTimeout(timer);
      resolve(ok);
    };
    try {
      // Detached with no stdio, and unref'd once it starts, so a browser that stays open does not
      // keep `gxy` running after login is done.
      const child = spawnImpl(cmd, args, { detached: true, stdio: "ignore" });
      timer = setTimeout(() => {
        child.unref();
        done(false);
      }, SPAWN_TIMEOUT_MS);
      child.once("error", () => done(false));
      child.once("spawn", () => {
        child.unref();
        done(true);
      });
    } catch {
      done(false);
    }
  });
}
