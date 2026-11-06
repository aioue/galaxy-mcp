import { join } from "node:path";

/**
 * Where `gxy` keeps its files: `$GXY_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gxy`, else
 * `~/.config/gxy`. Env and home directory are parameters so tests never see the real ones.
 * Empty variables count as unset, and relative `XDG_CONFIG_HOME` is ignored (the XDG spec
 * says so, and a relative path would move the file with the working directory).
 */
export function configDir(env: Record<string, string | undefined>, home: string): string {
  if (env.GXY_CONFIG_DIR) return env.GXY_CONFIG_DIR;
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg && xdg.startsWith("/")) return join(xdg, "gxy");
  return join(home, ".config", "gxy");
}

export function hostsFile(dir: string): string {
  return join(dir, "hosts.yml");
}
