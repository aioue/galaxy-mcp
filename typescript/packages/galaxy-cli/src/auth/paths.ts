import { join } from "node:path";

/**
 * Where `gxy` keeps its files: `$GXY_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gxy`, else
 * `~/.config/gxy`: gh's order (`GH_CONFIG_DIR`, `XDG_CONFIG_HOME`, `~/.config/gh`) with `gxy` in
 * place of `gh`. Env and home directory are parameters so tests never see the real ones.
 *
 * Empty variables count as unset, and a relative `XDG_CONFIG_HOME` is ignored, as the XDG spec
 * says: a relative path would put the credential file wherever the command happened to be run,
 * possibly inside a repository.
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
