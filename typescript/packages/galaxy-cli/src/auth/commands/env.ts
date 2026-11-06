import { AuthError, type AuthDeps } from "../types";
import { fail, requireLogin } from "./common";

export type Shell = "sh" | "fish" | "powershell";
export const SHELLS: readonly Shell[] = ["sh", "fish", "powershell"];

export interface EnvOptions {
  host?: string;
  shell?: string;
}

/** Single-quote for the shell, so no value can break out of the quotes. */
export function quoteFor(shell: Shell, value: string): string {
  switch (shell) {
    case "sh":
      return `'${value.replace(/'/g, `'\\''`)}'`;
    case "fish":
      // Inside fish single quotes only \' and \\ are special.
      return `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
    case "powershell":
      return `'${value.replace(/'/g, "''")}'`;
  }
}

function assign(shell: Shell, name: string, value: string): string {
  const q = quoteFor(shell, value);
  switch (shell) {
    case "sh":
      return `export ${name}=${q}`;
    case "fish":
      return `set -gx ${name} ${q}`;
    case "powershell":
      return `$env:${name} = ${q}`;
  }
}

export async function envCommand(opts: EnvOptions, deps: AuthDeps): Promise<number> {
  try {
    const shell = (opts.shell ?? "sh") as Shell;
    if (!SHELLS.includes(shell)) throw new AuthError("usage", `Unknown shell "${opts.shell}". Use one of: ${SHELLS.join(", ")}.`);
    const login = await requireLogin(deps, opts.host);
    deps.io.stdout.write(`${assign(shell, "GALAXY_URL", login.baseUrl)}\n${assign(shell, "GALAXY_API_KEY", login.token)}\n`);
    return 0;
  } catch (e) {
    return fail(deps, e);
  }
}
