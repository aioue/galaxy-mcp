import { Command, Option } from "commander";
import type { AuthDeps } from "./types";
import { loginCommand } from "./commands/login";
import { statusCommand } from "./commands/status";
import { tokenCommand } from "./commands/token";
import { envCommand, SHELLS } from "./commands/env";
import { headersCommand } from "./commands/headers";
import { logoutCommand } from "./commands/logout";
import { EX_SOFTWARE } from "../exit";

/** `--scopes a,b` or `--scopes "a b"`. */
export function parseScopes(value: string): string[] {
  return value.split(/[,\s]+/).filter(Boolean);
}

/**
 * Add the `auth` group. `makeDeps` is called per invocation, so `--help` and the other
 * commands never touch the keyring or the network.
 */
export function registerAuth(program: Command, makeDeps: (commandName: string) => AuthDeps): void {
  const commandName = program.name();
  const auth = program.command("auth").description("Log in to a Galaxy and manage stored credentials");
  const host = () => new Option("--host <url>", "Galaxy base URL (default: GALAXY_URL, or the only stored login)");

  const run = async (fn: (deps: AuthDeps) => Promise<number>): Promise<void> => {
    let deps: AuthDeps;
    try {
      deps = makeDeps(commandName);
    } catch (e) {
      console.error((e as Error).message);
      process.exitCode = EX_SOFTWARE;
      return;
    }
    process.exitCode = await fn(deps);
  };

  auth
    .command("login")
    .description("Log in with the device flow, or store an API key from stdin")
    .addOption(host())
    .option("--scopes <list>", "scopes to request, comma- or space-separated (default: the server's)", parseScopes)
    .option("--no-browser", "do not offer to open the approval page in a browser")
    .option("--with-token", "read an existing API key from stdin instead of the device flow")
    .option("--insecure-storage", "store the token in a file instead of the system keyring")
    .action((o) =>
      run(async (deps) => {
        const ac = new AbortController();
        const onSig = () => ac.abort();
        process.once("SIGINT", onSig);
        try {
          return await loginCommand({ ...o, signal: ac.signal }, deps);
        } finally {
          process.removeListener("SIGINT", onSig);
        }
      }),
    );

  auth
    .command("status")
    .description("Show stored logins and check them against Galaxy")
    .addOption(host())
    .option("--json", "print JSON to stdout (always exits 0)")
    .option("--show-token", "do not mask tokens")
    .action((o) => run((deps) => statusCommand(o, deps)));

  auth
    .command("token")
    .description("Print the stored token (stdout)")
    .addOption(host())
    .option("--json", "print a JSON object with the token and its expiry")
    .action((o) => run((deps) => tokenCommand(o, deps)));

  auth
    .command("env")
    .description("Print GALAXY_URL and GALAXY_API_KEY assignments, for eval")
    .addOption(host())
    .addOption(new Option("--shell <shell>", "shell syntax").choices([...SHELLS]).default("sh"))
    .action((o) => run((deps) => envCommand(o, deps)));

  auth
    .command("headers")
    .description("Print the request headers as JSON, for an MCP headersHelper")
    .addOption(host())
    .action((o) => run((deps) => headersCommand(o, deps)));

  auth
    .command("logout")
    .description("Revoke the token where possible and delete the stored login")
    .addOption(host())
    .action((o) => run((deps) => logoutCommand(o, deps)));
}
