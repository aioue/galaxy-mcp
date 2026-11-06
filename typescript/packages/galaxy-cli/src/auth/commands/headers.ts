import type { AuthDeps } from "../types";
import { fail, requireLogin } from "./common";

export interface HeadersOptions {
  host?: string;
}

/** For Claude Code's MCP `headersHelper`: a JSON object of headers on stdout. */
export async function headersCommand(opts: HeadersOptions, deps: AuthDeps): Promise<number> {
  try {
    const login = await requireLogin(deps, opts.host);
    deps.io.stdout.write(`${JSON.stringify({ "x-api-key": login.token })}\n`);
    return 0;
  } catch (e) {
    return fail(deps, e);
  }
}
