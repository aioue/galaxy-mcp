import type { AuthDeps } from "../types";
import { fail, requireLogin } from "./common";

export interface TokenOptions {
  host?: string;
  json?: boolean;
}

export async function tokenCommand(opts: TokenOptions, deps: AuthDeps): Promise<number> {
  try {
    const login = await requireLogin(deps, opts.host);
    if (opts.json) {
      deps.io.stdout.write(
        `${JSON.stringify({ version: 1, base_url: login.baseUrl, token: login.token, token_type: "x-api-key", expires_at: login.expiresAt })}\n`,
      );
    } else {
      deps.io.stdout.write(`${login.token}\n`);
    }
    return 0;
  } catch (e) {
    return fail(deps, e);
  }
}
