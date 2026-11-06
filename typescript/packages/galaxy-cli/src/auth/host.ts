import { normalizeBaseUrl } from "./base-url";
import { AuthError, type BaseUrl, type CredentialStore } from "./types";

export interface ResolveHostInput {
  /** `--host`. */
  explicit?: string;
  env: Record<string, string | undefined>;
  /** Values from `.env` in the working directory. */
  dotenv: Record<string, string | undefined>;
  store: Pick<CredentialStore, "list">;
  /** Name to show in messages. */
  commandName?: string;
}

/** Which Galaxy a command means: `--host`, `GALAXY_URL` (env, then .env), the only stored login. */
export async function resolveHost(input: ResolveHostInput): Promise<BaseUrl> {
  const named = input.explicit || input.env.GALAXY_URL || input.dotenv.GALAXY_URL;
  if (named) return normalizeBaseUrl(named);
  const stored = await input.store.list();
  if (stored.length === 1) return stored[0]!.baseUrl;
  if (stored.length === 0) {
    throw new AuthError("usage", "No Galaxy given and none logged in. Pass --host <url>.");
  }
  throw new AuthError(
    "ambiguous_host",
    `Logged in to several Galaxies; say which with --host:\n${stored.map((s) => `  ${s.baseUrl}`).join("\n")}`,
  );
}
