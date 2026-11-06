// PLACEHOLDER for the integration agent: replace with the real wiring (store, discover,
// whoami, resolveHost, openBrowser, process io/env). `registerAuth` calls this lazily,
// so only an `auth` subcommand fails until it is written.
import type { AuthDeps } from "./types";

export function createAuthDeps(_commandName: string): AuthDeps {
  throw new Error("auth is not wired yet (src/auth/deps.ts is a placeholder)");
}
