import type { KeyringBackend } from "../../src/auth/keyring-store";
import { normalizeBaseUrl } from "../../src/auth/base-url";
import type { StoredLogin } from "../../src/auth/types";

export function fakeLogin(over: Partial<StoredLogin> = {}): StoredLogin {
  return {
    baseUrl: normalizeBaseUrl("https://galaxy.example.org"),
    username: "alice",
    token: "FAKE-TOKEN-1",
    method: "device",
    scopes: ["histories:read"],
    expiresAt: null,
    obtainedAt: "2026-01-01T00:00:00.000Z",
    ...over,
  };
}

/** In-memory keyring. `mode` makes it fail, hang, or accept writes it cannot serve. */
export class FakeKeyring implements KeyringBackend {
  data = new Map<string, string>();
  mode: "ok" | "throw" | "hang" | "lossy" = "ok";
  private gate() {
    if (this.mode === "throw") return Promise.reject(new Error("no secret service"));
    if (this.mode === "hang") return new Promise<never>(() => {});
    return undefined;
  }
  async get(service: string, account: string) {
    await this.gate();
    return this.data.get(`${service}|${account}`) ?? null;
  }
  async set(service: string, account: string, secret: string) {
    await this.gate();
    if (this.mode !== "lossy") this.data.set(`${service}|${account}`, secret);
  }
  async delete(service: string, account: string) {
    await this.gate();
    return this.data.delete(`${service}|${account}`);
  }
}
