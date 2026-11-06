import { describe, expect, it } from "vitest";
import { resolveHost } from "../../src/auth/host";
import { AuthError, type LoginSummary } from "../../src/auth/types";
import { fakeLogin } from "./support";

const summary = (url: string): LoginSummary => {
  const { token: _t, ...rest } = fakeLogin({ baseUrl: url as never });
  return { ...rest, storage: "file" };
};
const storeOf = (...urls: string[]) => ({ list: async () => urls.map(summary) });
const base = { env: {}, dotenv: {} };

describe("resolveHost", () => {
  it("prefers --host, then env, then .env, normalised", async () => {
    const store = storeOf("https://stored.example");
    expect(await resolveHost({ ...base, explicit: "Flag.example/", env: { GALAXY_URL: "https://env.example" }, store })).toBe("https://flag.example");
    expect(await resolveHost({ ...base, env: { GALAXY_URL: "https://env.example" }, dotenv: { GALAXY_URL: "https://dot.example" }, store })).toBe("https://env.example");
    expect(await resolveHost({ ...base, dotenv: { GALAXY_URL: "https://dot.example" }, store })).toBe("https://dot.example");
  });
  it("uses the only stored login", async () => {
    expect(await resolveHost({ ...base, store: storeOf("https://stored.example") })).toBe("https://stored.example");
  });
  it("fails with ambiguous_host listing several", async () => {
    const err = await resolveHost({ ...base, store: storeOf("https://a.example", "https://b.example") }).catch((e) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect(err.kind).toBe("ambiguous_host");
    expect(err.message).toContain("https://a.example");
    expect(err.message).toContain("https://b.example");
  });
  it("fails with usage when nothing is stored", async () => {
    await expect(resolveHost({ ...base, store: storeOf() })).rejects.toMatchObject({ kind: "usage" });
  });
  it("rejects insecure http", async () => {
    await expect(resolveHost({ ...base, explicit: "http://remote.example", store: storeOf() })).rejects.toMatchObject({ kind: "insecure" });
  });
});
