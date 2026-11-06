import { describe, expect, it } from "vitest";
import { KeyringStore, KeyringUnavailableError } from "../../src/auth/keyring-store";
import { FakeKeyring, fakeLogin } from "./support";

const { baseUrl } = fakeLogin();

describe("KeyringStore", () => {
  it("keys entries by gxy:<baseUrl> and username", async () => {
    const kr = new FakeKeyring();
    const s = new KeyringStore(kr, 50);
    await s.set(baseUrl, "alice", "FAKE");
    expect([...kr.data.keys()]).toEqual([`gxy:${baseUrl}|alice`]);
    expect(await s.get(baseUrl, "alice")).toBe("FAKE");
    expect(await s.delete(baseUrl, "alice")).toBe(true);
  });
  it("times out a hung backend", async () => {
    const kr = new FakeKeyring();
    kr.mode = "hang";
    await expect(new KeyringStore(kr, 20).get(baseUrl, "alice")).rejects.toThrow(KeyringUnavailableError);
  });
  it("wraps backend errors", async () => {
    const kr = new FakeKeyring();
    kr.mode = "throw";
    await expect(new KeyringStore(kr, 50).set(baseUrl, "a", "x")).rejects.toThrow(/system keyring failed/);
  });
});

describe("KeyringStore.delete is verified", () => {
  it("reads back after deleting and reports the secret may remain when it is still there", async () => {
    const kr = new FakeKeyring();
    const s = new KeyringStore(kr, 50);
    await s.set(baseUrl, "alice", "FAKE");
    kr.mode = "undeletable";
    await expect(s.delete(baseUrl, "alice")).rejects.toThrow(/may remain/);
  });
  it("reports false when there was nothing to delete, and does not throw", async () => {
    expect(await new KeyringStore(new FakeKeyring(), 50).delete(baseUrl, "alice")).toBe(false);
  });
});
