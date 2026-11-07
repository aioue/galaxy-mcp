// A write that fails midway, and the rule that the temp file is never a pre-planted symlink. Both need the
// filesystem and the temp-file name under test control, so `node:fs/promises` and `randomBytes`
// are wrapped here (passing through unless a test arms them), in a file of their own.
import { mkdir, readdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const arm = vi.hoisted(() => ({
  failWrite: false,
  failRename: false,
  fixedRandom: undefined as number[] | undefined,
}));

vi.mock("node:crypto", async (orig) => {
  const actual = await orig<typeof import("node:crypto")>();
  return { ...actual, randomBytes: (n: number) => (arm.fixedRandom ? Buffer.from(arm.fixedRandom) : actual.randomBytes(n)) };
});

vi.mock("node:fs/promises", async (orig) => {
  const actual = await orig<typeof import("node:fs/promises")>();
  return {
    ...actual,
    async open(path: string, flags?: unknown, mode?: unknown) {
      const fh = await (actual.open as (...a: unknown[]) => Promise<import("node:fs/promises").FileHandle>)(path, flags, mode);
      if (!arm.failWrite || !String(path).includes(".hosts.")) return fh;
      return new Proxy(fh, {
        get(target, prop) {
          if (prop === "writeFile") return async () => { throw new Error("disk full"); };
          const v = Reflect.get(target, prop) as unknown;
          return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
        },
      });
    },
    async rename(from: string, to: string) {
      if (arm.failRename) throw new Error("rename refused");
      return actual.rename(from, to);
    },
  };
});

const { FileStore } = await import("../../src/auth/file-store");
const { FAKE_TOKEN, fakeLogin, useTempDir } = await import("./harness");

const tmp = useTempDir("gxy-fsw-");
beforeEach(() => {
  arm.failWrite = false;
  arm.failRename = false;
  arm.fixedRandom = undefined;
});

const rec = () => {
  const { token, ...rest } = fakeLogin();
  return { ...rest, storage: "file" as const, token };
};
const prior = "hosts: {}\n";

describe.each([
  ["writing the temp file", () => { arm.failWrite = true; }, /disk full/],
  ["renaming it into place", () => { arm.failRename = true; }, /rename refused/],
] as const)("a failure while %s", (_when, breakIt, why) => {
  async function failedPut() {
    const dir = join(tmp.path, "cfg");
    await mkdir(dir, { mode: 0o700 });
    const s = new FileStore(dir);
    await writeFile(s.path, prior, { mode: 0o600 });
    breakIt();
    await expect(s.put(rec())).rejects.toThrow(why);
    return s;
  }

  it("propagates the error and leaves the existing hosts.yml as it was", async () => {
    const s = await failedPut();
    expect(await readFile(s.path, "utf8")).toBe(prior);
  });

  it("leaves no temp file, which would hold the token", async () => {
    const s = await failedPut();
    expect(await readdir(s.dir)).toEqual(["hosts.yml"]);
  });
});

describe("the temp file", () => {
  it("is never a pre-planted symlink: the write fails rather than follow it", async () => {
    const dir = join(tmp.path, "cfg");
    await mkdir(dir, { mode: 0o700 });
    arm.fixedRandom = [1, 2, 3, 4, 5, 6];
    const victim = join(tmp.path, "victim");
    await writeFile(victim, "untouched");
    await symlink(victim, join(dir, `.hosts.${process.pid}.010203040506.tmp`));
    const s = new FileStore(dir);
    await expect(s.put(rec())).rejects.toThrow(/EEXIST/);
    expect(await readFile(victim, "utf8")).toBe("untouched");
    expect(await readFile(victim, "utf8")).not.toContain(FAKE_TOKEN);
  });
});
