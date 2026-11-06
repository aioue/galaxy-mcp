import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { exitQuietlyOnEpipe } from "../../src/auth/epipe";

describe("exitQuietlyOnEpipe", () => {
  it("exits 0 on EPIPE and rethrows anything else", () => {
    const s = new PassThrough();
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout: s, stderr: new PassThrough() }, (c) => void codes.push(c));
    s.emit("error", Object.assign(new Error("write EPIPE"), { code: "EPIPE" }));
    expect(codes).toEqual([0]);
    expect(() => s.emit("error", Object.assign(new Error("disk"), { code: "EIO" }))).toThrow("disk");
  });

  it("a real closed pipe ends the process quietly, with no stack trace", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gxy-epipe-"));
    try {
      const script = join(dir, "writer.mjs");
      // The module under test is loaded as TypeScript (Node strips the types; it imports nothing).
      await writeFile(
        script,
        `import { exitQuietlyOnEpipe } from ${JSON.stringify(new URL("../../src/auth/epipe.ts", import.meta.url).href)};
exitQuietlyOnEpipe();
const chunk = "fake-token-".repeat(100000);
for (let i = 0; i < 50; i++) process.stdout.write(chunk);
process.stdout.write("\\n");`,
      );
      const r = spawnSync("bash", ["-c", `node ${JSON.stringify(script)} 2>${JSON.stringify(join(dir, "err"))} | head -c1 >/dev/null; echo \${PIPESTATUS[0]}`], {
        encoding: "utf8",
        timeout: 20_000,
      });
      expect(r.stdout.trim()).toBe("0");
      const err = spawnSync("cat", [join(dir, "err")], { encoding: "utf8" }).stdout;
      expect(err).toBe("");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
