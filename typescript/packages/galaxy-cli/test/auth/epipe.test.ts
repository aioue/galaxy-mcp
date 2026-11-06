import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { exitQuietlyOnEpipe } from "../../src/auth/epipe";

const epipe = () => Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
const eio = () => Object.assign(new Error("disk"), { code: "EIO" });

describe("exitQuietlyOnEpipe", () => {
  it("on stdout exits quietly with 0, and rethrows any other error", () => {
    const stdout = new PassThrough();
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout, stderr: new PassThrough() }, (c) => void codes.push(c));
    stdout.emit("error", epipe());
    expect(codes).toEqual([0]);
    expect(() => stdout.emit("error", eio())).toThrow("disk");
  });

  it("on stderr does not exit, silences later stderr writes, and rethrows any other error", () => {
    const [stdout, stderr] = [new PassThrough(), new PassThrough()];
    const codes: number[] = [];
    exitQuietlyOnEpipe({ stdout, stderr }, (c) => void codes.push(c));
    expect(() => stderr.emit("error", epipe())).not.toThrow();
    expect(codes).toEqual([]);
    expect(stderr.write("more\n")).toBe(true);
    expect(stderr.read()).toBeNull();
    expect(() => stderr.emit("error", eio())).toThrow("disk");
  });

  // The one test with a real pipe. It needs bash and head, and Node able to load the module's
  // TypeScript source directly (Node 22.19 or later, which `engines` requires).
  it.skipIf(process.platform === "win32")("a real closed pipe ends the process quietly, with no stack trace", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gxy-epipe-"));
    try {
      const script = join(dir, "writer.mjs");
      const errFile = join(dir, "err");
      await writeFile(
        script,
        `import { exitQuietlyOnEpipe } from ${JSON.stringify(new URL("../../src/auth/epipe.ts", import.meta.url).href)};
exitQuietlyOnEpipe();
const chunk = "fake-token-".repeat(100000);
for (let i = 0; i < 50; i++) process.stdout.write(chunk);
process.stdout.write("\\n");`,
      );
      const r = spawnSync("bash", ["-c", `node ${JSON.stringify(script)} 2>${JSON.stringify(errFile)} | head -c1 >/dev/null; echo \${PIPESTATUS[0]}`], {
        encoding: "utf8",
        timeout: 20_000,
      });
      expect(r.stdout.trim()).toBe("0");
      expect(await readFile(errFile, "utf8")).toBe("");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
