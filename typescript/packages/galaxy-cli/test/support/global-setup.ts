// One parent temp directory for the whole run, removed at the end. Each test file gets a
// subdirectory of it from `safe-env.ts`, so nothing is left behind even when a worker is killed
// (a worker process never runs `process.on("exit")` handlers).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export default function setup(): () => void {
  const root = mkdtempSync(join(tmpdir(), "gxy-test-home-"));
  // Workers are started after this, so they inherit it.
  process.env.GXY_TEST_ROOT = root;
  return () => rmSync(root, { recursive: true, force: true });
}
