// A safety net for every test file: whatever a test forgets to inject, the real keyring, the real
// config directory and the developer's own settings stay out of reach. The keyring is off, the
// config dir and HOME are an empty temp directory, and every variable the code reads, or Node reads
// for it (the proxy and TLS ones, see leaky-env.ts), is cleared.
// Tests that need something else set it themselves (vi.stubEnv, or an `env` they pass in), and
// the one test that runs the real keyring child does so against a fake bus.
//
// Not covered here: the working directory, which `loadSources` reads `.env` from. A test that
// runs it spies on `process.cwd` (see config.test.ts) or runs a child in a temp cwd.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";
import { LEAKY_ENV } from "./leaky-env.js";

// Under the run's parent directory (global-setup.ts, which removes it at the end). The fallback
// covers running this file without it; the afterAll removes the directory either way.
const home = mkdtempSync(join(process.env.GXY_TEST_ROOT ?? tmpdir(), "gxy-test-home-"));
process.env.HOME = home;
process.env.XDG_CONFIG_HOME = join(home, "xdg");
process.env.GXY_CONFIG_DIR = join(home, "gxy");
process.env.GXY_NO_KEYRING = "1";

// Everything under src/ that reads the environment, so a developer's own values cannot change a result.
for (const name of [
  "DBUS_SESSION_BUS_ADDRESS",
  "GALAXY_URL",
  "GALAXY_API_KEY",
  "CLAUDE_CODE_MCP_SERVER_URL",
  "GXY_OAUTH_CLIENT_ID",
  "BROWSER",
  "DISPLAY",
  "WAYLAND_DISPLAY",
  ...LEAKY_ENV,
]) {
  delete process.env[name];
}

afterAll(() => rmSync(home, { recursive: true, force: true }));
