// A safety net for every test file: whatever a test forgets to inject, the real keyring and the
// real config directory stay out of reach. The keyring is off, and the config dir and HOME are an
// empty temp directory. Tests that need something else set it themselves (vi.stubEnv, or an `env`
// they pass in), and the one test that runs the real keyring child does so against a fake bus.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "gxy-test-home-"));
process.env.HOME = home;
process.env.XDG_CONFIG_HOME = join(home, "xdg");
process.env.GXY_CONFIG_DIR = join(home, "gxy");
process.env.GXY_NO_KEYRING = "1";
delete process.env.DBUS_SESSION_BUS_ADDRESS;
process.on("exit", () => rmSync(home, { recursive: true, force: true }));
