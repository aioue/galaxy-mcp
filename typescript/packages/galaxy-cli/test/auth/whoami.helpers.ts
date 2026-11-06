import { discover } from "../../src/auth/oauth";
import type { BaseUrl } from "../../src/auth/types";
import type { FakeGalaxy } from "../support/fake-galaxy";

/** Run a device login against the fake and return the token it issued. */
export async function startDevice(galaxy: FakeGalaxy, opts: { admin?: boolean } = {}): Promise<string> {
  const server = await discover(galaxy.baseUrl as BaseUrl);
  const pending = await server.startDeviceLogin();
  galaxy.approve(pending.userCode, { expiresIn: 3600, ...opts });
  return (await pending.waitForApproval()).accessToken;
}
