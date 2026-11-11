/**
 * The server contract for `gxy auth login`'s device flow (checks.ts), run against a Galaxy.
 *
 * By default it runs against the in-repo fake Galaxy, to show that the fake honours the contract.
 * That is what CI does. Set `GXY_CONTRACT_GALAXY_URL` to run it against a real Galaxy instead, and
 * it fails, naming the RFC, wherever that Galaxy does not meet the contract.
 *
 *   GXY_CONTRACT_GALAXY_URL   The Galaxy's base URL, e.g. https://galaxy.example.org or
 *                             https://example.org/galaxy. Switches the suite to that Galaxy.
 *   GXY_CONTRACT_DEVICE_LOGIN Set to 1 to get a token by running a device login: the suite prints a
 *                             code and a URL on stderr, and you approve it in a browser. This is
 *                             the only way to see the `token_type` the server really answers.
 *   GXY_CONTRACT_TOKEN        Instead, a token you already hold. `GXY_CONTRACT_TOKEN_TYPE` is the
 *                             `token_type` its response carried; without it the type check is skipped.
 *   GXY_CONTRACT_ALLOW_REVOKE Set to 1 to let the suite revoke that token. Revocation kills it, and
 *                             where the token is a user's API key it kills the key everywhere.
 *
 * What needs a real Galaxy, or a real token, is therefore skipped in CI and listed in the report that
 * came with this suite. The proxy and TLS variables are cleared for tests (leaky-env.ts), so a Galaxy
 * behind a proxy or a private CA is not reachable from here.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  startFakeGalaxy,
  type FakeGalaxy,
  type FakeGalaxyOptions,
} from "../../support/fake-galaxy";
import {
  ContractViolation,
  checkRevocationAdvertised,
  checkRevocationWorks,
  checkTokenTypeHonest,
  fetchMetadata,
  obtainGrant,
  type Grant,
  type Metadata,
} from "./checks";

const REAL_URL = process.env.GXY_CONTRACT_GALAXY_URL?.replace(/\/+$/, "");

/** What the checks run against: a base URL, and a way to get a token from it, if there is one. */
interface Target {
  baseUrl: string;
  /** A token response from this server, or why there is none. Fetched once and shared. */
  grant(): Promise<Grant | { skip: string }>;
  /** Whether the suite may revoke the token it was given. */
  mayRevoke: boolean;
}

/** Approve a device login on the fake as soon as it asks. */
const grantFromFake = (galaxy: FakeGalaxy) => async (metadata: Metadata) =>
  obtainGrant(
    metadata,
    ({ user_code }) => {
      galaxy.approve(user_code);
    },
    { timeoutMs: 10_000 },
  );

function realTarget(baseUrl: string): Target {
  let memo: Promise<Grant | { skip: string }> | undefined;
  return {
    baseUrl,
    mayRevoke: process.env.GXY_CONTRACT_ALLOW_REVOKE === "1",
    grant: () =>
      (memo ??= (async () => {
        const token = process.env.GXY_CONTRACT_TOKEN;
        if (token)
          return {
            access_token: token,
            ...(process.env.GXY_CONTRACT_TOKEN_TYPE
              ? { token_type: process.env.GXY_CONTRACT_TOKEN_TYPE }
              : {}),
          };
        if (process.env.GXY_CONTRACT_DEVICE_LOGIN !== "1")
          return {
            skip: "set GXY_CONTRACT_DEVICE_LOGIN=1 or GXY_CONTRACT_TOKEN to get a token",
          };
        const metadata = await fetchMetadata(baseUrl);
        return obtainGrant(metadata, (d) => {
          process.stderr.write(
            `\n[contract] Approve the device login: open ${d.verification_uri} and enter ${d.user_code}\n`,
          );
        });
      })()),
  };
}

/** The checks, in order: revocation last, since it kills the token the others use. */
function contract(
  describeName: string,
  make: () => Promise<{ target: Target; close?: () => Promise<void> }>,
) {
  // eslint-disable-next-line vitest/valid-title -- the title is this helper's parameter
  describe(describeName, () => {
    let target: Target;
    let close: (() => Promise<void>) | undefined;
    beforeAll(async () => {
      ({ target, close } = await make());
    }, 30_000);
    afterAll(async () => {
      await close?.();
    });
    const metadata = () => fetchMetadata(target.baseUrl);

    it("serves its metadata at the RFC 8414 location for its issuer", async () => {
      await expect(metadata()).resolves.toMatchObject({ issuer: target.baseUrl });
    });

    it("advertises a revocation_endpoint in its metadata", async () => {
      const m = await metadata();
      expect(() => {
        checkRevocationAdvertised(m);
      }).not.toThrow();
    });

    it(
      "answers a token_type that the token is accepted under",
      { timeout: 20 * 60_000 },
      async ({ skip }) => {
        const g = await target.grant();
        if ("skip" in g) return skip(g.skip);
        if (g.token_type === undefined && REAL_URL && process.env.GXY_CONTRACT_TOKEN)
          return skip("with GXY_CONTRACT_TOKEN, set GXY_CONTRACT_TOKEN_TYPE as well");
        await expect(checkTokenTypeHonest(target.baseUrl, g)).resolves.toBeUndefined();
      },
    );

    it(
      "revokes an issued token (RFC 7009), after which it is rejected",
      { timeout: 20 * 60_000 },
      async ({ skip }) => {
        if (!target.mayRevoke)
          return skip("revoking kills the token: set GXY_CONTRACT_ALLOW_REVOKE=1");
        const g = await target.grant();
        if ("skip" in g) return skip(g.skip);
        await expect(
          checkRevocationWorks(target.baseUrl, await metadata(), g),
        ).resolves.toBeUndefined();
      },
    );
  });
}

// Against the fake, at the root and under a prefix (the path-inserted form of the metadata).
describe.skipIf(REAL_URL)("the in-repo fake Galaxy meets the contract", () => {
  for (const pathPrefix of [undefined, "/galaxy"]) {
    contract(pathPrefix ? `served under ${pathPrefix}` : "served at the root", async () => {
      const galaxy = await startFakeGalaxy({ pathPrefix });
      let memo: Promise<Grant> | undefined;
      return {
        close: () => galaxy.close(),
        target: {
          baseUrl: galaxy.baseUrl,
          mayRevoke: true,
          grant: () => (memo ??= fetchMetadata(galaxy.baseUrl).then(grantFromFake(galaxy))),
        },
      };
    });
  }
});

// Against a real Galaxy, when GXY_CONTRACT_GALAXY_URL names one.
if (REAL_URL)
  contract(`the Galaxy at ${REAL_URL}`, async () => ({
    target: realTarget(REAL_URL),
  }));

// -------------------------------------------------------------------------------------------------
// NEGATIVE CONTROLS. These test the checks, not a server we support: each runs a check against a
// fake that has been deliberately broken in the way the check is for, and asserts that the check
// reports exactly that defect. Without them a check that always passed would look the same as a
// server that met the contract. The broken fakes use options marked "defect injection" in
// fake-galaxy.ts, and nothing else should.
// -------------------------------------------------------------------------------------------------
describe.skipIf(REAL_URL)(
  "negative controls: the checks catch a deliberately broken server",
  () => {
    const open: FakeGalaxy[] = [];
    afterAll(async () => {
      await Promise.all(open.map((g) => g.close()));
    });
    const broken = async (options: FakeGalaxyOptions) => {
      const g = await startFakeGalaxy(options);
      open.push(g);
      return g;
    };
    it("metadata only inside the prefix: the metadata check says RFC 8414 §3.1 and names the prefix", async () => {
      const g = await broken({
        pathPrefix: "/galaxy",
        metadataLocation: "in-prefix",
      });
      await expect(fetchMetadata(g.baseUrl)).rejects.toThrow(ContractViolation);
      await expect(fetchMetadata(g.baseUrl)).rejects.toThrow(
        /RFC 8414 §3\.1: expected .*HTTP 404.*only inside the prefix/,
      );
    });

    it("metadata that names another issuer: the metadata check says RFC 8414 §3.3", async () => {
      const g = await broken({});
      g.setMetadataMode("wrong-issuer");
      await expect(fetchMetadata(g.baseUrl)).rejects.toThrow(/RFC 8414 §3\.3/);
    });

    it("no revocation_endpoint: the advertisement check says so, naming RFC 7009", async () => {
      const g = await broken({ revocationEndpoint: false });
      const metadata = await fetchMetadata(g.baseUrl);
      expect(() => {
        checkRevocationAdvertised(metadata);
      }).toThrow(/RFC 7009 §2.*no "revocation_endpoint"/);
    });

    it("a revocation endpoint that does not exist: the revocation check says RFC 7009 §2.2", async () => {
      const g = await broken({});
      g.setMetadataOverrides({
        revocation_endpoint: `${g.baseUrl}/oauth/nowhere`,
      });
      const metadata = await fetchMetadata(g.baseUrl);
      const grant = await grantFromFake(g)(metadata);
      await expect(checkRevocationWorks(g.baseUrl, metadata, grant)).rejects.toThrow(
        /RFC 7009 §2\.2.*HTTP 404/,
      );
    });

    it("Bearer advertised but the token accepted only as x-api-key: the token_type check says RFC 6750", async () => {
      const g = await broken({ acceptBearer: false });
      const grant = await grantFromFake(g)(await fetchMetadata(g.baseUrl));
      expect(grant.token_type).toBe("Bearer");
      await expect(checkTokenTypeHonest(g.baseUrl, grant)).rejects.toThrow(
        /RFC 6750 §2\.1.*token_type "Bearer".*does not accept the token as "Authorization: Bearer.*x-api-key/,
      );
    });

    it("no token_type in the response: the token_type check says RFC 6749 §5.1", async () => {
      const g = await broken({ tokenType: null });
      const grant = await grantFromFake(g)(await fetchMetadata(g.baseUrl));
      await expect(checkTokenTypeHonest(g.baseUrl, grant)).rejects.toThrow(/RFC 6749 §5\.1/);
    });

    it("the same checks pass on an unbroken fake, so the controls above fail for their defect alone", async () => {
      const g = await broken({ pathPrefix: "/galaxy" });
      const metadata = await fetchMetadata(g.baseUrl);
      const grant = await grantFromFake(g)(metadata);
      expect(() => {
        checkRevocationAdvertised(metadata);
      }).not.toThrow();
      await expect(checkTokenTypeHonest(g.baseUrl, grant)).resolves.toBeUndefined();
    });
  },
);
