/** Actual production cache TTL, real time, TLS and PostgreSQL. No cache/Date overrides. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Pool } from "pg";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { tlsFixture } from "./helpers.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
process.env.NODE_ENV = "test";
test(
  "real 60 second JWKS cache propagation window preserves current policy, rejects fresh old-key proof after TTL, and keeps issued tokens",
  { timeout: 80000 },
  async () => {
    assert.ok(process.env.DATABASE_URL, "Use test:cache-window");
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 8,
    });
    const tls = await tlsFixture();
    const old = await generateKeyPair("ES256"),
      next = await generateKeyPair("ES256");
    const oldJwk = {
        ...(await exportJWK(old.publicKey)),
        kid: "old-key",
        alg: "ES256",
        use: "sig",
      },
      newJwk = {
        ...(await exportJWK(next.publicKey)),
        kid: "new-key",
        alg: "ES256",
        use: "sig",
      };
    let keys = [oldJwk, newJwk];
    let metadataGets = 0,
      jwksGets = 0,
      origin = "";
    const phases: Array<{
      phase: string;
      elapsedMs: number;
      metadataGets: number;
      jwksGets: number;
    }> = [];
    let start = Date.now();
    const report = (phase: string) => {
      const value = {
        phase,
        elapsedMs: Date.now() - start,
        metadataGets,
        jwksGets,
      };
      phases.push(value);
      process.stdout.write(JSON.stringify(value) + "\n");
    };
    try {
      const publisher = await tls.start((req, res) => {
        res.setHeader("content-type", "application/json");
        if (req.url === "/jwks.json") {
          jwksGets++;
          res.end(JSON.stringify({ keys }));
        } else if (req.url === "/client.json") {
          metadataGets++;
          res.end(
            JSON.stringify({
              client_id: origin + "/client.json",
              jwks_uri: origin + "/jwks.json",
              grant_types: ["client_credentials"],
              response_types: [],
              redirect_uris: [],
              token_endpoint_auth_method: "private_key_jwt",
              token_endpoint_auth_signing_alg: "ES256",
            }),
          );
        } else {
          res.statusCode = 404;
          res.end("{}");
        }
      });
      origin = publisher.origin;
      let handler: ReturnType<typeof createAuthorizationServer>;
      const as = await tls.start((req, res) => handler(req, res), "auth.test");
      const id = origin + "/client.json",
        resource = "https://resource.example/mcp",
        rsSecret = "isolated-cache-window-resource-secret-32-bytes";
      const store = new PostgresStore(pool, as.origin);
      await store.configureRequestLimits({
        globalMinute: 120,
        originMinute: 40,
        clientMinute: 20,
        sourceMinute: 60,
      });
      await store.configurePolicy({
        resource,
        scopes: ["catalog.read"],
        ttl: 300,
        maxNewClientsHour: 10,
        maxRequestsClientMinute: 20,
        maxRequestsMinute: 60,
        custodyCondition: "Isolated native cache propagation component",
        enabled: true,
      });
      await store.provisionResourceServer("cache-window-rs", rsSecret, [
        resource,
      ]);
      const authenticator = new ClientAuthenticator(tls.fetcher(), as.origin);
      handler = createAuthorizationServer(store, authenticator, [
        "catalog.read",
      ]);
      const fresh = async (which: "old" | "new") => {
        const now = Math.floor(Date.now() / 1000);
        const claims = {
          iss: id,
          sub: id,
          aud: as.origin,
          iat: now,
          exp: now + 60,
          jti: crypto.randomUUID(),
        };
        return {
          claims,
          assertion: await new SignJWT(claims)
            .setProtectedHeader({
              alg: "ES256",
              kid: which === "old" ? "old-key" : "new-key",
            })
            .sign(which === "old" ? old.privateKey : next.privateKey),
        };
      };
      const request = async (assertion: string) =>
        tls.http(
          as.origin + "/oauth/token",
          new URLSearchParams({
            grant_type: "client_credentials",
            client_id: id,
            client_assertion_type:
              "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: assertion,
            resource,
            scope: "catalog.read",
          }).toString(),
          { "content-type": "application/x-www-form-urlencoded" },
        );
      start = Date.now();
      const initialProof = await fresh("old");
      const verified = await authenticator.authenticate(
        id,
        initialProof.assertion,
      );
      const expiry = verified.metadataExpires;
      const verifiedAt = Date.now();
      const remainingAtVerificationMs = expiry * 1000 - verifiedAt;
      // This boundary begins after loading, rather than before TLS/JWK retrieval.
      // Whole-second rounding may shorten it; assertion clock tolerance does not extend the cache.
      assert.ok(
        remainingAtVerificationMs > 58000 && remainingAtVerificationMs <= 60000,
        "Recorded real default 60 second cache lifetime after loading",
      );
      const initial = await request(initialProof.assertion);
      assert.equal(initial.status, 200);
      const oldToken = JSON.parse(initial.body).access_token;
      const subject = (
        await store.introspect("cache-window-rs", rsSecret, oldToken)
      ).sub;
      assert.equal(metadataGets, 1);
      assert.equal(jwksGets, 1);
      keys = [newJwk];
      report("publisher-removed-old-key");
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const early = await request((await fresh("old")).assertion);
      assert.equal(early.status, 200);
      assert.equal(jwksGets, 1);
      report("fresh-old-proof-accepted-within-cache");
      // Both kids were in the original snapshot: using new must not force a cache reload.
      const cachedNew = await request((await fresh("new")).assertion);
      assert.equal(cachedNew.status, 200);
      assert.equal(jwksGets, 1);
      assert.equal(
        (
          await store.introspect(
            "cache-window-rs",
            rsSecret,
            JSON.parse(cachedNew.body).access_token,
          )
        ).sub,
        subject,
      );
      const lateTarget = (expiry - 2) * 1000 + 100;
      report("waiting-for-last-two-seconds-of-real-cache-window");
      await new Promise((resolve) =>
        setTimeout(resolve, Math.max(0, lateTarget - Date.now())),
      );
      const late = await request((await fresh("old")).assertion);
      assert.equal(late.status, 200);
      assert.equal(jwksGets, 1);
      report("fresh-old-proof-accepted-near-cache-expiry");
      await new Promise((resolve) =>
        setTimeout(resolve, Math.max(0, expiry * 1000 + 250 - Date.now())),
      );
      const after = await fresh("old");
      assert.ok(
        after.claims.exp * 1000 > Date.now() + 55000,
        "Old-key test assertion is fresh, not expired",
      );
      const rejected = await request(after.assertion);
      assert.equal(rejected.status, 401);
      assert.equal(JSON.parse(rejected.body).error, "invalid_client");
      // Expiry loads one new snapshot; missing kid then allows only its one bounded refresh.
      assert.equal(metadataGets, 3);
      assert.equal(jwksGets, 3);
      report("fresh-old-proof-rejected-after-real-cache-expiry");
      const newResponse = await request((await fresh("new")).assertion);
      assert.equal(newResponse.status, 200);
      assert.equal(jwksGets, 3);
      const newPrincipal = await store.introspect(
        "cache-window-rs",
        rsSecret,
        JSON.parse(newResponse.body).access_token,
      );
      assert.equal(newPrincipal.sub, subject);
      assert.equal(
        (await store.introspect("cache-window-rs", rsSecret, oldToken)).active,
        true,
      );
      assert.equal(
        (
          await pool.query(
            "SELECT count(*)::integer AS n FROM clients WHERE client_id=$1",
            [id],
          )
        ).rows[0].n,
        1,
      );
      process.stdout.write(
        JSON.stringify({
          passed: true,
          lane: "actual-60-second-cache-propagation-TLS-PG",
          configuredCacheTtlSeconds: 60,
          recordedCacheExpiresAt: expiry,
          actualRecordedLifetimeMs: expiry * 1000 - start,
          remainingAtVerificationMs,
          assertionClockToleranceSeconds: 5,
          cacheUsesAssertionSkew: false,
          afterTtlOldAssertionRemainingSeconds:
            after.claims.exp - Math.floor(Date.now() / 1000),
          oldTokenTtlSeconds: 300,
          oldAccessTokenStillActive: true,
          newKeyAccepted: true,
          stableMachineSubject: true,
          metadataGets,
          jwksGets,
          phases,
        }) + "\n",
      );
    } finally {
      await tls.close();
      await pool.end();
    }
  },
);
