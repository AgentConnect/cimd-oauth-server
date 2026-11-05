import { test } from "node:test";
import assert from "node:assert/strict";
import { Pool } from "pg";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { auth, fetchToken } from "@modelcontextprotocol/sdk/client/auth.js";
import {
  PrivateKeyJwtProvider,
  StaticPrivateKeyJwtProvider,
} from "@modelcontextprotocol/sdk/client/auth-extensions.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  PostgresStore,
  type Policy,
} from "../packages/store-postgres/store.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
import { tlsFixture } from "./helpers.js";
process.env.NODE_ENV = "test";
test("Postgres authoritative transactions, independent TLS AS/RS, and actual MCP SDK tools", async (t) => {
  assert.ok(process.env.DATABASE_URL, "Use npm run test:postgres");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 8 });
  const pool2 = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 8,
  });
  const f = await tlsFixture();
  const pair = await generateKeyPair("ES256", { extractable: true });
  const otherPair = await generateKeyPair("ES256");
  let identityOrigin = "";
  let identityHits = 0;
  try {
    let pub = {
      ...(await exportJWK(pair.publicKey)),
      kid: "one",
      alg: "ES256",
      use: "sig",
    };
    const identity = await f.start((req, res) => {
      identityHits++;
      res.setHeader("content-type", "application/json");
      if (req.url === "/jwks") res.end(JSON.stringify({ keys: [pub] }));
      else
        res.end(
          JSON.stringify({
            client_id: identityOrigin + req.url,
            jwks_uri: identityOrigin + "/jwks",
            grant_types: ["client_credentials"],
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "ES256",
            response_types: [],
            redirect_uris: [],
          }),
        );
    });
    identityOrigin = identity.origin;
    const otherPublic = await exportJWK(otherPair.publicKey);
    let otherOrigin = "";
    const otherPublisher = await f.start((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/jwks")
        res.end(
          JSON.stringify({
            keys: [{ ...otherPublic, kid: "one", alg: "ES256", use: "sig" }],
          }),
        );
      else
        res.end(
          JSON.stringify({
            client_id: otherOrigin + req.url,
            jwks_uri: otherOrigin + "/jwks",
            grant_types: ["client_credentials"],
            response_types: [],
            token_endpoint_auth_methods_supported: ["private_key_jwt"],
          }),
        );
    }, "other.test");
    otherOrigin = otherPublisher.origin;
    // Listener indirection lets configured issuer/resource include their real isolated ports.
    let asHandler: ReturnType<typeof createAuthorizationServer>;
    const as = await f.start((req, res) => asHandler(req, res), "auth.test");
    const store = new PostgresStore(pool, as.origin);
    const replica = new PostgresStore(pool2, as.origin);
    let mcpHandler: ReturnType<typeof createMcpApp>;
    const mcp = await f.start((req, res) => mcpHandler(req, res), "mcp.test");
    const resource = mcp.origin + "/mcp";
    const secret = "x".repeat(48);
    const rsId = "reference-rs";
    const policy: Policy = {
      resource,
      scopes: ["agent.self.read", "catalog.read"],
      ttl: 60,
      maxNewClientsHour: 100,
      maxRequestsClientMinute: 100,
      maxRequestsMinute: 500,
      custodyCondition: "Isolated local-key component fixture only",
      enabled: true,
    };
    await store.configurePolicy(policy);
    await store.configureRequestLimits({
      globalMinute: 1000,
      originMinute: 1000,
      clientMinute: 1000,
      sourceMinute: 1000,
    });
    await store.provisionResourceServer(rsId, secret, [resource]);
    await store.ready();
    const authenticator = new ClientAuthenticator(f.fetcher(), as.origin);
    asHandler = createAuthorizationServer(store, authenticator, policy.scopes);
    const verifier = new TokenVerifier(f.fetcher(), {
      issuer: as.origin,
      introspectionEndpoint: as.origin + "/oauth/introspect",
      resource,
      rsId,
      rsSecret: secret,
      allowedScopes: policy.scopes,
    });
    mcpHandler = createMcpApp(verifier);
    const clientId = identityOrigin + "/client";
    const sign = async (
      id = clientId,
      jti = crypto.randomUUID(),
      extra: Record<string, unknown> = {},
      key = pair.privateKey,
    ) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: id,
        sub: id,
        aud: as.origin,
        iat: now,
        exp: now + 60,
        jti,
        ...extra,
      })
        .setProtectedHeader({ alg: "ES256", kid: "one" })
        .sign(key);
    };
    const verified = async (id = clientId, jti = crypto.randomUUID()) =>
      authenticator.authenticate(id, await sign(id, jti));
    const tokenForm = (
      assertion: string,
      scope = "agent.self.read catalog.read",
      id = clientId,
      target = resource,
    ) =>
      new URLSearchParams({
        grant_type: "client_credentials",
        client_id: id,
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
        resource: target,
        scope,
      }).toString();
    const tokenRequest = async (
      assertion: string,
      scope?: string,
      id?: string,
      target?: string,
    ) =>
      f.http(
        as.origin + "/oauth/token",
        tokenForm(assertion, scope, id, target),
        { "content-type": "application/x-www-form-urlencoded" },
      );
    let token = "";
    await t.test(
      "unknown client first visit uses standard form, stable machine subject and digest-only token",
      async () => {
        const r = await tokenRequest(await sign());
        assert.equal(r.status, 200);
        const b = JSON.parse(r.body);
        token = b.access_token;
        assert.equal(b.token_type, "Bearer");
        assert.equal(b.scope, "agent.self.read catalog.read");
        assert.equal(b.refresh_token, undefined);
        const rows = await pool.query("SELECT * FROM access_tokens");
        assert.equal(rows.rowCount, 1);
        assert.equal(JSON.stringify(rows.rows).includes(token), false);
        const i = await store.introspect(rsId, secret, token);
        assert.equal(i.active, true);
        assert.equal(i.client_id, clientId);
        assert.equal(i.subject_type, "client");
        assert.equal(
          (await f.http(as.origin + "/.well-known/oauth-authorization-server"))
            .status,
          200,
        );
        assert.equal(
          (
            await f.http(
              mcp.origin + "/.well-known/oauth-protected-resource/mcp",
            )
          ).status,
          200,
        );
      },
    );
    await t.test(
      "unmodified upstream dynamic/static JWT providers expose frozen-profile interoperability limits",
      async () => {
        const observed: {
          path: string;
          keys: string[];
          kid: boolean;
          audienceExact: boolean;
          lifetime: number;
        }[] = [];
        const sdkFetch: typeof fetch = async (input, init) => {
          const url =
            input instanceof URL
              ? input.href
              : typeof input === "string"
                ? input
                : input.url;
          const body =
            init?.body instanceof URLSearchParams
              ? init.body.toString()
              : typeof init?.body === "string"
                ? init.body
                : undefined;
          if (new URL(url).pathname === "/oauth/token" && body) {
            const values = new URLSearchParams(body);
            const jwt = values.get("client_assertion");
            assert.ok(jwt);
            const parts = jwt.split(".");
            const header = JSON.parse(
              Buffer.from(parts[0]!, "base64url").toString(),
            );
            const claims = JSON.parse(
              Buffer.from(parts[1]!, "base64url").toString(),
            );
            observed.push({
              path: new URL(url).pathname,
              keys: [...values.keys()].sort(),
              kid: typeof header.kid === "string",
              audienceExact: claims.aud === as.origin,
              lifetime: claims.exp - claims.iat,
            });
          }
          const response = await f.http(
            url,
            body,
            Object.fromEntries(new Headers(init?.headers).entries()),
            init?.method,
          );
          return new Response(response.body || null, {
            status: response.status,
            headers: Object.fromEntries(
              Object.entries(response.headers).filter(
                ([, v]) => typeof v === "string",
              ),
            ) as Record<string, string>,
          });
        };
        const dynamicId = identityOrigin + "/upstream-dynamic";
        const dynamic = new PrivateKeyJwtProvider({
          clientId: dynamicId,
          privateKey: await exportJWK(pair.privateKey),
          algorithm: "ES256",
          jwtLifetimeSeconds: 60,
          scope: "agent.self.read catalog.read",
        });
        const metadataFailure = (error: unknown) =>
          error instanceof Error &&
          "issues" in error &&
          Array.isArray(error.issues) &&
          ["authorization_endpoint", "response_types_supported"].every(
            (field) =>
              (error.issues as unknown[]).some(
                (issue: unknown) =>
                  typeof issue === "object" &&
                  issue !== null &&
                  "path" in issue &&
                  JSON.stringify(issue.path) === JSON.stringify([field]),
              ),
          );
        await assert.rejects(
          auth(dynamic, {
            serverUrl: new URL(resource),
            scope: "agent.self.read catalog.read",
            fetchFn: sdkFetch,
          }),
          metadataFailure,
        );
        assert.equal(observed.length, 0);
        // Diagnostic only: inspect the genuine token request generated below the upstream metadata schema.
        // No synthetic authorization endpoint, form field, assertion or successful token is supplied.
        const liveMetadata = await (
          await sdkFetch(as.origin + "/.well-known/oauth-authorization-server")
        ).json();
        await assert.rejects(
          fetchToken(dynamic, new URL(as.origin), {
            metadata: liveMetadata,
            resource: new URL(resource),
            fetchFn: sdkFetch,
          }),
          (error) =>
            error instanceof Error &&
            error.constructor.name === "InvalidClientError",
        );
        assert.equal(dynamic.tokens(), undefined);
        assert.ok(observed.length >= 1);
        assert.ok(
          observed.every(
            (x) =>
              !x.keys.includes("client_id") &&
              !x.kid &&
              x.audienceExact &&
              x.lifetime === 60,
          ),
        );
        const staticId = identityOrigin + "/upstream-static";
        const now = Math.floor(Date.now() / 1000);
        const standardAssertion = await new SignJWT({
          iss: staticId,
          sub: staticId,
          aud: as.origin,
          iat: now,
          exp: now + 60,
          jti: crypto.randomUUID(),
        })
          .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "one" })
          .sign(pair.privateKey);
        observed.length = 0;
        const staticProvider = new StaticPrivateKeyJwtProvider({
          clientId: staticId,
          jwtBearerAssertion: standardAssertion,
          scope: "agent.self.read catalog.read",
        });
        await assert.rejects(
          auth(staticProvider, {
            serverUrl: new URL(resource),
            scope: "agent.self.read catalog.read",
            fetchFn: sdkFetch,
          }),
          metadataFailure,
        );
        assert.equal(observed.length, 0);
        await assert.rejects(
          fetchToken(staticProvider, new URL(as.origin), {
            metadata: liveMetadata,
            resource: new URL(resource),
            fetchFn: sdkFetch,
          }),
          (error) =>
            error instanceof Error &&
            error.constructor.name === "InvalidClientError",
        );
        assert.equal(staticProvider.tokens(), undefined);
        assert.ok(observed.length >= 1);
        assert.ok(
          observed.every(
            (x) =>
              !x.keys.includes("client_id") &&
              x.kid &&
              x.audienceExact &&
              x.lifetime === 60,
          ),
        );
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM clients WHERE client_id=ANY($1::text[])",
              [[dynamicId, staticId]],
            )
          ).rows[0].n,
          0,
        );
      },
    );
    await t.test(
      "maximum bounded identifier combinations do not overflow a PostgreSQL grant index",
      async () => {
        const { randomBytes } = await import("node:crypto");
        const id = identityOrigin + "/" + randomBytes(940).toString("hex");
        const longResource =
          "https://resource.test/" + randomBytes(940).toString("hex");
        const scope = randomBytes(250).toString("hex");
        await store.configurePolicy({
          ...policy,
          resource: longResource,
          scopes: [scope],
        });
        const issued = await store.issue(await verified(id), longResource, [
          scope,
          scope,
        ]);
        assert.equal(issued.scope, scope);
        await replica.issue(await verified(id), longResource, [scope]);
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM machine_grants WHERE client_id=$1",
              [id],
            )
          ).rows[0].n,
          1,
        );
      },
    );
    await t.test(
      "another HTTPS identity provider uses the same automatic admission policy",
      async () => {
        const id = otherOrigin + "/client";
        const response = await tokenRequest(
          await sign(id, crypto.randomUUID(), {}, otherPair.privateKey),
          "catalog.read",
          id,
        );
        assert.equal(response.status, 200);
        const issued = JSON.parse(response.body);
        assert.equal(
          (await store.introspect(rsId, secret, issued.access_token)).client_id,
          id,
        );
      },
    );
    await t.test(
      "JWKS rotation changes proof key while retaining the same stable machine subject",
      async () => {
        const id = identityOrigin + "/rotation";
        const initial = await store.issue(await verified(id), resource, [
          "catalog.read",
        ]);
        const before = await store.introspect(
          rsId,
          secret,
          initial.access_token,
        );
        const oldPub = pub;
        try {
          const rotated = await generateKeyPair("ES256");
          pub = {
            ...(await exportJWK(rotated.publicKey)),
            kid: "two",
            alg: "ES256",
            use: "sig",
          };
          const now = Math.floor(Date.now() / 1000);
          const assertion = await new SignJWT({
            iss: id,
            sub: id,
            aud: as.origin,
            iat: now,
            exp: now + 60,
            jti: crypto.randomUUID(),
          })
            .setProtectedHeader({ alg: "ES256", kid: "two" })
            .sign(rotated.privateKey);
          const accepted = await authenticator.authenticate(id, assertion);
          const next = await store.issue(accepted, resource, ["catalog.read"]);
          assert.equal(
            (await replica.introspect(rsId, secret, next.access_token)).sub,
            before.sub,
          );
          assert.equal(
            (await replica.introspect(rsId, secret, initial.access_token))
              .active,
            true,
          );
        } finally {
          pub = oldPub;
        }
      },
    );
    await t.test(
      "two database clients serialize concurrent first admission and consume jti across resources",
      async () => {
        const id = identityOrigin + "/concurrent";
        const vals = [];
        for (let n = 0; n < 8; n++) vals.push(await verified(id));
        const out = await Promise.all(
          vals.map((v, n) =>
            (n % 2 ? replica : store).issue(v, resource, ["catalog.read"]),
          ),
        );
        assert.equal(out.length, 8);
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM clients WHERE client_id=$1",
              [id],
            )
          ).rows[0].n,
          1,
        );
        const v = await verified();
        const same = await Promise.allSettled([
          store.issue(v, resource, ["catalog.read"]),
          replica.issue(v, resource, ["catalog.read"]),
        ]);
        assert.equal(same.filter((x) => x.status === "fulfilled").length, 1);
        await assert.rejects(
          replica.issue(v, resource + "/other", ["catalog.read"]),
        );
      },
    );
    await t.test(
      "verified policy denial commits replay without creating a client/grant/token",
      async () => {
        const id = identityOrigin + "/denied";
        const v = await verified(id);
        await assert.rejects(
          store.issue(v, resource, ["account.profile.read"]),
          /invalid_scope/,
        );
        await assert.rejects(
          replica.issue(v, resource, ["catalog.read"]),
          /invalid_client/,
        );
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM clients WHERE client_id=$1",
              [id],
            )
          ).rows[0].n,
          0,
        );
      },
    );
    await t.test(
      "MCP initialize/tools/list/tools/call are real SDK wire and operation-scoped",
      async () => {
        const unauth = await f.http(
          resource,
          JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
          { "content-type": "application/json" },
        );
        assert.equal(unauth.status, 401);
        assert.match(unauth.headers["www-authenticate"]!, /resource_metadata=/);
        const jwt = await sign();
        const notAccess = await f.http(
          resource,
          JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
          {
            "content-type": "application/json",
            authorization: `Bearer ${jwt}`,
          },
        );
        assert.equal(notAccess.status, 401);
        const limited = await tokenRequest(await sign(), "catalog.read");
        const limitedToken = JSON.parse(limited.body).access_token;
        const sdkFetch: typeof fetch = async (input, init) => {
          const url =
            input instanceof URL
              ? input.href
              : typeof input === "string"
                ? input
                : input.url;
          const h = Object.fromEntries(new Headers(init?.headers).entries());
          const r = await f.http(
            url,
            typeof init?.body === "string" ? init.body : undefined,
            h,
            init?.method,
          );
          return new Response(r.body || null, {
            status: r.status,
            headers: Object.fromEntries(
              Object.entries(r.headers).filter(
                ([, v]) => typeof v === "string",
              ),
            ) as Record<string, string>,
          });
        };
        const client = new Client({
          name: "independent-standard-client",
          version: "1.0.0",
        });
        const transport = new StreamableHTTPClientTransport(new URL(resource), {
          fetch: sdkFetch,
          requestInit: { headers: { authorization: `Bearer ${limitedToken}` } },
        });
        try {
          await client.connect(transport);
          const tools = await client.listTools();
          assert.deepEqual(
            tools.tools.map((x) => x.name),
            ["catalog_list"],
          );
          const result = await client.callTool({
            name: "catalog_list",
            arguments: {},
          });
          assert.ok(JSON.stringify(result).includes("sample-notebook"));
          await assert.rejects(
            client.callTool({
              name: "identity_get",
              arguments: { owner: "forged" },
            }),
          );
        } finally {
          await client.close();
        }
        const full = new Client({
          name: "full-standard-client",
          version: "1.0.0",
        });
        const fullTransport = new StreamableHTTPClientTransport(
          new URL(resource),
          {
            fetch: sdkFetch,
            requestInit: { headers: { authorization: `Bearer ${token}` } },
          },
        );
        try {
          await full.connect(fullTransport);
          const result = await full.callTool({
            name: "identity_get",
            arguments: { owner: "forged" },
          });
          assert.ok(JSON.stringify(result).includes(clientId));
          assert.equal(JSON.stringify(result).includes("forged"), false);
        } finally {
          await full.close();
        }
      },
    );
    await t.test(
      "RS cannot introspect other resources and forged introspection source fails closed",
      async () => {
        await assert.rejects(
          store.introspect(rsId, "wrong", token),
          /invalid_client/,
        );
        await store.provisionResourceServer("other-rs", secret, [
          resource + "/other",
        ]);
        assert.deepEqual(await store.introspect("other-rs", secret, token), {
          active: false,
        });
        const wrong = new TokenVerifier(f.fetcher(), {
          ...verifier.config,
          resource: resource + "/other",
        });
        await assert.rejects(wrong.verify(`Bearer ${token}`), /invalid_token/);
        const badSource = new TokenVerifier(f.fetcher(), {
          ...verifier.config,
          introspectionEndpoint: as.origin + "/missing",
        });
        await assert.rejects(
          badSource.verify(`Bearer ${token}`),
          /temporarily_unavailable/,
        );
        const badIssuer = new TokenVerifier(f.fetcher(), {
          ...verifier.config,
          issuer: "https://evil.test",
        });
        await assert.rejects(
          badIssuer.verify(`Bearer ${token}`),
          /invalid_token/,
        );
      },
    );
    await t.test(
      "revocation checks owner, consumes new assertions and leaves other clients intact",
      async () => {
        const own = await verified(identityOrigin + "/other-owner");
        await store.revoke(own, token);
        assert.equal(
          (await store.introspect(rsId, secret, token)).active,
          true,
        );
        const v = await verified();
        await store.revoke(v, token);
        assert.deepEqual(await store.introspect(rsId, secret, token), {
          active: false,
        });
        await assert.rejects(store.revoke(v, token), /invalid_client/);
      },
    );
    await t.test(
      "client/grant disable and policy generation invalidate tokens across replicas and restart",
      async () => {
        const v = await verified();
        const issued = await store.issue(v, resource, ["catalog.read"]);
        await replica.blockClient(clientId, true);
        assert.deepEqual(
          await store.introspect(rsId, secret, issued.access_token),
          { active: false },
        );
        await assert.rejects(
          store.issue(await verified(), resource, ["catalog.read"]),
          /unauthorized_client/,
        );
        const pending = await verified(clientId);
        const race = await Promise.allSettled([
          store.issue(pending, resource, ["catalog.read"]),
          replica.blockClient(clientId, true),
        ]);
        for (const r of race)
          if (r.status === "fulfilled" && r.value && "access_token" in r.value)
            assert.deepEqual(
              await store.introspect(rsId, secret, r.value.access_token),
              { active: false },
            );
        await replica.blockClient(clientId, false);
        const newer = await store.issue(await verified(), resource, [
          "catalog.read",
        ]);
        await replica.configurePolicy(policy);
        assert.deepEqual(
          await store.introspect(rsId, secret, newer.access_token),
          { active: false },
        );
        const last = await store.issue(await verified(), resource, [
          "catalog.read",
        ]);
        const grant = (
          await pool.query(
            "SELECT grant_id FROM access_tokens WHERE digest=$1",
            [
              (await import("../packages/oauth-core/parse.js")).digest(
                last.access_token,
              ),
            ],
          )
        ).rows[0].grant_id;
        await replica.disableGrant(clientId, grant);
        assert.deepEqual(
          await store.introspect(rsId, secret, last.access_token),
          { active: false },
        );
        await assert.rejects(
          store.issue(await verified(), resource, ["catalog.read"]),
          /unauthorized_client/,
        );
        const restarted = new PostgresStore(pool2, as.origin);
        assert.deepEqual(
          await restarted.introspect(rsId, secret, newer.access_token),
          { active: false },
        );
      },
    );
    await t.test(
      "cross-replica prefetch budgets reject before metadata and cleanup keeps live windows/blocks",
      async () => {
        await store.configureRequestLimits({
          globalMinute: 2,
          originMinute: 2,
          clientMinute: 2,
          sourceMinute: 2,
        });
        await pool.query(
          "DELETE FROM rate_buckets WHERE bucket LIKE 'preflight:%'",
        );
        await Promise.all([
          store.preflight(identityOrigin + "/budget-a", "source"),
          replica.preflight(identityOrigin + "/budget-b", "source"),
        ]);
        const before = identityHits;
        const b = await tokenRequest(
          await sign(identityOrigin + "/budget-c"),
          "catalog.read",
          identityOrigin + "/budget-c",
        );
        assert.equal(b.status, 429);
        assert.equal(identityHits, before);
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM rate_buckets WHERE bucket LIKE 'preflight:client:%'",
            )
          ).rows[0].n,
          2,
        );
        await pool.query(
          "INSERT INTO rate_buckets(namespace,bucket,window_start,expires_at,count) VALUES($1,'old-minute',0,now()-interval '1 second',1),($1,'old-hour',0,now()-interval '1 second',1),($1,'live-hour',1,now()+interval '1 hour',1)",
          [store.namespace],
        );
        await replica.blockClient(identityOrigin + "/budget-blocked", true);
        await store.cleanup();
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM rate_buckets WHERE bucket IN ('old-minute','old-hour')",
            )
          ).rows[0].n,
          0,
        );
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM rate_buckets WHERE bucket='live-hour'",
            )
          ).rows[0].n,
          1,
        );
        assert.equal(
          await store.isBlocked(identityOrigin + "/budget-blocked"),
          true,
        );
        await assert.rejects(
          replica.preflight(identityOrigin + "/new-budget", "source"),
          /temporarily_unavailable/,
        );
      },
    );
    await t.test(
      "lost COMMIT receipt never retries and new assertion preserves the machine subject",
      async () => {
        const id = identityOrigin + "/lost-receipt";
        const v = await verified(id);
        const receiptPool = {
          connect: async () => {
            const c = await pool2.connect();
            const query = c.query.bind(c);
            return {
              query: async (text: string, values?: unknown[]) => {
                const result = await query(text, values);
                if (text === "COMMIT")
                  throw new Error("simulated_commit_receipt_loss");
                return result;
              },
              release: () => c.release(),
            };
          },
        } as unknown as Pool;
        const uncertain = new PostgresStore(receiptPool, as.origin);
        await assert.rejects(
          uncertain.issue(v, resource, ["catalog.read"]),
          /simulated_commit_receipt_loss/,
        );
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM access_tokens WHERE client_id=$1",
              [id],
            )
          ).rows[0].n,
          1,
        );
        await assert.rejects(
          store.issue(v, resource, ["catalog.read"]),
          /invalid_client/,
        );
        await replica.issue(await verified(id), resource, ["catalog.read"]);
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM clients WHERE client_id=$1",
              [id],
            )
          ).rows[0].n,
          1,
        );
      },
    );
    await t.test(
      "expired token, malformed scope replay and recovery generation remain closed",
      async () => {
        await store.configureRequestLimits({
          globalMinute: 1000,
          originMinute: 1000,
          clientMinute: 1000,
          sourceMinute: 1000,
        });
        const id = identityOrigin + "/recovery";
        const one = await store.issue(await verified(id), resource, [
          "catalog.read",
        ]);
        await pool.query(
          "UPDATE access_tokens SET expires_at=now()-interval '1 second' WHERE client_id=$1",
          [id],
        );
        assert.deepEqual(
          await replica.introspect(rsId, secret, one.access_token),
          { active: false },
        );
        const malformedId = identityOrigin + "/bad-scope";
        const assertion = await sign(malformedId);
        const denied = await tokenRequest(
          assertion,
          "catalog.read  agent.self.read",
          malformedId,
        );
        assert.equal(denied.status, 400);
        assert.equal(JSON.parse(denied.body).error, "invalid_scope");
        const replay = await tokenRequest(
          assertion,
          "catalog.read",
          malformedId,
        );
        assert.equal(replay.status, 401);
        const beforeRecovery = await store.issue(await verified(id), resource, [
          "catalog.read",
        ]);
        await replica.invalidateForRecovery();
        assert.deepEqual(
          await store.introspect(rsId, secret, beforeRecovery.access_token),
          { active: false },
        );
        await assert.rejects(
          store.issue(await verified(id), resource, ["catalog.read"]),
          /invalid_target/,
        );
        await replica.configurePolicy(policy);
        assert.deepEqual(
          await store.introspect(rsId, secret, beforeRecovery.access_token),
          { active: false },
        );
      },
    );
    await t.test(
      "wrong signature never creates a machine identity",
      async () => {
        await store.configureRequestLimits({
          globalMinute: 1000,
          originMinute: 1000,
          clientMinute: 1000,
          sourceMinute: 1000,
        });
        const id = identityOrigin + "/bad-key";
        const r = await tokenRequest(
          await sign(id, crypto.randomUUID(), {}, otherPair.privateKey),
          "catalog.read",
          id,
        );
        assert.equal(r.status, 401);
        assert.equal(
          (
            await pool.query(
              "SELECT count(*)::integer AS n FROM clients WHERE client_id=$1",
              [id],
            )
          ).rows[0].n,
          0,
        );
      },
    );
  } finally {
    await f.close();
    await pool.end();
    await pool2.end();
  }
});
