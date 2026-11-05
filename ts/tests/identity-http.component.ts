/** E owning security evidence: direct Token/MCP HTTP, real TLS and isolated PostgreSQL. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
import { tlsFixture } from "./helpers.js";

process.env.NODE_ENV = "test";

test(
  "identity HTTP rejects validly signed identity/algorithm mismatches without admission and authorizes the actual MCP body",
  { timeout: 30000 },
  async (t) => {
    let database: URL;
    try {
      database = new URL(process.env.DATABASE_URL ?? "postgresql:///missing");
    } catch {
      throw new Error("Use the owning private PostgreSQL runner");
    }
    assert.equal(database.protocol, "postgresql:");
    assert.equal(database.pathname, "/cimd_component");
    assert.equal(
      database.hostname === "" &&
        database.username === "" &&
        database.password === "",
      true,
      "Use a credential-free private Unix socket database URL",
    );
    assert.match(
      database.searchParams.get("host") ?? "",
      /^\/tmp\/cimd-pg\.[A-Za-z0-9]+\/socket$/u,
      "Use the owning private PostgreSQL runner",
    );

    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 8,
    });
    const tls = await tlsFixture();
    const p256 = await generateKeyPair("ES256", { extractable: true });
    const p384 = await generateKeyPair("ES384", { extractable: true });
    const public256 = {
      ...(await exportJWK(p256.publicKey)),
      kid: "identity-http-es256",
      alg: "ES256",
      use: "sig",
    };
    const public384 = {
      ...(await exportJWK(p384.publicKey)),
      kid: "identity-http-es384",
      alg: "ES384",
      use: "sig",
    };
    const prefix = "/identity-http-" + randomUUID();
    let namespace: string | undefined;
    let publisherOrigin = "";
    let completed = 0;
    const jsonObject = (body: string): Record<string, unknown> => {
      let value: unknown;
      try {
        value = JSON.parse(body);
      } catch {
        throw new Error("Expected a JSON HTTP response");
      }
      assert.equal(
        !!value && typeof value === "object" && !Array.isArray(value),
        true,
        "Expected a JSON object",
      );
      return value as Record<string, unknown>;
    };
    try {
      const publisher = await tls.start((request, response) => {
        response.setHeader("content-type", "application/json");
        if (request.method !== "GET") {
          response.writeHead(405);
          response.end();
          return;
        }
        if (request.url === prefix + "/jwks-es256.json") {
          response.end(JSON.stringify({ keys: [public256] }));
          return;
        }
        if (request.url === prefix + "/jwks-es384.json") {
          response.end(JSON.stringify({ keys: [public384] }));
          return;
        }
        if (!request.url?.startsWith(prefix + "/clients/")) {
          response.writeHead(404);
          response.end();
          return;
        }
        response.end(
          JSON.stringify({
            client_id: publisherOrigin + request.url,
            client_name: "Identity HTTP security fixture",
            jwks_uri:
              publisherOrigin +
              prefix +
              (request.url.endsWith("/wrong-alg.json")
                ? "/jwks-es384.json"
                : "/jwks-es256.json"),
            grant_types: ["client_credentials"],
            response_types: [],
            redirect_uris: [],
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "ES256",
          }),
        );
      });
      publisherOrigin = publisher.origin;
      let asHandler!: ReturnType<typeof createAuthorizationServer>;
      const as = await tls.start(
        (request, response) => asHandler(request, response),
        "auth.test",
      );
      let rsHandler!: ReturnType<typeof createMcpApp>;
      const rs = await tls.start(
        (request, response) => rsHandler(request, response),
        "mcp.test",
      );
      const resource = rs.origin + "/mcp";
      const store = new PostgresStore(pool, as.origin);
      namespace = store.namespace;
      const allowedScopes = ["agent.self.read", "catalog.read"];
      await store.configureRequestLimits({
        globalMinute: 1000,
        originMinute: 1000,
        clientMinute: 1000,
        sourceMinute: 1000,
      });
      await store.configurePolicy({
        resource,
        scopes: allowedScopes,
        ttl: 60,
        maxNewClientsHour: 100,
        maxRequestsClientMinute: 100,
        maxRequestsMinute: 500,
        custodyCondition: "Isolated local-key owning security component only",
        enabled: true,
      });
      const rsId = "identity-http-rs";
      const rsSecret = randomBytes(32).toString("base64url");
      await store.provisionResourceServer(rsId, rsSecret, [resource]);
      await store.ready();
      asHandler = createAuthorizationServer(
        store,
        new ClientAuthenticator(tls.fetcher(), as.origin),
        allowedScopes,
      );
      rsHandler = createMcpApp(
        new TokenVerifier(tls.fetcher(), {
          issuer: as.origin,
          introspectionEndpoint: as.origin + "/oauth/introspect",
          resource,
          rsId,
          rsSecret,
          allowedScopes,
        }),
      );

      const client = (name: string) =>
        publisherOrigin + prefix + "/clients/" + name + ".json";
      const assertion = async (
        id: string,
        altered: { iss?: string; sub?: string } = {},
        algorithm: "ES256" | "ES384" = "ES256",
      ) => {
        const pair = algorithm === "ES256" ? p256 : p384;
        const now = Math.floor(Date.now() / 1000);
        const claims = {
          iss: altered.iss ?? id,
          sub: altered.sub ?? id,
          aud: as.origin,
          iat: now,
          exp: now + 60,
          jti: randomUUID(),
        };
        const compact = await new SignJWT(claims)
          .setProtectedHeader({
            alg: algorithm,
            kid: algorithm === "ES256" ? public256.kid : public384.kid,
          })
          .sign(pair.privateKey);
        // This independent verification proves the negative is not merely a corrupt signature.
        try {
          const checked = await jwtVerify(compact, pair.publicKey, {
            algorithms: [algorithm],
            issuer: claims.iss,
            subject: claims.sub,
            audience: as.origin,
            requiredClaims: ["iat", "exp", "jti"],
          });
          assert.equal(checked.protectedHeader.alg === algorithm, true);
        } catch {
          throw new Error(
            "The negative assertion must have an independently valid signature",
          );
        }
        return compact;
      };
      const directTokenPost = (
        id: string,
        compact: string,
        scope = "catalog.read",
      ) =>
        tls.http(
          as.origin + "/oauth/token",
          new URLSearchParams({
            grant_type: "client_credentials",
            client_id: id,
            client_assertion_type:
              "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: compact,
            resource,
            scope,
          }).toString(),
          { "content-type": "application/x-www-form-urlencoded" },
        );
      const assertNoAdmission = async (formId: string) => {
        for (const table of [
          "clients",
          "machine_grants",
          "access_tokens",
          "metadata_snapshots",
          "assertion_replays",
        ] as const) {
          const result = await pool.query<{ count: number }>(
            `SELECT count(*)::integer AS count FROM ${table} WHERE namespace=$1`,
            [namespace],
          );
          assert.equal(
            result.rows[0]?.count,
            0,
            "Rejected authentication must create no " +
              table +
              " rows in its namespace",
          );
        }
        const bucket =
          "preflight:client:" +
          createHash("sha256").update(formId).digest("hex");
        const preflight = await pool.query<{ count: number }>(
          "SELECT count(*)::integer AS count FROM rate_buckets WHERE namespace=$1 AND bucket=$2 AND count>0",
          [namespace, bucket],
        );
        assert.equal(
          preflight.rows[0]?.count,
          1,
          "Real HTTP authentication must retain its bounded prefetch rate state",
        );
      };
      const rejectedHttp = async (formId: string, compact: string) => {
        const response = await directTokenPost(formId, compact);
        assert.equal(
          response.status,
          401,
          "A validly signed but invalid identity or algorithm must be rejected over Token HTTP",
        );
        assert.equal(
          jsonObject(response.body).error === "invalid_client",
          true,
          "Expected the standard authentication error",
        );
        await assertNoAdmission(formId);
      };
      const scenario = (name: string, run: () => Promise<void>) =>
        t.test(name, async () => {
          await run();
          completed++;
        });

      await scenario(
        "valid ES256 signature with wrong iss is rejected by Token HTTP without client/grant/token/snapshot state",
        async () => {
          const id = client("wrong-iss");
          await rejectedHttp(
            id,
            await assertion(id, { iss: client("different-issuer") }),
          );
        },
      );
      await scenario(
        "valid ES256 signature with wrong sub is rejected by Token HTTP without client/grant/token/snapshot state",
        async () => {
          const id = client("wrong-sub");
          await rejectedHttp(
            id,
            await assertion(id, { sub: client("different-subject") }),
          );
        },
      );
      await scenario(
        "valid ES256 assertion for another form client_id is rejected without admitting either identity",
        async () => {
          const signedId = client("form-signed");
          const formId = client("form-other");
          await rejectedHttp(formId, await assertion(signedId));
        },
      );
      await scenario(
        "independently valid ES384 P384 assertion is rejected by the unchanged ES256 Token profile without admission",
        async () => {
          const id = client("wrong-alg");
          await rejectedHttp(id, await assertion(id, {}, "ES384"));
        },
      );
      await scenario(
        "catalog-only Access Token cannot call identity_get by advertising tools/list in MCP routing headers",
        async () => {
          const id = client("catalog-only");
          const tokenResponse = await directTokenPost(id, await assertion(id));
          assert.equal(
            tokenResponse.status,
            200,
            "The unchanged production profile must admit its valid ES256 control",
          );
          const token = jsonObject(tokenResponse.body);
          assert.equal(
            typeof token.access_token === "string",
            true,
            "Expected a real issued Access Token",
          );
          assert.equal(
            token.scope === "catalog.read",
            true,
            "The Token must remain catalog-only",
          );
          const headers = {
            authorization: "Bearer " + (token.access_token as string),
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            "mcp-protocol-version": "2025-11-25",
          };
          const initialize = await tls.http(
            resource,
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: "initialize",
              params: {
                protocolVersion: "2025-11-25",
                capabilities: {},
                clientInfo: {
                  name: "identity-http-owning-security",
                  version: "1",
                },
              },
            }),
            headers,
          );
          assert.equal(
            initialize.status,
            200,
            "Real MCP initialize must succeed for the catalog-only control",
          );
          const listed = await tls.http(
            resource,
            JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
            headers,
          );
          assert.equal(
            listed.status,
            200,
            "Real tools/list must succeed for the control",
          );
          const listResult = jsonObject(listed.body).result as
            | { tools?: Array<{ name: string }> }
            | undefined;
          assert.equal(
            listResult?.tools?.length,
            1,
            "Only the authorized catalog tool may be listed",
          );
          assert.equal(
            listResult?.tools?.[0]?.name === "catalog_list",
            true,
            "The identity tool must not be listed",
          );
          const catalog = await tls.http(
            resource,
            JSON.stringify({
              jsonrpc: "2.0",
              id: 3,
              method: "tools/call",
              params: { name: "catalog_list", arguments: {} },
            }),
            headers,
          );
          assert.equal(
            catalog.status,
            200,
            "The actual authorized catalog call must succeed",
          );
          const denied = await tls.http(
            resource,
            JSON.stringify({
              jsonrpc: "2.0",
              id: 4,
              method: "tools/call",
              params: { name: "identity_get", arguments: {} },
            }),
            {
              ...headers,
              "mcp-method": "tools/list",
              "mcp-name": "catalog_list",
            },
          );
          assert.equal(
            denied.status,
            403,
            "The actual body method/tool must control authorization despite contradictory routing headers",
          );
          assert.equal(
            jsonObject(denied.body).error === "insufficient_scope",
            true,
            "Expected operation-scope refusal",
          );
          const stillActive = await store.introspect(
            rsId,
            rsSecret,
            token.access_token as string,
          );
          assert.equal(
            stillActive.active,
            true,
            "The refusal is actual tool authorization, not an invalid or expired Token",
          );
          assert.equal(stillActive.scope === "catalog.read", true);
        },
      );
      assert.equal(completed, 5);
      process.stdout.write(
        JSON.stringify({
          passed: true,
          lane: "E-owning-direct-identity-HTTP-TLS-Postgres-and-MCP-body-authorization",
          validSignatureIdentityNegatives: ["iss", "sub", "form_client_id"],
          validUnsupportedAlgorithm: "ES384",
          admissionRowsCreatedByInvalidAssertions: 0,
          boundedPrefetchRateStateRetained: true,
          actualBodyAuthorization:
            "catalog-only identity_get denied403 despite tools/list routing header",
          systemProductE2E: "not-run",
          independentClientEvidence: false,
        }) + "\n",
      );
    } finally {
      try {
        await tls.close();
      } finally {
        try {
          if (namespace) {
            const connection = await pool.connect();
            try {
              await connection.query("BEGIN");
              for (const table of [
                "access_tokens",
                "machine_grants",
                "metadata_snapshots",
                "assertion_replays",
                "audit_events",
                "rate_buckets",
                "client_blocks",
                "clients",
                "resource_servers",
                "admission_policies",
                "request_limits",
              ] as const)
                await connection.query(
                  `DELETE FROM ${table} WHERE namespace=$1`,
                  [namespace],
                );
              await connection.query("COMMIT");
            } catch (error) {
              await connection.query("ROLLBACK");
              throw error;
            } finally {
              connection.release();
            }
          }
        } finally {
          await pool.end();
        }
      }
    }
  },
);
