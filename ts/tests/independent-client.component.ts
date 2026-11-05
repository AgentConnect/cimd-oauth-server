/** Unmodified oauth4webapi handles discovery/authentication/CC/token/revocation over real isolated TLS. */
import { test } from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import * as oauth from "oauth4webapi";
import { Client as McpClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
import { tlsFixture } from "./helpers.js";
process.env.NODE_ENV = "test";
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
test("independent oauth4webapi discovery/private_key_jwt/client_credentials interoperates with real TLS AS/RS/PG and MCP", async (t) => {
  assert.ok(process.env.DATABASE_URL, "Use test:independent-client");
  const tls = await tlsFixture();
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 8 });
  const key = await oauth.generateKeyPair("ES256");
  const otherKey = await oauth.generateKeyPair("ES256");
  const publicJwk = await crypto.subtle.exportKey("jwk", key.publicKey);
  const otherPublicJwk = await crypto.subtle.exportKey(
    "jwk",
    otherKey.publicKey,
  );
  let identityOrigin = "";
  let metadataReads = 0;
  const wire: Array<{
    path: string;
    clientId: string;
    keys: string[];
    kid: unknown;
    alg: unknown;
    aud: unknown;
    iat: number;
    exp: number;
    jtiDigest: string;
    status?: number;
  }> = [];
  try {
    const identity = await tls.start((req, res) => {
      res.setHeader("content-type", "application/json");
      metadataReads++;
      const owner = req.url?.startsWith("/other/") ? "other" : "client";
      if (req.url === `/${owner}/jwks.json`)
        res.end(
          JSON.stringify({
            keys: [
              {
                ...(owner === "other" ? otherPublicJwk : publicJwk),
                kid: "independent-es256",
                alg: "ES256",
                use: "sig",
              },
            ],
          }),
        );
      else if (req.url === `/${owner}/client.json`)
        res.end(
          JSON.stringify({
            client_id: identityOrigin + req.url,
            jwks_uri: identityOrigin + `/${owner}/jwks.json`,
            grant_types: ["client_credentials"],
            response_types: [],
            redirect_uris: [],
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "ES256",
          }),
        );
      else {
        res.statusCode = 404;
        res.end("{}");
      }
    });
    identityOrigin = identity.origin;
    let asHandler: ReturnType<typeof createAuthorizationServer>;
    const as = await tls.start((req, res) => asHandler(req, res), "auth.test");
    let rsHandler: ReturnType<typeof createMcpApp>;
    const rs = await tls.start((req, res) => rsHandler(req, res), "mcp.test");
    const resource = rs.origin + "/mcp",
      scope = "agent.self.read catalog.read",
      scopes = scope.split(" ");
    const store = new PostgresStore(pool, as.origin);
    const rsSecret = randomBytes(32).toString("base64url");
    await store.configureRequestLimits({
      globalMinute: 120,
      originMinute: 40,
      clientMinute: 20,
      sourceMinute: 60,
    });
    await store.configurePolicy({
      resource,
      scopes,
      ttl: 3,
      maxNewClientsHour: 10,
      maxRequestsClientMinute: 20,
      maxRequestsMinute: 60,
      custodyCondition:
        "Independent non-DSH local test process / ephemeral ES256 key",
      enabled: true,
    });
    await store.provisionResourceServer("independent-rs", rsSecret, [resource]);
    asHandler = createAuthorizationServer(
      store,
      new ClientAuthenticator(tls.fetcher(), as.origin),
      scopes,
    );
    rsHandler = createMcpApp(
      new TokenVerifier(tls.fetcher(), {
        issuer: as.origin,
        introspectionEndpoint: as.origin + "/oauth/introspect",
        resource,
        rsId: "independent-rs",
        rsSecret,
        allowedScopes: scopes,
      }),
    );
    const allowedOrigins = new Set([as.origin, rs.origin]);
    // This adapter only transports upstream bytes through a CA-validated, pinned test TLS socket.
    // It never sets OAuth form fields, signs assertions, alters metadata or fabricates a response.
    const customFetch = async (
      url: string,
      options: {
        method: string;
        headers: Record<string, string>;
        body?: URLSearchParams | string;
        redirect: "manual";
        signal?: AbortSignal;
      },
    ): Promise<Response> => {
      const target = new URL(url);
      assert.ok(
        allowedOrigins.has(target.origin),
        "Exact test origin required",
      );
      assert.equal(target.protocol, "https:");
      assert.equal(options.redirect, "manual");
      const body = options.body?.toString();
      assert.ok(body === undefined || Buffer.byteLength(body) <= 24576);
      let trace: (typeof wire)[number] | undefined;
      if (
        target.pathname === "/oauth/token" ||
        target.pathname === "/oauth/revoke"
      ) {
        const params = new URLSearchParams(body);
        const assertion = params.get("client_assertion");
        assert.ok(assertion, "Upstream supplied assertion");
        const [encodedHeader, encodedClaims] = assertion.split(".");
        const header = JSON.parse(
          Buffer.from(encodedHeader!, "base64url").toString(),
        );
        const claims = JSON.parse(
          Buffer.from(encodedClaims!, "base64url").toString(),
        );
        assert.equal(params.get("client_id"), claims.iss);
        assert.equal(claims.sub, claims.iss);
        trace = {
          path: target.pathname,
          clientId: params.get("client_id")!,
          keys: [...params.keys()].sort(),
          kid: header.kid,
          alg: header.alg,
          aud: claims.aud,
          iat: claims.iat,
          exp: claims.exp,
          jtiDigest: sha(claims.jti),
        };
        wire.push(trace);
      }
      const response = await new Promise<Response>((resolve, reject) => {
        const request = https.request(
          target,
          {
            method: options.method,
            headers: options.headers,
            ca: tls.cert,
            rejectUnauthorized: true,
            agent: false,
            maxHeaderSize: 16384,
            signal: AbortSignal.any([
              AbortSignal.timeout(5000),
              ...(options.signal ? [options.signal] : []),
            ]),
            lookup: ((
              _host: string,
              lookupOptions: { all?: boolean },
              callback: Function,
            ) =>
              lookupOptions.all
                ? callback(null, [{ address: "127.0.0.1", family: 4 }])
                : callback(null, "127.0.0.1", 4)) as never,
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            let bytes = 0;
            incoming.on("data", (chunk: Buffer) => {
              bytes += chunk.length;
              if (bytes > 65536)
                incoming.destroy(new Error("test_response_too_large"));
              else chunks.push(chunk);
            });
            incoming.on("error", reject);
            incoming.on("end", () => {
              const headers = new Headers();
              for (const [name, value] of Object.entries(incoming.headers)) {
                if (Array.isArray(value))
                  value.forEach((item) => headers.append(name, item));
                else if (value !== undefined) headers.set(name, value);
              }
              const status = incoming.statusCode!;
              if (trace) trace.status = status;
              resolve(
                new Response(
                  [204, 205, 304].includes(status)
                    ? null
                    : Buffer.concat(chunks),
                  { status, headers },
                ),
              );
            });
          },
        );
        request.on("error", reject);
        if (body !== undefined) request.write(body);
        request.end();
      });
      assert.equal(
        options.body?.toString(),
        body,
        "Transport must not mutate upstream form",
      );
      return response;
    };
    const options = { [oauth.customFetch]: customFetch };
    const issuer = new URL(as.origin);
    const metadata = await oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, { algorithm: "oauth2", ...options }),
    );
    assert.equal(metadata.issuer, as.origin);
    assert.equal(metadata.authorization_endpoint, undefined);
    assert.equal(metadata.token_endpoint, as.origin + "/oauth/token");
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.deepEqual(metadata.grant_types_supported, ["client_credentials"]);
    const client: oauth.Client = {
      client_id: identityOrigin + "/client/client.json",
      token_endpoint_auth_signing_alg: "ES256",
    };
    const authentication = oauth.PrivateKeyJwt({
      key: key.privateKey,
      kid: "independent-es256",
    });
    const requestToken = async (
      parameters: Record<string, string> = { resource, scope },
      auth: oauth.ClientAuth = authentication,
      selected: oauth.Client = client,
    ) =>
      oauth.processClientCredentialsResponse(
        metadata,
        selected,
        await oauth.clientCredentialsGrantRequest(
          metadata,
          selected,
          auth,
          parameters,
          options,
        ),
      );
    const expectedError = (code: string) => (error: unknown) =>
      error instanceof oauth.ResponseBodyError && error.error === code;
    assert.equal(
      (await pool.query("SELECT count(*)::integer AS n FROM clients")).rows[0]
        .n,
      0,
    );
    let first!: oauth.TokenEndpointResponse;
    let renewed!: oauth.TokenEndpointResponse;
    const sdkFetch: typeof fetch = (input, init = {}) => {
      const url = input instanceof Request ? input.url : String(input);
      assert.ok(init.body === undefined || typeof init.body === "string");
      return customFetch(url, {
        method: init.method ?? "GET",
        headers: Object.fromEntries(new Headers(init.headers).entries()),
        body: init.body as string | undefined,
        redirect: "manual",
        signal: init.signal ?? undefined,
      });
    };
    const openMcp = async (token: string) => {
      const mcp = new McpClient({
        name: "oauth4webapi-independent-client",
        version: "3.8.8",
      });
      try {
        await mcp.connect(
          new StreamableHTTPClientTransport(new URL(resource), {
            fetch: sdkFetch,
            requestInit: { headers: { authorization: `Bearer ${token}` } },
          }),
        );
        return mcp;
      } catch (error) {
        await mcp.close();
        throw error;
      }
    };
    let completedScenarios = 0;
    const scenario = async (name: string, run: () => Promise<void>) => {
      await t.test(name, async () => {
        await run();
        completedScenarios++;
      });
    };
    await scenario(
      "unknown HTTPS CIMD is admitted by a pure upstream CC request and both MCP tools work",
      async () => {
        first = await requestToken();
        assert.equal(first.token_type, "bearer");
        assert.equal(first.expires_in, 3);
        assert.equal(first.scope, scope);
        assert.equal(first.refresh_token, undefined);
        assert.ok(metadataReads >= 2);
        const trace = wire.at(-1)!;
        assert.equal(trace.kid, "independent-es256");
        assert.equal(trace.alg, "ES256");
        assert.equal(trace.aud, as.origin);
        assert.equal(trace.exp - trace.iat, 60);
        assert.deepEqual(trace.keys, [
          "client_assertion",
          "client_assertion_type",
          "client_id",
          "grant_type",
          "resource",
          "scope",
        ]);
        const principal = await store.introspect(
          "independent-rs",
          rsSecret,
          first.access_token,
        );
        assert.equal(principal.active, true);
        const mcp = await openMcp(first.access_token);
        try {
          assert.deepEqual(
            (await mcp.listTools()).tools.map((tool) => tool.name).sort(),
            ["catalog_list", "identity_get"],
          );
          const identity = await mcp.callTool({
            name: "identity_get",
            arguments: {},
          });
          assert.ok(JSON.stringify(identity).includes(client.client_id));
          assert.ok(JSON.stringify(identity).includes(String(principal.sub)));
          const catalog = await mcp.callTool({
            name: "catalog_list",
            arguments: {},
          });
          assert.ok(JSON.stringify(catalog).includes("sample-notebook"));
        } finally {
          await mcp.close();
        }
        assert.equal(
          (await pool.query("SELECT count(*)::integer AS n FROM clients"))
            .rows[0].n,
          1,
        );
      },
    );
    await scenario(
      "real token expiry requires a new upstream CC request with fresh iat/exp/jti and stable subject",
      async () => {
        const firstTrace = wire.at(-1)!;
        const subject = (
          await store.introspect("independent-rs", rsSecret, first.access_token)
        ).sub;
        await new Promise((resolve) =>
          setTimeout(resolve, Number(first.expires_in) * 1000 + 150),
        );
        assert.deepEqual(
          await store.introspect(
            "independent-rs",
            rsSecret,
            first.access_token,
          ),
          { active: false },
        );
        await assert.rejects(openMcp(first.access_token));
        renewed = await requestToken();
        const nextTrace = wire.at(-1)!;
        assert.ok(
          renewed.access_token !== first.access_token,
          "Renewal returns a fresh opaque token",
        );
        assert.ok(nextTrace.iat > firstTrace.iat);
        assert.ok(nextTrace.exp > firstTrace.exp);
        assert.ok(nextTrace.jtiDigest !== firstTrace.jtiDigest);
        assert.equal(
          (
            await store.introspect(
              "independent-rs",
              rsSecret,
              renewed.access_token,
            )
          ).sub,
          subject,
        );
        assert.equal(
          (await pool.query("SELECT count(*)::integer AS n FROM clients"))
            .rows[0].n,
          1,
        );
      },
    );
    await scenario(
      "upstream resource/scope and official-hook JWT negative vectors fail closed",
      async () => {
        await assert.rejects(
          requestToken({ resource: resource + "/other", scope }),
          expectedError("invalid_target"),
        );
        await assert.rejects(
          requestToken({ resource, scope: "account.profile.read" }),
          expectedError("invalid_scope"),
        );
        const fixed = randomUUID();
        const repeated = oauth.PrivateKeyJwt(
          { key: key.privateKey, kid: "independent-es256" },
          {
            [oauth.modifyAssertion]: (_header, payload) => {
              payload.jti = fixed;
            },
          },
        );
        await requestToken({ resource, scope }, repeated);
        await assert.rejects(
          requestToken({ resource, scope }, repeated),
          expectedError("invalid_client"),
        );
        const expired = oauth.PrivateKeyJwt(
          { key: key.privateKey, kid: "independent-es256" },
          {
            [oauth.modifyAssertion]: (_header, payload) => {
              const now = Math.floor(Date.now() / 1000);
              payload.iat = now - 30;
              payload.nbf = now - 30;
              payload.exp = now - 6;
            },
          },
        );
        await assert.rejects(
          requestToken({ resource, scope }, expired),
          expectedError("invalid_client"),
        );
        const wrongAudience = oauth.PrivateKeyJwt(
          { key: key.privateKey, kid: "independent-es256" },
          {
            [oauth.modifyAssertion]: (_header, payload) => {
              payload.aud = as.origin + "/other";
            },
          },
        );
        await assert.rejects(
          requestToken({ resource, scope }, wrongAudience),
          expectedError("invalid_client"),
        );
        const wrongResource = new TokenVerifier(tls.fetcher(), {
          issuer: as.origin,
          introspectionEndpoint: as.origin + "/oauth/introspect",
          resource: resource + "/other",
          rsId: "independent-rs",
          rsSecret,
          allowedScopes: scopes,
        });
        await assert.rejects(
          wrongResource.verify(`Bearer ${renewed.access_token}`),
          /invalid_token/,
        );
      },
    );
    await scenario(
      "upstream revocation preserves foreign ownership and invalidates the owner token without replay",
      async () => {
        const other: oauth.Client = {
          client_id: identityOrigin + "/other/client.json",
        };
        const otherAuth = oauth.PrivateKeyJwt({
          key: otherKey.privateKey,
          kid: "independent-es256",
        });
        await oauth.processRevocationResponse(
          await oauth.revocationRequest(
            metadata,
            other,
            otherAuth,
            renewed.access_token,
            {
              additionalParameters: { token_type_hint: "access_token" },
              ...options,
            },
          ),
        );
        assert.equal(
          (
            await store.introspect(
              "independent-rs",
              rsSecret,
              renewed.access_token,
            )
          ).active,
          true,
        );
        await oauth.processRevocationResponse(
          await oauth.revocationRequest(
            metadata,
            client,
            authentication,
            renewed.access_token,
            {
              additionalParameters: { token_type_hint: "access_token" },
              ...options,
            },
          ),
        );
        assert.deepEqual(
          await store.introspect(
            "independent-rs",
            rsSecret,
            renewed.access_token,
          ),
          { active: false },
        );
        await assert.rejects(openMcp(renewed.access_token));
        const successful = wire.filter(
          (trace) =>
            trace.status === 200 && trace.clientId === client.client_id,
        );
        assert.equal(
          new Set(successful.map((trace) => trace.jtiDigest)).size,
          successful.length,
        );
        assert.equal(
          (await pool.query("SELECT count(*)::integer AS n FROM clients"))
            .rows[0].n,
          1,
        );
      },
    );
    assert.equal(
      completedScenarios,
      4,
      "Every independent-client scenario must pass before the success record",
    );
    process.stdout.write(
      JSON.stringify({
        passed: true,
        lane: "independent-oauth4webapi-3.8.8-real-TLS-Postgres-MCP",
        libraryUnmodified: true,
        positiveModifyAssertionHook: false,
        asDiscovery: "upstream-oauth2",
        tokenForms: "upstream-only",
        unknownClientAdmitted: true,
        tools: ["identity_get", "catalog_list"],
        expiryRenewal: true,
        resourceScopeReplayTimeAudienceNegatives: true,
        foreignRevocationPreserved: true,
        ownerRevocationConfirmed: true,
        source: "primary-npm-fixed-version",
        dshUsed: false,
        systemProductE2E: "not-run",
      }) + "\n",
    );
  } finally {
    await tls.close();
    await pool.end();
  }
});
