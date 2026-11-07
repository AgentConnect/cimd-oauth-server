import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  calculateJwkThumbprint,
} from "jose";
import {
  createDidWbaDocument,
  DidProfile,
  generateHttpSignatureHeaders,
} from "@awiki/anp-typescript-sdk";
import { tlsFixture } from "./helpers.js";
import { createServiceAgent } from "../packages/service-agent/index.js";
import { createWebsiteServices } from "../packages/service-agent/website.js";
import { AnpVerifier, publicDidResolver } from "../packages/anp/index.js";
import { PapSessionVerifier } from "../packages/pap/session.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";

process.env.NODE_ENV = "test";
test("one HTTPS service serves ANP, PAP and CIMD OAuth MCP with persisted messages", async () => {
  assert.ok(process.env.DATABASE_URL, "Use test:website");
  const tls = await tlsFixture();
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const oauth = await generateKeyPair("ES256");
    const delegated = await generateKeyPair("ES256");
    const oauthJwk = {
      ...(await exportJWK(oauth.publicKey)),
      kid: "oauth",
      alg: "ES256",
      use: "sig",
    };
    let clientId = "";
    let did: ReturnType<typeof createDidWbaDocument>;
    const publisher = await tls.start((req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify(
          req.url === "/client.json"
            ? {
                client_id: clientId,
                jwks_uri: clientId.replace("client.json", "jwks.json"),
                grant_types: ["client_credentials"],
                response_types: [],
                redirect_uris: [],
                token_endpoint_auth_method: "private_key_jwt",
                token_endpoint_auth_signing_alg: "ES256",
              }
            : req.url === "/jwks.json"
              ? { keys: [oauthJwk] }
              : did.didDocument,
        ),
      );
    });
    clientId = publisher.origin + "/client.json";
    did = createDidWbaDocument("identity.test", {
      port: Number(new URL(publisher.origin).port),
      pathSegments: ["agent"],
      didProfile: DidProfile.E1,
    });
    let app: ReturnType<typeof createServiceAgent>;
    const server = await tls.start((req, res) => app(req, res), "other.test");
    const origin = server.origin;
    const store = new PostgresStore(pool, origin);
    const scopes = ["protocol.read", "message.write"];
    await store.configurePolicy({
      resource: origin + "/mcp",
      scopes,
      enabled: true,
      ttl: 60,
      maxNewClientsHour: 100,
      maxRequestsClientMinute: 100,
      maxRequestsMinute: 100,
      custodyCondition: "Isolated component identity",
    });
    await store.configureRequestLimits({
      globalMinute: 1000,
      originMinute: 1000,
      clientMinute: 1000,
      sourceMinute: 1000,
    });
    await store.provisionResourceServer("website", "s".repeat(48), [
      origin + "/mcp",
    ]);
    const catalog = [
      {
        version: "1.1",
        language: "en",
        document: "white-paper",
        content: "# ANP 1.1",
        sourceUrl: origin + "/specs/1.1/white-paper",
      },
    ];
    const services = await createWebsiteServices(catalog, pool);
    app = createServiceAgent({
      origin,
      services,
      anp: new AnpVerifier(publicDidResolver(tls.fetcher())),
      pap: new PapSessionVerifier(tls.fetcher(), origin),
      mcp: new TokenVerifier(tls.fetcher(), {
        issuer: origin,
        introspectionEndpoint: origin + "/oauth/introspect",
        resource: origin + "/mcp",
        rsId: "website",
        rsSecret: "s".repeat(48),
        allowedScopes: scopes,
      }),
      authorizationServer: createAuthorizationServer(
        store,
        new ClientAuthenticator(tls.fetcher(), origin),
        scopes,
      ),
    });
    const anp = (path: string, message?: object) => {
      const body = message ? JSON.stringify(message) : undefined;
      const method = body ? "POST" : "GET";
      const headers = generateHttpSignatureHeaders(
        did.didDocument,
        origin + path,
        method,
        did.keys["key-1"]!.privateKeyPem,
        {},
        body,
      );
      return tls.http(
        origin + path,
        body,
        { ...headers, ...(body ? { "content-type": "application/json" } : {}) },
        method,
      );
    };
    assert.equal(
      (await tls.http(origin + "/.well-known/agent-descriptions")).status,
      200,
    );
    assert.equal(
      (await tls.http(origin + "/agents/official/ad.json")).status,
      401,
    );
    const ad = await anp("/agents/official/ad.json");
    assert.equal(ad.status, 200);
    assert.equal(JSON.parse(ad.body).did, undefined);
    assert.equal((await anp("/anp/openapi.json")).status, 200);
    assert.equal((await anp("/anp/catalog.json")).status, 200);
    assert.equal(
      JSON.parse((await anp("/anp/api/protocols/1.1/white-paper")).body)
        .content,
      "# ANP 1.1",
    );
    assert.equal((await anp("/anp/api/protocols/9.9/white-paper")).status, 404);
    const anpMessage = await anp("/anp/api/messages", { message: "ANP hello" });
    assert.equal(anpMessage.status, 200);
    assert.equal(
      (
        await tls.http(
          origin + "/anp/api/messages",
          '{"message":"unauthenticated"}',
          { "content-type": "application/json" },
        )
      ).status,
      401,
    );
    const delegatedJwk = await exportJWK(delegated.publicKey);
    const now = Math.floor(Date.now() / 1000);
    const delegation = await new SignJWT({
      iss: clientId,
      cnf: { jwk: delegatedJwk },
      iat: now,
      exp: now + 3600,
      jti: randomUUID(),
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "poppy-delegation+jwt",
        kid: "oauth",
      })
      .sign(oauth.privateKey);
    const pap = async (path: string, message?: object) => {
      const method = message ? "POST" : "GET";
      const proof = await new SignJWT({
        iss: clientId,
        aud: origin,
        sid: "website-session",
        sub: "pairwise-user",
        htm: method,
        htu: origin + path,
        iat: now,
        jti: randomUUID(),
      })
        .setProtectedHeader({
          alg: "ES256",
          typ: "poppy-session+jwt",
          kid: await calculateJwkThumbprint(delegatedJwk),
          poppy_dlg: delegation,
        })
        .sign(delegated.privateKey);
      return tls.http(
        origin + path,
        message ? JSON.stringify(message) : undefined,
        {
          "poppy-session": proof,
          ...(message ? { "content-type": "application/json" } : {}),
        },
        method,
      );
    };
    assert.equal(
      (await tls.http(origin + "/.well-known/poppy.json")).status,
      200,
    );
    assert.equal(
      (await tls.http(origin + "/.well-known/oauth-protected-resource")).status,
      404,
    );
    assert.equal(
      JSON.parse((await pap("/pap/api/protocols/1.1/white-paper")).body)
        .content,
      "# ANP 1.1",
    );
    assert.equal(
      (await pap("/pap/api/messages", { message: "PAP hello" })).status,
      200,
    );
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "oauth" })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience(origin)
      .setIssuedAt()
      .setExpirationTime("60s")
      .setJti(randomUUID())
      .sign(oauth.privateKey);
    const tokenResponse = await tls.http(
      origin + "/oauth/token",
      new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
        resource: origin + "/mcp",
        scope: scopes.join(" "),
      }).toString(),
      { "content-type": "application/x-www-form-urlencoded" },
    );
    assert.equal(tokenResponse.status, 200, tokenResponse.body);
    const token = JSON.parse(tokenResponse.body).access_token;
    const mcp = async (name: string, args: object) =>
      tls.http(
        origin + "/mcp",
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name, arguments: args },
        }),
        {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: "Bearer " + token,
        },
      );
    const read = await mcp("protocol_get", {
      version: "1.1",
      document: "white-paper",
    });
    assert.equal(read.status, 200, read.body);
    assert.equal(
      JSON.parse(JSON.parse(read.body).result.content[0].text).content,
      "# ANP 1.1",
    );
    assert.equal(
      (await mcp("message_create", { message: "MCP hello" })).status,
      200,
    );
    assert.equal(
      (await pool.query("SELECT count(*)::int AS count FROM website_messages"))
        .rows[0].count,
      3,
    );
    const reopened = await createWebsiteServices(catalog, pool);
    assert.equal(
      (await pool.query("SELECT count(*)::int AS count FROM website_messages"))
        .rows[0].count,
      3,
    );
    await assert.rejects(
      reopened.getProtocol({ version: "2.0", document: "white-paper" }),
    );
  } finally {
    await tls.close();
    await pool.end();
  }
});
