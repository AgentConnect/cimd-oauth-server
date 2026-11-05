/** Real oidc-provider deployment configuration and an independent MCP test application. No AS handler is implemented here. */
import assert from "node:assert/strict";
import https from "node:https";
import type { RequestListener } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import express from "express";
import * as oauth from "oauth4webapi";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { tlsFixture } from "../helpers.js";
const product: string = "oidc-provider";
const { Provider, errors } = await import(product);
export async function independentAsFixture(
  options: { tokenTtlSeconds?: number } = {},
) {
  const tokenTtlSeconds = options.tokenTtlSeconds ?? 3;
  assert.ok(
    Number.isInteger(tokenTtlSeconds) &&
      tokenTtlSeconds > 0 &&
      tokenTtlSeconds <= 300,
  );
  assert.equal(process.env.NODE_ENV, "test");
  const tls = await tlsFixture();
  try {
    const scopes = ["agent.self.read", "catalog.read"];
    const publications = new Map<string, { metadata: string; jwks: string }>();
    const counts = {
      forbiddenFlowRequests: 0,
      tokenRequests: 0,
      revocations: 0,
      publicReads: 0,
      introspections: 0,
    };
    const destroyedClients: string[] = [];
    const destroyedTokenDigests: string[] = [];
    const tokenDigest = (token: any) =>
      createHash("sha256").update(String(token.jti)).digest("hex");
    const facts: Array<{
      clientId: string;
      kind: string;
      scope: string;
      aud: unknown;
      tokenDigest: string;
    }> = [];
    const startPublisher = async () => {
      const listener = await tls.start((req, res) => {
        counts.publicReads++;
        res.setHeader("content-type", "application/json");
        const materials = publications.get(listener.origin);
        if (!materials) {
          res.statusCode = 503;
          res.end("{}");
          return;
        }
        const metadata = JSON.parse(materials.metadata);
        if (req.url === new URL(metadata.client_id).pathname)
          res.end(materials.metadata);
        else if (req.url === new URL(metadata.jwks_uri).pathname)
          res.end(materials.jwks);
        else {
          res.statusCode = 404;
          res.end("{}");
        }
      }, "localhost");
      return listener.origin;
    };
    const nativePublisher = await startPublisher(),
      independentPublisher = await startPublisher();
    let asHandler: RequestListener = (_req, res) => {
      res.statusCode = 503;
      res.end();
    };
    const as = await tls.start((req, res) => {
      if (
        ["/auth", "/reg", "/interaction"].some((path) =>
          req.url?.startsWith(path),
        )
      )
        counts.forbiddenFlowRequests++;
      if (req.method === "POST" && req.url === "/token") counts.tokenRequests++;
      if (req.method === "POST" && req.url === "/token/revocation")
        counts.revocations++;
      if (req.method === "POST" && req.url === "/token/introspection")
        counts.introspections++;
      asHandler(req, res);
    }, "localhost");
    let rsHandler: RequestListener = (_req, res) => {
      res.statusCode = 503;
      res.end();
    };
    const rs = await tls.start((req, res) => rsHandler(req, res), "localhost");
    const resource = rs.origin + "/mcp";
    const issuer = new URL(as.origin);
    const allowedOrigins = new Set([
      as.origin,
      rs.origin,
      nativePublisher,
      independentPublisher,
    ]);
    const fetch: typeof globalThis.fetch = async (input, init = {}) => {
      const original =
        input instanceof Request ? input : new Request(input, init);
      const target = new URL(original.url);
      assert.ok(
        allowedOrigins.has(target.origin),
        "Exact configured test origin required",
      );
      const method =
        input instanceof Request && init.method === undefined
          ? input.method
          : (init.method ?? "GET");
      const headers = Object.fromEntries(
        new Headers(init.headers ?? original.headers).entries(),
      );
      const body =
        init.body instanceof URLSearchParams
          ? init.body.toString()
          : typeof init.body === "string"
            ? init.body
            : undefined;
      assert.ok(
        init.body === undefined ||
          init.body === null ||
          typeof init.body === "string" ||
          init.body instanceof URLSearchParams,
        "Unsupported test body",
      );
      assert.ok(
        body === undefined || Buffer.byteLength(body) <= 24576,
        "Bounded test request",
      );
      return new Promise<Response>((resolve, reject) => {
        const request = https.request(
          target,
          {
            method,
            headers,
            agent: false,
            rejectUnauthorized: true,
            ca: tls.cert,
            maxHeaderSize: 16384,
            signal: AbortSignal.any([
              AbortSignal.timeout(5000),
              ...(init.signal ? [init.signal] : []),
            ]),
            lookup: ((_host: string, o: { all?: boolean }, cb: Function) =>
              o.all
                ? cb(null, [{ address: "127.0.0.1", family: 4 }])
                : cb(null, "127.0.0.1", 4)) as never,
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            let size = 0;
            incoming.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size > 65536)
                incoming.destroy(new Error("test_response_too_large"));
              else chunks.push(chunk);
            });
            incoming.on("error", reject);
            incoming.on("end", () => {
              const output = new Headers();
              for (const [name, value] of Object.entries(incoming.headers)) {
                if (Array.isArray(value))
                  value.forEach((v) => output.append(name, v));
                else if (value !== undefined) output.set(name, value);
              }
              const status = incoming.statusCode!;
              resolve(
                new Response(
                  [204, 205, 304].includes(status)
                    ? null
                    : Buffer.concat(chunks),
                  { status, headers: output },
                ),
              );
            });
          },
        );
        request.on("error", reject);
        if (body !== undefined) request.write(body);
        request.end();
      });
    };
    const key = await oauth.generateKeyPair("RS256", { extractable: true });
    const signing = await crypto.subtle.exportKey("jwk", key.privateKey);
    const rsPair = await oauth.generateKeyPair("ES256");
    const rsPublic = await crypto.subtle.exportKey("jwk", rsPair.publicKey);
    const rsClient: oauth.Client = { client_id: "independent-resource-server" };
    const rsAuthentication = oauth.PrivateKeyJwt({
      key: rsPair.privateKey,
      kid: "resource-server-key",
    });
    let fetchBudget = 0;
    const provider = new Provider(as.origin, {
      clients: [
        {
          client_id: rsClient.client_id,
          grant_types: ["client_credentials"],
          response_types: [],
          redirect_uris: [],
          token_endpoint_auth_method: "private_key_jwt",
          token_endpoint_auth_signing_alg: "ES256",
          jwks: {
            keys: [
              {
                ...rsPublic,
                kid: "resource-server-key",
                alg: "ES256",
                use: "sig",
              },
            ],
          },
        },
      ],
      responseTypes: [],
      clockTolerance: 0,
      scopes,
      clientAuthMethods: ["private_key_jwt"],
      enabledJWA: { clientAuthSigningAlgValues: ["ES256"] },
      jwks: {
        keys: [
          {
            ...signing,
            kid: "independent-as-signing",
            alg: "RS256",
            use: "sig",
          },
        ],
      },
      cookies: { keys: [randomBytes(32).toString("base64url")] },
      fetch: (url: string, options: RequestInit) => fetch(url, options),
      ttl: { ClientCredentials: tokenTtlSeconds },
      features: {
        devInteractions: { enabled: false },
        registration: { enabled: false },
        clientCredentials: { enabled: true },
        revocation: {
          enabled: true,
          allowedPolicy: async (_ctx: unknown, client: any, token: any) =>
            token.kind === "ClientCredentials" &&
            token.clientId === client.clientId,
        },
        clientIdMetadataDocument: {
          enabled: true,
          ack: "draft-02",
          allowFetch: async (_ctx: unknown, id: string) => {
            const url = new URL(id);
            return (
              ++fetchBudget <= 40 &&
              [nativePublisher, independentPublisher].includes(url.origin) &&
              url.pathname.endsWith("/client.json")
            );
          },
          allowClient: async (_ctx: unknown, client: any) =>
            client.clientAuthMethod === "private_key_jwt" &&
            client.tokenEndpointAuthSigningAlg === "ES256" &&
            client.grantTypeAllowed("client_credentials"),
        },
        introspection: {
          enabled: true,
          allowedPolicy: async (_ctx: unknown, client: any, token: any) =>
            client.clientId === rsClient.client_id &&
            token.kind === "ClientCredentials" &&
            token.aud === resource,
        },
        resourceIndicators: {
          enabled: true,
          defaultResource: async () => {
            throw new errors.InvalidTarget("explicit resource required");
          },
          getResourceServerInfo: async (ctx: any, id: string) => {
            if (id !== resource)
              throw new errors.InvalidTarget("resource not allowed");
            const requested = String(ctx.oidc.params.scope ?? "")
              .split(" ")
              .filter(Boolean);
            if (
              !requested.length ||
              requested.some((value) => !scopes.includes(value))
            )
              throw new errors.InvalidScope("scope not allowed");
            return {
              scope: scopes.join(" "),
              audience: resource,
              accessTokenTTL: tokenTtlSeconds,
              accessTokenFormat: "opaque",
            };
          },
        },
      },
      extraTokenClaims: async (_ctx: unknown, token: any) => {
        if (token.kind !== "ClientCredentials") return undefined;
        facts.push({
          clientId: token.clientId,
          kind: token.kind,
          scope: token.scope,
          aud: token.aud,
          tokenDigest: tokenDigest(token),
        });
        // Official hook derives this application marker only from the library's native token kind.
        return { grant_type: "client_credentials" };
      },
    });
    provider.on("client_credentials.destroyed", (token: any) => {
      destroyedClients.push(token.clientId);
      destroyedTokenDigests.push(tokenDigest(token));
    });
    asHandler = provider.callback();
    const metadata = await oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, {
        algorithm: "oauth2",
        [oauth.customFetch]: fetch,
      }),
    );
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.ok(metadata.grant_types_supported?.includes("client_credentials"));
    assert.ok(
      metadata.token_endpoint_auth_methods_supported?.includes(
        "private_key_jwt",
      ),
    );
    assert.ok(
      metadata.token_endpoint_auth_signing_alg_values_supported?.includes(
        "ES256",
      ),
    );
    const introspect = async (token: string) =>
      oauth.processIntrospectionResponse(
        metadata,
        rsClient,
        await oauth.introspectionRequest(
          metadata,
          rsClient,
          rsAuthentication,
          token,
          { [oauth.customFetch]: fetch },
        ),
      );
    type Principal = oauth.IntrospectionResponse & {
      active: true;
      client_id: string;
      exp: number;
      scope: string;
    };
    const authenticate = async (
      bearer: string | undefined,
    ): Promise<Principal | undefined> => {
      if (!bearer?.startsWith("Bearer ")) return undefined;
      let principal: oauth.IntrospectionResponse;
      try {
        principal = await introspect(bearer.slice(7));
      } catch {
        return undefined;
      }
      if (
        principal.active !== true ||
        principal.iss !== as.origin ||
        principal.aud !== resource ||
        principal.grant_type !== "client_credentials" ||
        typeof principal.client_id !== "string" ||
        typeof principal.exp !== "number" ||
        principal.exp <= Date.now() / 1000 ||
        typeof principal.scope !== "string" ||
        principal.scope.split(" ").some((scope) => !scopes.includes(scope))
      )
        return undefined;
      return principal as Principal;
    };
    const app = express();
    app.disable("x-powered-by");
    app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) =>
      res.json({
        resource,
        authorization_servers: [as.origin],
        scopes_supported: scopes,
        bearer_methods_supported: ["header"],
      }),
    );
    app.post("/mcp", express.json({ limit: "64kb" }), async (req, res) => {
      const challenge = () =>
        res
          .status(401)
          .set(
            "WWW-Authenticate",
            `Bearer resource_metadata="${rs.origin}/.well-known/oauth-protected-resource/mcp"`,
          )
          .json({ error: "invalid_token" });
      const bearer = req.headers.authorization;
      if (!bearer?.startsWith("Bearer ")) return challenge();
      const principal = await authenticate(bearer);
      if (!principal) return challenge();
      const actual = principal.scope.split(" ");
      const message = req.body;
      if (!message || typeof message.method !== "string")
        return res.status(400).json({ error: "invalid_request" });
      const toolScopes: Record<string, string> = {
        identity_get: "agent.self.read",
        catalog_list: "catalog.read",
      };
      if (
        message.method === "tools/call" &&
        !actual.includes(toolScopes[message.params?.name] ?? "")
      )
        return res.status(403).json({ error: "insufficient_scope" });
      if (
        ![
          "initialize",
          "notifications/initialized",
          "ping",
          "tools/list",
          "tools/call",
        ].includes(message.method)
      )
        return res.status(403).json({ error: "insufficient_scope" });
      const server = new Server(
        { name: "independent-product-rs", version: "1.0.0" },
        { capabilities: { tools: {} } },
      );
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: Object.entries(toolScopes)
          .filter(([, scope]) => actual.includes(scope))
          .map(([name]) => ({
            name,
            inputSchema: { type: "object" as const, properties: {} },
            annotations: { readOnlyHint: true, destructiveHint: false },
          })),
      }));
      server.setRequestHandler(CallToolRequestSchema, async (request) => {
        if (!actual.includes(toolScopes[request.params.name] ?? ""))
          throw new Error("insufficient_scope");
        const value =
          request.params.name === "identity_get"
            ? {
                client_id: principal.client_id,
                subject: principal.client_id,
                resource,
                scope: principal.scope,
                grant_type: principal.grant_type,
              }
            : {
                items: [
                  { id: "independent-notebook", name: "Notebook" },
                  { id: "independent-pencil", name: "Pencil" },
                ],
              };
        return {
          content: [{ type: "text" as const, text: JSON.stringify(value) }],
        };
      });
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, message);
    });
    app.all("/mcp", async (req, res) => {
      if (!(await authenticate(req.headers.authorization)))
        return res
          .status(401)
          .set(
            "WWW-Authenticate",
            `Bearer resource_metadata="${rs.origin}/.well-known/oauth-protected-resource/mcp"`,
          )
          .json({ error: "invalid_token" });
      // JSON-only Streamable HTTP does not expose an SSE GET stream; valid credentials receive 405.
      return res.status(405).set("Allow", "POST").end();
    });
    rsHandler = app;
    const standalone = await oauth.generateKeyPair("ES256");
    const standalonePublic = await crypto.subtle.exportKey(
      "jwk",
      standalone.publicKey,
    );
    const independentClient: oauth.Client = {
      client_id: independentPublisher + "/machine/client.json",
    };
    publications.set(independentPublisher, {
      metadata: JSON.stringify({
        client_id: independentClient.client_id,
        jwks_uri: independentPublisher + "/machine/jwks.json",
        grant_types: ["client_credentials"],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
      }),
      jwks: JSON.stringify({
        keys: [
          {
            ...standalonePublic,
            kid: "standalone-key",
            alg: "ES256",
            use: "sig",
          },
        ],
      }),
    });
    return {
      provider,
      tokenTtlSeconds,
      ca: tls.cert,
      preconfiguredClientIds: [rsClient.client_id],
      metadata,
      resource,
      issuer: as.origin,
      nativePublisher,
      independentPublisher,
      fetch,
      counts,
      facts,
      destroyedClients,
      destroyedTokenDigests,
      introspect,
      independentClient,
      independentAuthentication: oauth.PrivateKeyJwt({
        key: standalone.privateKey,
        kid: "standalone-key",
      }),
      setNativePublication: (materials: { metadata: string; jwks: string }) =>
        publications.set(nativePublisher, materials),
      async close() {
        await tls.close();
      },
    };
  } catch (error) {
    await tls.close();
    throw error;
  }
}
