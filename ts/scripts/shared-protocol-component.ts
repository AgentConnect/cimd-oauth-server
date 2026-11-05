/** One native DID/CIMD: actual PAP consumer shutdown precedes first machine MCP access. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { RequestListener } from "node:http";
import type { Server } from "node:https";
import { setTimeout as wait } from "node:timers/promises";
import { existsSync } from "node:fs";
import { Pool } from "pg";
import {
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
} from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { object, strictJson } from "../packages/oauth-core/parse.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
import { tlsFixture } from "../tests/helpers.js";

assert.equal(process.env.NODE_ENV, "test");
assert.ok(process.env.DATABASE_URL, "Use E's isolated PostgreSQL owner runner");
assert.ok(
  process.argv[2] && process.argv[3] && process.argv[4],
  "Pass identity, Harness and PAP source roots",
);
const identityRoot = resolve(process.argv[2]!);
const harnessRoot = resolve(process.argv[3]!);
const papRoot = resolve(process.argv[4]!);
const papSourceCommit = execFileSync(
  "git",
  ["-C", papRoot, "rev-parse", "HEAD"],
  { encoding: "utf8" },
).trim();
if (process.env.EXPECTED_PAP_COMMIT)
  assert.equal(papSourceCommit, process.env.EXPECTED_PAP_COMMIT);
assert.equal(
  execFileSync("git", ["-C", papRoot, "status", "--porcelain", "--", "src"], {
    encoding: "utf8",
  }).trim(),
  "",
  "PAP source must be frozen before the shared component run",
);
const nativePath = join(
  identityRoot,
  "bindings/node/anp-identity.linux-x64-gnu.node",
);
const modulePaths: Record<string, string> = {
  cFixture: join(
    identityRoot,
    "packages/dsh-anp-identity/test/helpers/native-protocol-fixture.ts",
  ),
  cAuthority: join(
    identityRoot,
    "packages/dsh-anp-identity/src/target-policy.ts",
  ),
  cHost: join(identityRoot, "packages/dsh-anp-identity/src/index.ts"),
  cProtocolClient: join(
    identityRoot,
    "packages/dsh-anp-identity/src/protocol-client.ts",
  ),
  cPublication: join(
    identityRoot,
    "packages/dsh-anp-identity/src/publication.ts",
  ),
  dMachine: join(harnessRoot, "packages/mcp/mcp-client/src/machine-auth.ts"),
  dNetwork: join(harnessRoot, "packages/mcp/mcp-client/src/machine-http.ts"),
  dStore: join(harnessRoot, "packages/mcp/mcp-client/src/machine-store.ts"),
  dDiscovery: join(
    harnessRoot,
    "packages/mcp/mcp-client/src/machine-discovery.ts",
  ),
  harnessSourceFace: join(harnessRoot, "tsconfig.base.json"),
  fClient: join(papRoot, "src/client.ts"),
  fHost: join(papRoot, "src/protocol-adapter.ts"),
  fNetwork: join(papRoot, "src/network.ts"),
  fStore: join(papRoot, "src/store.ts"),
  fDelegation: join(papRoot, "src/delegation.ts"),
  eAs: resolve("packages/oauth-as/app.ts"),
  eStore: resolve("packages/store-postgres/store.ts"),
  eClient: resolve("packages/oauth-core/client.ts"),
  eRs: resolve("packages/oauth-rs/index.ts"),
  eTls: resolve("tests/helpers.ts"),
  eMcp: resolve("examples/minimal-mcp-server/app.ts"),
  orchestrator: fileURLToPath(import.meta.url),
  eLock: resolve("package-lock.json"),
  fLock: join(papRoot, "package-lock.json"),
  native: nativePath,
};
for (const file of (await readdir(join(papRoot, "src"))).filter((file) =>
  file.endsWith(".ts"),
))
  modulePaths[`fSource:${file}`] = join(papRoot, "src", file);
const sha = async (path: string) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
const sourceSha256 = Object.fromEntries(
  await Promise.all(
    Object.entries(modulePaths).map(async ([key, path]) => [
      key,
      await sha(path),
    ]),
  ),
);
assert.equal(
  sourceSha256.native,
  "e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef",
);

// Explicit source roots supply the real cross-repository APIs, not alternate implementations.
const { createNativeProtocolFixture } = await import(
  pathToFileURL(modulePaths.cFixture!).href
);
const { MachineAuthenticationSession } = await import(
  pathToFileURL(modulePaths.dMachine!).href
);
const { createTestMachineFetch } = await import(
  pathToFileURL(modulePaths.dNetwork!).href
);
interface PapEngine {
  resolvePapCompany(
    domain: string,
  ): Promise<{ companyRef: string; companyId: string; authMode: string }>;
  getOrCreatePapUser(ref: string): Promise<{ subjectRef: string }>;
  openPapSession(ref: string): Promise<{ sessionRef: string }>;
  dispatchPap(
    ref: string,
    operation: { url: string },
  ): Promise<{ status: number; body: Uint8Array }>;
  close(): void;
}
const { PapClient } = (await import(
  pathToFileURL(modulePaths.fClient!).href
)) as { PapClient: new (options: object, transport: object) => PapEngine };
const { ProtocolIdentityHost } = (await import(
  pathToFileURL(modulePaths.fHost!).href
)) as {
  ProtocolIdentityHost: new (
    client: unknown,
    policy: string,
  ) => { dispose(): void };
};
const { SafeHttpsTransport } = (await import(
  pathToFileURL(modulePaths.fNetwork!).href
)) as { SafeHttpsTransport: new (options: object) => object };

const tls = await tlsFixture();
const root = await mkdtemp(join(tmpdir(), "shared-protocol-"));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 8 });
const servers: Server[] = [];
const start = async (handler: RequestListener, host = "localhost") => {
  const listener = await tls.start(handler, host);
  servers.push(listener.server);
  return listener;
};
let fixture:
  | Awaited<ReturnType<typeof createNativeProtocolFixture>>
  | undefined;
let machine: InstanceType<typeof MachineAuthenticationSession> | undefined;
let sdk: Client | undefined;
let pap: PapEngine | undefined;
let tokenPosts = 0,
  revocations = 0,
  forbiddenRequests = 0,
  papRequests = 0,
  identityReads = 0;
let papClosed = false,
  machineConstructed = false;
const grantTypes: string[] = [];
const grantFields: string[][] = [];
const order: string[] = [];
const orderErrors: string[] = [];
let passed: Record<string, unknown> | undefined;
let nativeRoot = "";
const toolJson = (result: unknown) => {
  const text = (
    result as { content?: Array<{ type: string; text?: string }> }
  ).content?.find((item) => item.type === "text")?.text;
  assert.ok(text);
  return object(strictJson(text));
};

try {
  const publisher = await start((request, response) => {
    const materials = fixture?.publicMaterials;
    if (!materials) {
      response.writeHead(503);
      response.end();
      return;
    }
    const metadata = JSON.parse(materials.metadata);
    response.setHeader("content-type", "application/json");
    if (request.url === new URL(metadata.client_id).pathname) {
      identityReads++;
      response.end(materials.metadata);
    } else if (request.url === new URL(metadata.jwks_uri).pathname) {
      identityReads++;
      response.end(materials.jwks);
    } else {
      response.writeHead(404);
      response.end("{}");
    }
  });
  let asHandler: RequestListener = (_request, response) => {
    response.writeHead(503);
    response.end();
  };
  const as = await start((request, response) => {
    if (
      /\/(?:authorize|callback|device|register)(?:\/|$)/u.test(
        request.url ?? "",
      )
    )
      forbiddenRequests++;
    if (request.method === "POST" && request.url === "/oauth/token") {
      tokenPosts++;
      if (!papClosed || !machineConstructed)
        orderErrors.push("token_before_PAP_shutdown_or_MCP_construction");
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        const fields = new URLSearchParams(Buffer.concat(chunks).toString());
        grantTypes.push(fields.get("grant_type") ?? "missing");
        grantFields.push([...fields.keys()].sort());
      });
    }
    if (request.method === "POST" && request.url === "/oauth/revoke")
      revocations++;
    asHandler(request, response);
  });
  let rsHandler: RequestListener = (_request, response) => {
    response.writeHead(503);
    response.end();
  };
  const rs = await start((request, response) => rsHandler(request, response));
  let papHandler: RequestListener = (_request, response) => {
    response.writeHead(503);
    response.end();
  };
  const papListener = await start(
    (request, response) => papHandler(request, response),
    "other.test",
  );
  const papCompany = "https://other.test";
  const resource = rs.origin + "/mcp";
  const scopes = ["agent.self.read", "catalog.read"];
  const ttl = 8;
  const store = new PostgresStore(pool, as.origin);
  await store.configureRequestLimits({
    globalMinute: 240,
    originMinute: 100,
    clientMinute: 60,
    sourceMinute: 100,
  });
  await store.configurePolicy({
    resource,
    scopes,
    ttl,
    maxNewClientsHour: 10,
    maxRequestsClientMinute: 30,
    maxRequestsMinute: 120,
    custodyCondition: "Shared C Context/A native local key component",
    enabled: true,
  });
  const rsId = "shared-protocol-rs",
    rsSecret = randomBytes(32).toString("base64url");
  await store.provisionResourceServer(rsId, rsSecret, [resource]);
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
      rsId,
      rsSecret,
      allowedScopes: scopes,
    }),
  );
  const papConsumerName = "@agentconnect/dsh-pap";
  const machineConsumerName = "@deepseek-ai/dsh-mcp-client";
  fixture = await createNativeProtocolFixture({
    consumer: papConsumerName,
    profiles: ["pap_session"],
    scopes: ["pap.read"],
    issuers: [papCompany],
    resources: [papCompany],
    publicationOrigin: publisher.origin,
    publicationCapabilities: {
      mcpMachine: true,
      papSession: true,
      papAccount: false,
    },
    additionalConsumers: [
      {
        consumer: machineConsumerName,
        profiles: ["mcp_machine"],
        scopes,
        issuers: [as.origin],
        resources: [resource],
      },
    ],
  });
  nativeRoot = fixture.root;
  const papConsumer = fixture.getConsumer(papConsumerName);
  const machineConsumer = fixture.getConsumer(machineConsumerName);
  assert.notEqual(papConsumer.context, machineConsumer.context);
  assert.notEqual(papConsumer.context.fiber, machineConsumer.context.fiber);
  assert.notEqual(papConsumer.policyRef, machineConsumer.policyRef);
  assert.equal(fixture.client, papConsumer.client);
  assert.equal(fixture.context, papConsumer.context);
  const metadataBytes = fixture.publicMaterials.metadata;
  const jwksBytes = fixture.publicMaterials.jwks;
  const metadata = object(strictJson(metadataBytes));
  assert.ok(
    typeof metadata.client_id === "string" &&
      typeof metadata.jwks_uri === "string",
  );
  const clientId = metadata.client_id;
  assert.deepEqual(metadata.grant_types, ["client_credentials"]);
  assert.deepEqual(metadata.response_types, []);
  assert.deepEqual(metadata.redirect_uris, []);
  const document = await fixture.publicDocument();
  assert.equal(document.id, fixture.reference.did);
  const binding = (document.service ?? []).find(
    (item: Record<string, unknown>) => item.type === "ANPCIMD",
  );
  assert.equal(binding?.serviceEndpoint, clientId);
  assert.equal(
    binding?.anp_metadata_sha256,
    createHash("sha256").update(metadataBytes).digest("hex"),
  );
  const clients = async () =>
    (
      await pool.query(
        "SELECT count(*)::integer AS n FROM clients WHERE namespace=$1",
        [store.namespace],
      )
    ).rows[0].n;
  assert.equal(await clients(), 0);
  const seenJti = new Set<string>();
  papHandler = (request, response) => {
    void (async () => {
      response.setHeader("content-type", "application/json");
      assert.equal(request.headers.host, "other.test");
      if (
        [
          "/.well-known/poppy.json",
          "/.well-known/oauth-protected-resource",
          "/openapi.json",
        ].includes(request.url ?? "")
      ) {
        assert.equal(request.headers["poppy-session"], undefined);
        if (request.url === "/.well-known/poppy.json")
          return response.end(
            JSON.stringify({
              protocol_version: "0.3",
              organization: {
                name: "Shared native NoAS component",
                domain: "other.test",
              },
              apis: [{ type: "openapi", url: papCompany + "/openapi.json" }],
            }),
          );
        if (request.url === "/openapi.json")
          return response.end(
            JSON.stringify({
              openapi: "3.1.0",
              servers: [{ url: papCompany }],
              paths: { "/api/identity": { get: {} } },
            }),
          );
        response.statusCode = 404;
        return response.end("{}");
      }
      assert.equal(request.url, "/api/identity");
      assert.equal(request.method, "GET");
      assert.equal(request.headers.authorization, undefined);
      assert.equal(request.headers.dpop, undefined);
      const compact = request.headers["poppy-session"];
      assert.ok(typeof compact === "string");
      assert.equal(decodeJwt(compact).iss, clientId);
      const header = decodeProtectedHeader(compact);
      assert.equal(header.alg, "ES256");
      assert.equal(header.typ, "poppy-session+jwt");
      assert.ok(typeof header.poppy_dlg === "string");
      const delegationHeader = decodeProtectedHeader(header.poppy_dlg);
      const publicMetadata = object(
        strictJson(await tls.fetcher().request(clientId)),
      );
      assert.equal(publicMetadata.client_id, clientId);
      assert.equal(publicMetadata.jwks_uri, metadata.jwks_uri);
      const jwks = object(
        strictJson(
          await tls.fetcher().request(String(publicMetadata.jwks_uri)),
        ),
      );
      assert.ok(Array.isArray(jwks.keys));
      const keys = jwks.keys.filter(
        (key: unknown) => object(key).kid === delegationHeader.kid,
      );
      assert.equal(keys.length, 1);
      const delegation = await jwtVerify(
        header.poppy_dlg,
        await importJWK(keys[0] as JWK, "ES256"),
        {
          algorithms: ["ES256"],
          issuer: clientId,
          typ: "poppy-delegation+jwt",
        },
      );
      const now = Math.floor(Date.now() / 1000);
      assert.ok(
        typeof delegation.payload.exp === "number" &&
          typeof delegation.payload.iat === "number",
      );
      assert.ok(
        delegation.payload.exp > now &&
          delegation.payload.iat <= now + 5 &&
          delegation.payload.exp - delegation.payload.iat <= 86400,
      );
      assert.equal(delegation.payload.sub, undefined);
      assert.equal(delegation.payload.aud, undefined);
      const delegatedJwk = object(object(delegation.payload.cnf).jwk) as JWK;
      assert.equal(delegatedJwk.d, undefined);
      assert.equal(header.kid, await calculateJwkThumbprint(delegatedJwk));
      const session = await jwtVerify(
        compact,
        await importJWK(delegatedJwk, "ES256"),
        {
          algorithms: ["ES256"],
          issuer: clientId,
          audience: papCompany,
          typ: "poppy-session+jwt",
        },
      );
      assert.equal(session.payload.htm, "GET");
      assert.equal(session.payload.htu, papCompany + "/api/identity");
      assert.equal(session.payload.ath, undefined);
      assert.ok(
        typeof session.payload.iat === "number" &&
          session.payload.iat >= now - 60 &&
          session.payload.iat <= now + 5,
      );
      assert.ok(
        typeof session.payload.sid === "string" &&
          typeof session.payload.sub === "string" &&
          typeof session.payload.jti === "string",
      );
      assert.ok(!seenJti.has(session.payload.jti));
      seenJti.add(session.payload.jti);
      papRequests++;
      response.end(JSON.stringify({ verified: true, client_id: clientId }));
    })().catch(() => {
      response.statusCode = 400;
      response.end(JSON.stringify({ error: "invalid_session" }));
    });
  };

  const papMaster = randomBytes(32);
  const papHost = new ProtocolIdentityHost(
    papConsumer.client,
    papConsumer.policyRef,
  );
  pap = new PapClient(
    {
      stateRoot: join(root, "pap-state"),
      binding: {
        identityRef: fixture.reference,
        ownerRef: "shared-protocol-owner",
        clientId,
      },
      secretStore: {
        getEncryptionKey: async () => papMaster,
        getOrCreateEncryptionKey: async () => papMaster,
      },
      identityHost: papHost,
    },
    new SafeHttpsTransport({
      ca: tls.cert,
      privateOrigins: [papCompany],
      portOverrides: { [papCompany]: Number(new URL(papListener.origin).port) },
      lookup: async () => [{ address: "127.0.0.1", family: 4 }],
    }),
  );
  order.push("PAP_engine_started");
  const company = await pap.resolvePapCompany("other.test");
  assert.equal(company.authMode, "no_as");
  assert.equal(company.companyId, papCompany);
  const subject = await pap.getOrCreatePapUser(company.companyRef);
  const papSession = await pap.openPapSession(subject.subjectRef);
  const response = await pap.dispatchPap(papSession.sessionRef, {
    url: papCompany + "/api/identity",
  });
  assert.equal(response.status, 200);
  assert.equal(
    object(strictJson(Buffer.from(response.body))).client_id,
    clientId,
  );
  assert.equal(papRequests, 1);
  assert.equal(tokenPosts, 0);
  assert.equal(await clients(), 0);
  assert.equal(machineConstructed, false);
  order.push("PAP_verified_with_zero_tokens");
  pap.close();
  await assert.rejects(
    pap.dispatchPap(papSession.sessionRef, {
      url: papCompany + "/api/identity",
    }),
  );
  await papConsumer.context.fiber.dispose();
  papListener.server.closeAllConnections();
  await new Promise<void>((resolve) =>
    papListener.server.close(() => resolve()),
  );
  assert.equal(papListener.server.listening, false);
  papClosed = true;
  order.push("PAP_engine_context_leases_server_closed");
  assert.equal(fixture.publicMaterials.metadata, metadataBytes);
  assert.equal(fixture.publicMaterials.jwks, jwksBytes);
  assert.deepEqual(await fixture.publicDocument(), document);
  assert.equal(await clients(), 0);
  assert.equal(tokenPosts, 0);

  const master = randomBytes(32).toString("base64url");
  machineConsumer.context.provide("credentials", {
    resolve: async (ref: string) => {
      assert.equal(ref, "SHARED_MCP_KEY");
      return { value: master };
    },
  });
  const transports = new Map(
    [as.origin, rs.origin].map((origin) => [
      origin,
      createTestMachineFetch({ origin, ca: tls.cert }),
    ]),
  );
  const send = async (
    input: string | URL | Request,
    init: RequestInit = {},
  ) => {
    const request = new Request(input, init);
    assert.equal(request.headers.has("poppy-session"), false);
    assert.equal(request.headers.has("dpop"), false);
    const transport = transports.get(new URL(request.url).origin);
    assert.ok(transport, "No implicit origin fallback");
    return transport(request);
  };
  const stateRoot = join(root, "machine-state");
  machineConstructed = true;
  order.push("MCP_constructed_after_PAP_shutdown");
  machine = new MachineAuthenticationSession(
    machineConsumer.context,
    {
      mode: "cimd-client-credentials",
      connectionId: "shared-protocol-after-pap",
      identityRef: fixture.reference,
      policyRef: machineConsumer.policyRef,
      requestedScopes: scopes,
      stateRoot,
      encryptionKeyRef: "SHARED_MCP_KEY",
      issuer: as.origin,
    },
    resource,
    send,
  );
  sdk = new Client({ name: "shared-protocol-native", version: "1" });
  await sdk.connect(
    new StreamableHTTPClientTransport(new URL(resource), {
      fetch: machine.fetch,
    }),
  );
  assert.deepEqual(
    (await sdk.listTools()).tools.map((tool) => tool.name).sort(),
    ["catalog_list", "identity_get"],
  );
  assert.equal(
    toolJson(await sdk.callTool({ name: "identity_get", arguments: {} }))
      .client_id,
    clientId,
  );
  assert.equal(
    (
      toolJson(await sdk.callTool({ name: "catalog_list", arguments: {} }))
        .items as unknown[]
    ).length,
    2,
  );
  assert.equal(tokenPosts, 1);
  assert.equal(await clients(), 1);
  await wait(ttl * 1000 + 500);
  assert.equal(
    (
      await pool.query(
        "SELECT count(*)::integer AS n FROM access_tokens WHERE namespace=$1 AND client_id=$2 AND expires_at<=clock_timestamp()",
        [store.namespace, clientId],
      )
    ).rows[0].n,
    1,
  );
  assert.equal(
    toolJson(await sdk.callTool({ name: "identity_get", arguments: {} }))
      .client_id,
    clientId,
  );
  assert.equal(
    (
      toolJson(await sdk.callTool({ name: "catalog_list", arguments: {} }))
        .items as unknown[]
    ).length,
    2,
  );
  assert.equal(tokenPosts, 2);
  assert.deepEqual(grantTypes, ["client_credentials", "client_credentials"]);
  for (const fields of grantFields)
    for (const forbidden of [
      "code",
      "redirect_uri",
      "refresh_token",
      "session_id",
      "sid",
      "sub",
    ])
      assert.equal(fields.includes(forbidden), false);
  assert.equal(forbiddenRequests, 0);
  assert.deepEqual(orderErrors, []);
  assert.equal(fixture.publicMaterials.metadata, metadataBytes);
  assert.equal(fixture.publicMaterials.jwks, jwksBytes);
  await sdk.close();
  sdk = undefined;
  await machine.dispose(true);
  assert.equal(
    machine.status().remoteRevocation,
    "remote_revocation_unconfirmed",
  );
  assert.equal(revocations, 1);
  const newest = await pool.query(
    "SELECT revoked_at FROM access_tokens WHERE namespace=$1 AND client_id=$2 ORDER BY issued_at DESC LIMIT 1",
    [store.namespace, clientId],
  );
  assert.ok(newest.rows[0].revoked_at);
  const stateFile = (await readdir(stateRoot)).find((file) =>
    file.endsWith(".json"),
  );
  assert.ok(stateFile);
  assert.equal((await stat(join(stateRoot, stateFile))).mode & 0o077, 0);
  const fence = JSON.parse(await readFile(join(stateRoot, stateFile), "utf8"));
  assert.equal(fence.active, false);
  assert.equal(fence.ciphertext, undefined);
  await assert.rejects(machine.fetch(resource));
  assert.equal(tokenPosts, 2);
  for (const [key, path] of Object.entries(modulePaths))
    assert.equal(await sha(path), sourceSha256[key], `Source changed: ${key}`);
  passed = {
    passed: true,
    lane: "shared-native-DID-CIMD-PAP-off-then-machine-MCP",
    sourceSha256,
    identitySourceCommit: execFileSync(
      "git",
      ["-C", identityRoot, "rev-parse", "HEAD"],
      { encoding: "utf8" },
    ).trim(),
    harnessSourceCommit: execFileSync(
      "git",
      ["-C", harnessRoot, "rev-parse", "HEAD"],
      { encoding: "utf8" },
    ).trim(),
    papSourceCommit,
    sameDidAndCimd: true,
    did: fixture.reference.did,
    clientId,
    metadataSha256: createHash("sha256").update(metadataBytes).digest("hex"),
    jwksSha256: createHash("sha256").update(jwksBytes).digest("hex"),
    distinctInstalledConsumers: true,
    papSessionRequests: papRequests,
    papStageTokenRequests: 0,
    papHostScopeCeiling: ["pap.read"],
    papWireRequestedScopes: [],
    mcpConstructedAfterPapClosed: true,
    ttlSeconds: ttl,
    actualExpiryObserved: true,
    standardTokenRequests: tokenPosts,
    tokenGrantTypes: grantTypes,
    forbiddenAuthorizeCallbackRefresh: forbiddenRequests,
    tools: ["identity_get", "catalog_list"],
    identityPublicReads: identityReads,
    publication: "explicit-fixture-acceptance-mcp-machine-plus-pap-session",
    targetTrust: "separate-installed-F-and-D-contexts",
    aggregateRevocation: machine.status().remoteRevocation,
    order,
    systemProductE2E: "not-run",
    agentPrivateKeys: "not-read-or-exported",
  };
} finally {
  pap?.close();
  await sdk?.close().catch(() => {});
  await machine?.dispose().catch(() => {});
  await fixture?.dispose();
  await tls.close();
  await pool.end();
  await rm(root, { recursive: true, force: true });
}
if (passed) {
  assert.ok(servers.every((server) => !server.listening));
  assert.equal(existsSync(root), false);
  assert.equal(nativeRoot ? existsSync(nativeRoot) : false, false);
  const pgSocket = new URL(process.env.DATABASE_URL!).searchParams.get("host");
  process.stdout.write(
    JSON.stringify({
      ...passed,
      cleanup: {
        tlsServersClosed: true,
        nativeStateRemoved: true,
        papAndMachineStateRemoved: true,
        pgPoolClosed: true,
        pgCluster: "existing-owner-runner-EXIT-trap",
        pgOwnerDirectory: pgSocket
          ? dirname(pgSocket)
          : "not-a-local-owner-socket",
      },
    }) + "\n",
  );
}
