/** Explicit source integration: real C Context + A native -> D machine session -> E TLS/PG/MCP. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { RequestListener } from "node:http";
import { Pool } from "pg";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
import { tlsFixture } from "../tests/helpers.js";

assert.equal(process.env.NODE_ENV, "test");
assert.ok(process.env.DATABASE_URL, "Use the isolated test:dsh-native runner");
const identitySource = resolve(process.argv[2] ?? "");
const harnessSource = resolve(process.argv[3] ?? "");
assert.ok(
  process.argv[2] && process.argv[3],
  "Pass explicit ANP Identity and Harness source roots",
);
const fixtureModule = join(
  identitySource,
  "packages/dsh-anp-identity/test/helpers/native-protocol-fixture.ts",
);
const sessionModule = join(
  harnessSource,
  "packages/mcp/mcp-client/src/machine-auth.ts",
);
const transportModule = join(
  harnessSource,
  "packages/mcp/mcp-client/src/machine-http.ts",
);
const nativePath = join(
  identitySource,
  "bindings/node/anp-identity.linux-x64-gnu.node",
);
const hash = async (path: string) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
const sourceFiles: Record<string, string> = {
  dMachine: sessionModule,
  dNetwork: transportModule,
  cFixture: fixtureModule,
  native: nativePath,
  dStore: join(harnessSource, "packages/mcp/mcp-client/src/machine-store.ts"),
  dDiscovery: join(
    harnessSource,
    "packages/mcp/mcp-client/src/machine-discovery.ts",
  ),
  sourceFace: join(harnessSource, "tsconfig.base.json"),
  cAuthority: join(
    identitySource,
    "packages/dsh-anp-identity/src/target-policy.ts",
  ),
  cHost: join(identitySource, "packages/dsh-anp-identity/src/index.ts"),
  cPublication: join(
    identitySource,
    "packages/dsh-anp-identity/src/publication.ts",
  ),
};
const sourceSha256 = Object.fromEntries(
  await Promise.all(
    Object.entries(sourceFiles).map(async ([name, path]) => [
      name,
      await hash(path),
    ]),
  ),
);
const { createNativeProtocolFixture } = await import(
  pathToFileURL(fixtureModule).href
);
const { MachineAuthenticationSession } = await import(
  pathToFileURL(sessionModule).href
);
const { createTestMachineFetch } = await import(
  pathToFileURL(transportModule).href
);
const nativeSha256 = await hash(nativePath);
assert.equal(
  nativeSha256,
  "e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef",
);
const tls = await tlsFixture();
const root = await mkdtemp(join(tmpdir(), "cimd-dsh-native-"));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 8 });
let fixture:
  | Awaited<ReturnType<typeof createNativeProtocolFixture>>
  | undefined;
let session: InstanceType<typeof MachineAuthenticationSession> | undefined;
let rejectedSession:
  | InstanceType<typeof MachineAuthenticationSession>
  | undefined;
let client: Client | undefined;
let tokenPosts = 0,
  revokePosts = 0,
  publicReads = 0;
const readTool = (value: unknown): Record<string, unknown> => {
  const result = value as { content?: Array<{ type: string; text?: string }> };
  const text = result.content?.find((item) => item.type === "text")?.text;
  assert.ok(text);
  return JSON.parse(text) as Record<string, unknown>;
};
try {
  const identity = await tls.start((req, res) => {
    publicReads++;
    res.setHeader("content-type", "application/json");
    const materials = fixture?.publicMaterials;
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
  let asHandler: RequestListener = (_req, res) => {
    res.statusCode = 503;
    res.end();
  };
  const as = await tls.start((req, res) => {
    if (req.method === "POST" && req.url === "/oauth/token") tokenPosts++;
    if (req.method === "POST" && req.url === "/oauth/revoke") revokePosts++;
    asHandler(req, res);
  }, "localhost");
  let rsHandler: RequestListener = (_req, res) => {
    res.statusCode = 503;
    res.end();
  };
  const rs = await tls.start((req, res) => rsHandler(req, res), "localhost");
  const resource = rs.origin + "/mcp";
  const scopes = ["agent.self.read", "catalog.read"];
  const store = new PostgresStore(pool, as.origin);
  await store.configureRequestLimits({
    globalMinute: 120,
    originMinute: 40,
    clientMinute: 20,
    sourceMinute: 60,
  });
  await store.configurePolicy({
    resource,
    scopes,
    ttl: 300,
    maxNewClientsHour: 10,
    maxRequestsClientMinute: 10,
    maxRequestsMinute: 60,
    custodyCondition:
      "Isolated C Context / A encrypted native local key fixture",
    enabled: true,
  });
  const rsId = "native-component-rs",
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
  fixture = await createNativeProtocolFixture({
    consumer: "@deepseek-ai/dsh-mcp-client",
    profiles: ["mcp_machine"],
    scopes,
    issuers: [as.origin],
    resources: [resource],
    publicationOrigin: identity.origin,
    publicationCapabilities: {
      mcpMachine: true,
      papSession: false,
      papAccount: false,
    },
  });
  const published = JSON.parse(fixture.publicMaterials.metadata);
  assert.equal(published.client_id.startsWith(identity.origin + "/"), true);
  assert.deepEqual(published.grant_types, ["client_credentials"]);
  assert.deepEqual(published.response_types, []);
  assert.deepEqual(published.redirect_uris, []);
  const document = await fixture.publicDocument();
  const bindings = (document.service ?? []).filter(
    (service: Record<string, unknown>) => service.type === "ANPCIMD",
  );
  assert.equal(bindings.length, 1);
  assert.equal(bindings[0].serviceEndpoint, published.client_id);
  assert.equal(
    bindings[0].anp_metadata_sha256,
    createHash("sha256").update(fixture.publicMaterials.metadata).digest("hex"),
  );

  assert.equal(
    (await pool.query("SELECT count(*)::integer AS n FROM clients")).rows[0].n,
    0,
  );
  const master = randomBytes(32).toString("base64url");
  fixture.context.provide("credentials", {
    resolve: async (ref: string) => {
      assert.equal(ref, "MCP_KEY");
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
    const url = input instanceof Request ? input.url : String(input);
    const transport = transports.get(new URL(url).origin);
    assert.ok(transport, "No implicit origin or transport fallback");
    return transport(input, init);
  };
  const config = {
    mode: "cimd-client-credentials",
    connectionId: "native-chain",
    identityRef: fixture.reference,
    policyRef: fixture.policyRef,
    requestedScopes: scopes,
    stateRoot: join(root, "credentials"),
    encryptionKeyRef: "MCP_KEY",
    issuer: as.origin,
  };
  session = new MachineAuthenticationSession(
    fixture.context,
    config,
    resource,
    send,
  );
  client = new Client({ name: "D-E-native-component", version: "1.0.0" });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(resource), {
      fetch: session.fetch,
    }),
  );
  assert.deepEqual(
    (await client.listTools()).tools.map((tool) => tool.name).sort(),
    ["catalog_list", "identity_get"],
  );
  const identityResult = readTool(
    await client.callTool({ name: "identity_get", arguments: {} }),
  );
  const catalogResult = readTool(
    await client.callTool({ name: "catalog_list", arguments: {} }),
  );
  assert.equal(identityResult.client_id, published.client_id);
  assert.equal(identityResult.resource, resource);
  assert.equal(identityResult.scope, scopes.join(" "));
  assert.ok(Array.isArray(catalogResult.items));
  assert.equal(catalogResult.items.length, 2);
  assert.equal(tokenPosts, 1);
  assert.ok(publicReads >= 2);
  const machines = await pool.query(
    "SELECT subject FROM clients WHERE namespace=$1 AND client_id=$2",
    [store.namespace, published.client_id],
  );
  assert.equal(machines.rowCount, 1);
  assert.equal(machines.rows[0].subject, identityResult.subject);
  assert.equal(
    (
      await pool.query(
        "SELECT count(*)::integer AS n FROM access_tokens WHERE client_id=$1",
        [published.client_id],
      )
    ).rows[0].n,
    1,
  );
  const stateFile = (await readdir(config.stateRoot)).find((name) =>
    name.endsWith(".json"),
  );
  assert.ok(stateFile);
  const path = join(config.stateRoot, stateFile);
  assert.equal((await stat(path)).mode & 0o077, 0);
  const encrypted = JSON.parse(await readFile(path, "utf8"));
  assert.ok(encrypted.ciphertext && encrypted.iv && encrypted.tag);
  assert.equal(encrypted.token, undefined);
  rejectedSession = new MachineAuthenticationSession(
    fixture.context,
    {
      ...config,
      connectionId: "forbidden-native-scope",
      requestedScopes: ["account.profile.read"],
    },
    resource,
    send,
  );
  await assert.rejects(
    rejectedSession.fetch(resource, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 999, method: "tools/list" }),
    }),
  );
  assert.equal(tokenPosts, 1);
  await rejectedSession.dispose();
  rejectedSession = undefined;
  await client.close();
  client = undefined;
  await session.dispose(true);
  assert.equal(session.status().remoteRevocation, "confirmed");
  assert.equal(revokePosts, 1);
  assert.equal(
    (
      await pool.query(
        "SELECT count(*)::integer AS n FROM access_tokens WHERE client_id=$1 AND revoked_at IS NOT NULL",
        [published.client_id],
      )
    ).rows[0].n,
    1,
  );
  await assert.rejects(session.fetch(resource));
  assert.equal(tokenPosts, 1);
  const fence = JSON.parse(await readFile(path, "utf8"));
  assert.equal(fence.active, false);
  assert.equal(fence.ciphertext, undefined);
  const commit = (source: string) =>
    execFileSync("git", ["-C", source, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
  for (const [name, path] of Object.entries(sourceFiles))
    assert.equal(
      await hash(path),
      sourceSha256[name],
      `Source changed during component run: ${name}`,
    );
  const dirty = (source: string) =>
    Boolean(
      execFileSync("git", ["-C", source, "status", "--porcelain"], {
        encoding: "utf8",
      }).trim(),
    );
  process.stdout.write(
    JSON.stringify({
      passed: true,
      lane: "real-C-context-A-native-D-machine-E-TLS-Postgres-MCP",
      identitySourceCommit: commit(identitySource),
      harnessSourceCommit: commit(harnessSource),
      nativeSha256,
      sourceSha256,
      identitySourceDirty: dirty(identitySource),
      harnessSourceDirty: dirty(harnessSource),
      dMachineSha256: sourceSha256.dMachine,
      dNetworkSha256: sourceSha256.dNetwork,
      cFixtureSha256: sourceSha256.cFixture,
      tools: ["identity_get", "catalog_list"],
      standardTokenRequests: tokenPosts,
      remoteRevocations: revokePosts,
      uniqueMachine: true,
      encryptedLocalCredentials: true,
      scopePolicyRefusedBeforeToken: true,
      disconnectFence: true,
      publication: "explicit-fixture-acceptance-and-real-TLS-public-bytes",
      targetTrust: "trusted-installed-D-adapter-context-no-C-network-refetch",
      systemProductE2E: "not-run",
    }) + "\n",
  );
} finally {
  await client?.close().catch(() => {});
  await rejectedSession?.dispose().catch(() => {});
  await session?.dispose().catch(() => {});
  await fixture?.dispose();
  await tls.close();
  await pool.end();
  await rm(root, { recursive: true, force: true });
}
