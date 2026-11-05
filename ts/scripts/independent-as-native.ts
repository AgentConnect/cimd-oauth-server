/** Final source integration: native C/A -> official D -> unmodified independent oidc-provider AS -> SDK MCP application. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import * as oauth from "oauth4webapi";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { independentAsFixture } from "../tests/independent-as/fixture.js";
assert.equal(process.env.NODE_ENV, "test");
assert.ok(
  process.argv[2] && process.argv[3],
  "Explicit identity and D source roots required",
);
const identitySource = resolve(process.argv[2]!),
  dSource = resolve(process.argv[3]!);
const modulePaths = {
  nativeFixture: join(
    identitySource,
    "packages/dsh-anp-identity/test/helpers/registered-protocol-fixture.ts",
  ),
  dMachine: join(dSource, "packages/mcp/mcp-client/src/machine-auth.ts"),
  dNetwork: join(dSource, "packages/mcp/mcp-client/src/machine-http.ts"),
  dStore: join(dSource, "packages/mcp/mcp-client/src/machine-store.ts"),
  sourceFace: join(dSource, "tsconfig.base.json"),
  cAuthority: join(
    identitySource,
    "packages/dsh-anp-identity/src/target-policy.ts",
  ),
  cHost: join(identitySource, "packages/dsh-anp-identity/src/index.ts"),
  cPublication: join(
    identitySource,
    "packages/dsh-anp-identity/src/publication.ts",
  ),
  bBridge: join(
    resolve(process.env.DSH_IDENTITY_USER_SERVICE_SOURCE ?? ""),
    "tests/app/cimd/management_bridge.py",
  ),
  independentAsCore: resolve("node_modules/oidc-provider/lib/provider.js"),
  independentAsCimd: resolve(
    "node_modules/oidc-provider/lib/helpers/client_id_metadata_document.js",
  ),
  independentAsClientAuth: resolve(
    "node_modules/oidc-provider/lib/shared/client_auth.js",
  ),
  independentAsCc: resolve(
    "node_modules/oidc-provider/lib/actions/grants/client_credentials.js",
  ),
  independentAsIntrospection: resolve(
    "node_modules/oidc-provider/lib/actions/introspection.js",
  ),
  lock: resolve("package-lock.json"),
  native: join(identitySource, "bindings/node/anp-identity.linux-x64-gnu.node"),
};
const sha = async (path: string) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
const sourceSha256 = Object.fromEntries(
  await Promise.all(
    Object.entries(modulePaths).map(async ([name, path]) => [
      name,
      await sha(path),
    ]),
  ),
);
assert.equal(
  sourceSha256.native,
  "e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef",
);
const { createRegisteredProtocolFixture } = await import(
  pathToFileURL(modulePaths.nativeFixture).href
);
const { MachineAuthenticationSession } = await import(
  pathToFileURL(modulePaths.dMachine).href
);
const { createTestMachineFetch } = await import(
  pathToFileURL(modulePaths.dNetwork).href
);
const f = await independentAsFixture({ tokenTtlSeconds: 8 });
const root = await mkdtemp(join(tmpdir(), "independent-as-native-"));
let fixture:
  | Awaited<ReturnType<typeof createRegisteredProtocolFixture>>
  | undefined;
let session: InstanceType<typeof MachineAuthenticationSession> | undefined;
let badSession: InstanceType<typeof MachineAuthenticationSession> | undefined;
let client: Client | undefined;
const toolResult = (value: unknown) => {
  const content = (
    value as { content?: Array<{ type: string; text?: string }> }
  ).content;
  const text = content?.find((item) => item.type === "text")?.text;
  assert.ok(text);
  return JSON.parse(text) as Record<string, unknown>;
};
try {
  assert.equal(f.counts.publicReads, 0);
  assert.deepEqual(f.preconfiguredClientIds, ["independent-resource-server"]);
  fixture = await createRegisteredProtocolFixture({
    consumer: "@deepseek-ai/dsh-mcp-client",
    profiles: ["mcp_machine"],
    scopes: ["agent.self.read", "catalog.read", "account.profile.read"],
    issuers: [f.issuer],
    resources: [f.resource],
    publicationOrigin: f.nativePublisher,
  });
  f.setNativePublication(fixture.publicMaterials);
  const published = JSON.parse(fixture.publicMaterials.metadata);
  assert.ok(
    published.client_id.startsWith(f.nativePublisher + "/"),
    "B generated client_id must remain on its configured test publication origin",
  );
  assert.deepEqual(published.grant_types, ["client_credentials"]);
  assert.deepEqual(published.response_types, []);
  assert.deepEqual(published.redirect_uris, []);
  const document = await fixture.publicDocument();
  const bindings = (document.service ?? []).filter(
    (s: Record<string, unknown>) => s.type === "ANPCIMD",
  );
  assert.equal(bindings.length, 1);
  assert.equal(bindings[0].serviceEndpoint, published.client_id);
  assert.equal(
    bindings[0].anp_metadata_sha256,
    createHash("sha256").update(fixture.publicMaterials.metadata).digest("hex"),
  );
  const encryptionKey = randomBytes(32).toString("base64url");
  fixture.context.provide("credentials", {
    resolve: async (ref: string) => {
      assert.equal(ref, "INDEPENDENT_MCP_KEY");
      return { value: encryptionKey };
    },
  });
  const origins = [f.issuer, new URL(f.resource).origin];
  const transports = new Map(
    origins.map((origin) => [
      origin,
      createTestMachineFetch({ origin, ca: f.ca }),
    ]),
  );
  const send = async (
    input: string | URL | Request,
    init: RequestInit = {},
  ) => {
    const target = input instanceof Request ? input.url : String(input);
    const transport = transports.get(new URL(target).origin);
    assert.ok(transport, "Exact D transport origin required");
    return transport(input, init);
  };
  const config = {
    mode: "cimd-client-credentials",
    connectionId: "independent-AS-native",
    identityRef: fixture.reference,
    policyRef: fixture.policyRef,
    requestedScopes: ["agent.self.read", "catalog.read"],
    stateRoot: join(root, "machine-state"),
    encryptionKeyRef: "INDEPENDENT_MCP_KEY",
    issuer: f.issuer,
  };
  session = new MachineAuthenticationSession(
    fixture.context,
    config,
    f.resource,
    send,
  );
  client = new Client({
    name: "native-C-A-D-independent-AS",
    version: "1.0.0",
  });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(f.resource), {
      fetch: session.fetch,
    }),
  );
  assert.deepEqual(
    (await client.listTools()).tools.map((tool) => tool.name).sort(),
    ["catalog_list", "identity_get"],
  );
  const initial = toolResult(
    await client.callTool({ name: "identity_get", arguments: {} }),
  );
  assert.equal(initial.client_id, published.client_id);
  assert.equal(initial.subject, published.client_id);
  assert.equal(initial.grant_type, "client_credentials");
  const catalog = toolResult(
    await client.callTool({ name: "catalog_list", arguments: {} }),
  );
  assert.equal((catalog.items as unknown[]).length, 2);
  assert.equal(f.counts.tokenRequests, 1);
  assert.equal(f.facts[0]?.kind, "ClientCredentials");
  assert.equal(f.facts[0]?.clientId, published.client_id);
  await new Promise((resolve) =>
    setTimeout(resolve, f.tokenTtlSeconds * 1000 + 150),
  );
  const afterExpiry = toolResult(
    await client.callTool({ name: "identity_get", arguments: {} }),
  );
  assert.equal(afterExpiry.subject, initial.subject);
  assert.equal(f.counts.tokenRequests, 2);
  assert.equal(
    f.facts.filter((fact) => fact.clientId === published.client_id).length,
    2,
  );
  const beforeBad = f.facts.length;
  badSession = new MachineAuthenticationSession(
    fixture.context,
    {
      ...config,
      connectionId: "independent-AS-denied",
      requestedScopes: ["account.profile.read"],
    },
    f.resource,
    send,
  );
  await assert.rejects(
    badSession.fetch(f.resource, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 999, method: "tools/list" }),
    }),
  );
  assert.equal(f.counts.tokenRequests, 3);
  assert.equal(f.facts.length, beforeBad);
  await badSession.dispose();
  badSession = undefined;
  const other = await oauth.processClientCredentialsResponse(
    f.metadata,
    f.independentClient,
    await oauth.clientCredentialsGrantRequest(
      f.metadata,
      f.independentClient,
      f.independentAuthentication,
      { resource: f.resource, scope: "agent.self.read catalog.read" },
      { [oauth.customFetch]: f.fetch },
    ),
  );
  assert.equal((await f.introspect(other.access_token)).active, true);
  assert.deepEqual(
    new Set(f.facts.map((fact) => fact.clientId)),
    new Set([published.client_id, f.independentClient.client_id]),
  );
  const otherClient = new Client({
    name: "independent-publisher-client",
    version: "1.0.0",
  });
  try {
    await otherClient.connect(
      new StreamableHTTPClientTransport(new URL(f.resource), {
        fetch: f.fetch,
        requestInit: {
          headers: { authorization: `Bearer ${other.access_token}` },
        },
      }),
    );
    assert.ok(
      JSON.stringify(
        await otherClient.callTool({ name: "identity_get", arguments: {} }),
      ).includes(f.independentClient.client_id),
    );
    assert.ok(
      JSON.stringify(
        await otherClient.callTool({ name: "catalog_list", arguments: {} }),
      ).includes("independent-notebook"),
    );
  } finally {
    await otherClient.close();
  }
  await client.close();
  client = undefined;
  await session.dispose(true);
  // D conservatively keeps aggregate revocation unconfirmed after multiple issuances.
  // Verify the concrete latest token independently through the real AS native destroy event.
  assert.equal(
    session.status().remoteRevocation,
    "remote_revocation_unconfirmed",
  );
  const lastNative = f.facts
    .filter((fact) => fact.clientId === published.client_id)
    .at(-1);
  assert.ok(lastNative);
  assert.ok(f.destroyedClients.includes(published.client_id));
  assert.ok(
    f.destroyedTokenDigests.includes(lastNative.tokenDigest),
    "Native AS destroyed the actual latest token",
  );
  assert.equal((await f.introspect(other.access_token)).active, true);
  await assert.rejects(session.fetch(f.resource));
  const stored = join(
    config.stateRoot,
    createHash("sha256").update(config.connectionId).digest("hex") + ".json",
  );
  assert.equal(JSON.parse(await readFile(stored, "utf8")).active, false);
  assert.equal(f.counts.forbiddenFlowRequests, 0);
  assert.ok(f.counts.publicReads >= 4);
  for (const [name, path] of Object.entries(modulePaths))
    assert.equal(
      await sha(path),
      sourceSha256[name],
      `Source changed during the component: ${name}`,
    );
  const git = (dir: string, ...args: string[]) =>
    execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();
  process.stdout.write(
    JSON.stringify({
      passed: true,
      lane: "real-C-A-native-D-independent-oidc-provider-9.13.3-MCP",
      identitySourceCommit: git(identitySource, "rev-parse", "HEAD"),
      dSourceCommit: git(dSource, "rev-parse", "HEAD"),
      bSourceCommit: git(
        process.env.DSH_IDENTITY_USER_SERVICE_SOURCE!,
        "rev-parse",
        "HEAD",
      ),
      identitySourceDirty: Boolean(
        git(identitySource, "status", "--porcelain"),
      ),
      dSourceDirty: Boolean(git(dSource, "status", "--porcelain")),
      sourceSha256,
      asLibrary: "oidc-provider@9.13.3-unmodified",
      asTokenKind: "native-ClientCredentials",
      extraClaims: "official-kind-derived-grant_type-only",
      rsSubject: "authenticated-client_id-application-mapping",
      subjectTypeInjected: false,
      preconfiguredAgentClients: 0,
      identityPublishers: [
        "actual-C-A-B-registration-and-AWiki-software-publisher",
        "independent-self-hosted-CIMD",
      ],
      publicationAcceptance:
        "real-C-approval-native-A-B-registration-Registry-enrollment-prepare-bind-activate-readback",
      publisherProvenance: {
        publisher: fixture.provenance.publisher,
        registration: fixture.provenance.registration,
        publication: fixture.provenance.publication,
        machineOnly: fixture.provenance.machineOnly,
        metadataSha256: fixture.provenance.metadataSha256,
        jwksSha256: fixture.provenance.jwksSha256,
      },
      asState: "official-memory-adapter-isolated-component-only",
      dNativeExpiryRenewal: true,
      accessTokenTtlSeconds: f.tokenTtlSeconds,
      asScopeRejected: true,
      remoteRevocation: {
        latestTokenDestroyed: true,
        clientAggregateState: session.status().remoteRevocation,
        reason: "D-conservative-multiple-issuance-policy",
      },
      localDisconnectFence: true,
      forbiddenBrowserDcrCallbackRequests: f.counts.forbiddenFlowRequests,
      tools: ["identity_get", "catalog_list"],
      systemProductE2E: "not-run",
    }) + "\n",
  );
} finally {
  await client?.close().catch(() => {});
  await badSession?.dispose().catch(() => {});
  await session?.dispose().catch(() => {});
  await fixture?.dispose();
  await f.close();
  await rm(root, { recursive: true, force: true });
}
