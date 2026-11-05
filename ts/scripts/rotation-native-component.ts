/** Source-only module evidence: actual C/A/B publication rotation and real native-provider removal. */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import type { RequestListener } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Pool } from "pg";
import { importJWK, jwtVerify } from "jose";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { tlsFixture } from "../tests/helpers.js";

assert.equal(process.env.NODE_ENV, "test");
assert.ok(process.env.DATABASE_URL, "Use the isolated rotation-native runner");
assert.ok(
  process.argv[2] && process.argv[3],
  "Pass identity and Harness source roots",
);
const identitySource = resolve(process.argv[2]!);
const harnessSource = resolve(process.argv[3]!);
const publisherSource = resolve(
  process.env.DSH_IDENTITY_USER_SERVICE_SOURCE ?? "",
);
assert.ok(
  process.env.DSH_IDENTITY_USER_SERVICE_SOURCE &&
    process.env.DSH_IDENTITY_PYTHON,
);
const fixtureModule = join(
  identitySource,
  "packages/dsh-anp-identity/test/helpers/registered-protocol-fixture.ts",
);
const machineRoot = join(harnessSource, "packages/mcp/mcp-client/src");
const nativePath = join(
  identitySource,
  "bindings/node/anp-identity.linux-x64-gnu.node",
);
const sha = (value: string | Buffer) =>
  createHash("sha256").update(value).digest("hex");
const hash = async (path: string) => sha(await readFile(path));
const sourceFiles: Record<string, string> = {
  component: resolve(process.argv[1]!),
  cRegisteredFixture: fixtureModule,
  cHost: join(identitySource, "packages/dsh-anp-identity/src/index.ts"),
  cAuthority: join(
    identitySource,
    "packages/dsh-anp-identity/src/target-policy.ts",
  ),
  cPublication: join(
    identitySource,
    "packages/dsh-anp-identity/src/publication.ts",
  ),
  cManagement: join(
    identitySource,
    "packages/dsh-anp-identity/src/management-driver.ts",
  ),
  native: nativePath,
  dMachine: join(machineRoot, "machine-auth.ts"),
  dNetwork: join(machineRoot, "machine-http.ts"),
  dStore: join(machineRoot, "machine-store.ts"),
  dDiscovery: join(machineRoot, "machine-discovery.ts"),
  sourceFace: join(harnessSource, "tsconfig.base.json"),
  eAuthenticator: resolve("packages/oauth-core/client.ts"),
  eStore: resolve("packages/store-postgres/store.ts"),
  eAs: resolve("packages/oauth-as/app.ts"),
  eRs: resolve("packages/oauth-rs/index.ts"),
  bBridge: join(publisherSource, "tests/app/cimd/management_bridge.py"),
};
const sourceSha256 = Object.fromEntries(
  await Promise.all(
    Object.entries(sourceFiles).map(async ([name, path]) => [
      name,
      await hash(path),
    ]),
  ),
);
assert.equal(
  sourceSha256.native,
  "e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef",
);
const { createRegisteredProtocolFixture } = await import(
  pathToFileURL(fixtureModule).href
);
const { MachineAuthenticationSession } = await import(
  pathToFileURL(sourceFiles.dMachine!).href
);
const { createTestMachineFetch } = await import(
  pathToFileURL(sourceFiles.dNetwork!).href
);
const { discoverMachineTarget } = await import(
  pathToFileURL(sourceFiles.dDiscovery!).href
);
const tls = await tlsFixture();
const root = await mkdtemp(join(tmpdir(), "cimd-rotation-native-"));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 8 });
let fixture:
  | Awaited<ReturnType<typeof createRegisteredProtocolFixture>>
  | undefined;
let session: InstanceType<typeof MachineAuthenticationSession> | undefined;
let unavailableSession:
  | InstanceType<typeof MachineAuthenticationSession>
  | undefined;
let client: Client | undefined;
let releaseOldLease: (() => void) | undefined;
let tokenPosts = 0,
  resourceRequests = 0,
  publicReads = 0,
  interactiveRequests = 0;
const tokenAttempts: Array<{ kid: string; tokenDigest: string }> = [];
// Opaque tokens remain only in this process for an independent RS check. Never print them.
const bearerByKid = new Map<string, string>();
const tokenRejections: Array<{ status: number; code: string }> = [];
const authenticationFailures: Array<{
  name: string;
  code: string;
  locations: string[];
}> = [];
let nativeAssertionChecks = 0;
let stage = "setup";
const toolResult = (value: unknown): Record<string, unknown> => {
  const text = (
    value as { content?: Array<{ type: string; text?: string }> }
  ).content?.find((item) => item.type === "text")?.text;
  assert.ok(text);
  return JSON.parse(text) as Record<string, unknown>;
};
const rejectedCode = async (
  operation: Promise<unknown>,
  expected: string[],
) => {
  let code: string | undefined;
  try {
    await operation;
  } catch (error) {
    const candidate = error as { code?: unknown; message?: unknown };
    const value =
      typeof candidate.code === "string" ? candidate.code : candidate.message;
    if (typeof value === "string" && /^[A-Za-z0-9_:-]{1,128}$/u.test(value))
      code = value;
  }
  assert.ok(
    code && expected.includes(code),
    "Expected a sanitized authorization failure",
  );
  return code;
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
    if (/\/(?:authorize|register|callback)(?:[/?]|$)/u.test(req.url ?? ""))
      interactiveRequests++;
    asHandler(req, res);
  }, "localhost");
  let rsHandler: RequestListener = (_req, res) => {
    res.statusCode = 503;
    res.end();
  };
  const rs = await tls.start((req, res) => {
    if (req.url === "/mcp") resourceRequests++;
    rsHandler(req, res);
  }, "localhost");
  const resource = rs.origin + "/mcp";
  const scopes = ["agent.self.read", "catalog.read"];
  const store = new PostgresStore(pool, as.origin);
  await store.configureRequestLimits({
    globalMinute: 120,
    originMinute: 40,
    clientMinute: 20,
    sourceMinute: 60,
  });
  // Set policy once. Publication rotation must not change AS policy/grant generations.
  await store.configurePolicy({
    resource,
    scopes,
    ttl: 300,
    maxNewClientsHour: 10,
    maxRequestsClientMinute: 10,
    maxRequestsMinute: 60,
    custodyCondition:
      "Actual B publication and C/A local native custody rotation component",
    enabled: true,
  });
  const rsId = "rotation-native-rs",
    rsSecret = randomBytes(32).toString("base64url");
  await store.provisionResourceServer(rsId, rsSecret, [resource]);
  class ObservedAuthenticator extends ClientAuthenticator {
    override async authenticate(clientId: string, assertion: string) {
      try {
        return await super.authenticate(clientId, assertion);
      } catch (error) {
        const value = error as {
          name?: unknown;
          code?: unknown;
          stack?: unknown;
        };
        const safe = (field: unknown) =>
          typeof field === "string" && /^[A-Za-z0-9_:-]{1,64}$/u.test(field)
            ? field
            : "unclassified";
        authenticationFailures.push({
          name: safe(value.name),
          code: safe(value.code),
          locations:
            typeof value.stack === "string"
              ? (value.stack.match(
                  /oauth-core\/(?:client|fetch)\.ts:\d+:\d+/gu,
                ) ?? [])
              : [],
        });
        throw error;
      }
    }
  }
  asHandler = createAuthorizationServer(
    store,
    new ObservedAuthenticator(tls.fetcher(), as.origin),
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
  stage = "real-registration-publication";
  fixture = await createRegisteredProtocolFixture({
    publicationOrigin: identity.origin,
    issuers: [as.origin],
    resources: [resource],
    scopes,
  });
  assert.equal(fixture.provenance.registration, "production-command");
  const initialMaterials = fixture.publicMaterials;
  const initialMetadata = JSON.parse(initialMaterials.metadata);
  const initialJwks = JSON.parse(initialMaterials.jwks);
  const clientId = initialMetadata.client_id;
  const initialKid = initialJwks.keys[0].kid;
  assert.deepEqual(initialMetadata.redirect_uris, []);
  const initialDocument = await fixture.publicDocument();
  assert.ok(initialDocument);
  const master = randomBytes(32).toString("base64url");
  fixture.context.provide("credentials", {
    resolve: async (reference: string) => {
      assert.equal(reference, "ROTATION_COMPONENT_KEY");
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
    const transport = transports.get(new URL(request.url).origin);
    assert.ok(transport, "No implicit transport fallback");
    let kid: string | undefined;
    if (request.url === as.origin + "/oauth/token") {
      const form = new URLSearchParams(await request.clone().text());
      assert.equal(form.get("grant_type"), "client_credentials");
      assert.equal(form.get("client_id"), clientId);
      const assertion = form.get("client_assertion");
      assert.ok(assertion);
      const parts = assertion.split(".");
      assert.equal(parts.length, 3);
      const header = JSON.parse(
        Buffer.from(parts[0]!, "base64url").toString("utf8"),
      );
      const claims = JSON.parse(
        Buffer.from(parts[1]!, "base64url").toString("utf8"),
      );
      assert.equal(header.alg, "ES256");
      assert.equal(claims.iss, clientId);
      assert.equal(claims.sub, clientId);
      assert.equal(claims.aud, as.origin);
      assert.equal(typeof header.kid, "string");
      kid = header.kid;
      const publicKey = JSON.parse(fixture!.publicMaterials.jwks).keys.find(
        (key: { kid: string }) => key.kid === kid,
      );
      assert.ok(
        publicKey,
        "Native assertion must select the currently published kid",
      );
      const verified = await jwtVerify(
        assertion,
        await importJWK(publicKey, "ES256"),
        {
          algorithms: ["ES256"],
          issuer: clientId,
          subject: clientId,
          audience: as.origin,
        },
      );
      assert.equal(verified.protectedHeader.kid, kid);
      nativeAssertionChecks++;
    }
    const response = await transport(request);
    if (kid && response.status !== 200) {
      const failure = (await response
        .clone()
        .json()
        .catch(() => ({}))) as { error?: unknown };
      const code =
        typeof failure.error === "string" &&
        /^[a-z_]{1,64}$/u.test(failure.error)
          ? failure.error
          : "unclassified";
      tokenRejections.push({ status: response.status, code });
    }
    if (kid && response.status === 200) {
      const value = (await response.clone().json()) as {
        access_token?: unknown;
      };
      assert.equal(typeof value.access_token, "string");
      const bearer = value.access_token as string;
      bearerByKid.set(kid, bearer);
      tokenAttempts.push({ kid, tokenDigest: sha(bearer) });
    }
    return response;
  };
  const discovery = await discoverMachineTarget(resource, as.origin, send);
  // Retain a separately acquired genuine C lease as well as D's own frozen binding.
  const originalLease = await fixture.client.registerValidatedTarget({
    identityRef: fixture.reference,
    policyRef: fixture.policyRef,
    discovery,
    requestedScopes: scopes,
  });
  releaseOldLease = () => originalLease.dispose();
  const initialIdentity = await originalLease.getOAuthClientIdentity();
  assert.equal(initialIdentity.keyId, initialKid);
  const config = {
    mode: "cimd-client-credentials",
    connectionId: "rotation-native-stable",
    identityRef: fixture.reference,
    policyRef: fixture.policyRef,
    requestedScopes: scopes,
    stateRoot: join(root, "credentials"),
    encryptionKeyRef: "ROTATION_COMPONENT_KEY",
    issuer: as.origin,
  };
  const connect = async () => {
    session = new MachineAuthenticationSession(
      fixture!.context,
      config,
      resource,
      send,
    );
    client = new Client({
      name: "rotation-native-component",
      version: "1.0.0",
    });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(resource), {
        fetch: session.fetch,
      }),
    );
    assert.deepEqual(
      (await client.listTools()).tools.map((tool) => tool.name).sort(),
      ["catalog_list", "identity_get"],
    );
    const identityResult = toolResult(
      await client.callTool({ name: "identity_get", arguments: {} }),
    );
    const catalog = toolResult(
      await client.callTool({ name: "catalog_list", arguments: {} }),
    );
    assert.equal(identityResult.client_id, clientId);
    assert.equal(identityResult.resource, resource);
    assert.equal((catalog.items as unknown[]).length, 2);
    return identityResult;
  };
  stage = "initial-machine-connection";
  const first = await connect();
  assert.equal(tokenPosts, 1);
  assert.deepEqual(
    tokenAttempts.map((value) => value.kid),
    [initialKid],
  );
  const files = (await readdir(config.stateRoot)).filter((name) =>
    name.endsWith(".json"),
  );
  assert.equal(files.length, 1);
  const statePath = join(config.stateRoot, files[0]!);
  const beforeStateBytes = await readFile(statePath, "utf8");
  const beforeState = JSON.parse(beforeStateBytes);
  assert.ok(beforeState.ciphertext && beforeState.iv && beforeState.tag);
  assert.equal(beforeState.token, undefined);
  stage = "actual-publication-rotation";
  const rotation = await fixture.rotateOAuthKey();
  assert.equal(rotation.previous.version, initialIdentity.version);
  assert.equal(rotation.previous.keyId, initialKid);
  assert.equal(
    rotation.previous.metadataSha256,
    sha(initialMaterials.metadata),
  );
  assert.equal(rotation.previous.jwksSha256, sha(initialMaterials.jwks));
  assert.ok(rotation.version > rotation.previous.version);
  assert.notEqual(rotation.keyId, initialKid);
  const rotatedMaterials = fixture.publicMaterials;
  assert.equal(JSON.parse(rotatedMaterials.metadata).client_id, clientId);
  assert.equal(sha(rotatedMaterials.metadata), rotation.metadataSha256);
  assert.equal(sha(rotatedMaterials.jwks), rotation.jwksSha256);
  assert.equal(
    JSON.parse(rotatedMaterials.jwks).keys.some(
      (key: { kid: string }) => key.kid === rotation.keyId,
    ),
    true,
  );
  assert.equal(
    JSON.parse(rotatedMaterials.jwks).keys.some(
      (key: { kid: string }) => key.kid === initialKid,
    ),
    false,
  );
  await fixture.publicDocument();
  const countersAfterRotation = { tokenPosts, resourceRequests };
  const oldLeaseCode = await rejectedCode(originalLease.assertActive(), [
    "capability_forbidden",
  ]);
  const oldSessionCode = await rejectedCode(
    session!.fetch(resource, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 900, method: "tools/list" }),
    }),
    ["capability_forbidden"],
  );
  assert.deepEqual({ tokenPosts, resourceRequests }, countersAfterRotation);
  assert.equal(
    await readFile(statePath, "utf8"),
    beforeStateBytes,
    "Rejected old binding must not replace its token partition",
  );
  const oldBearer = bearerByKid.get(initialKid);
  assert.ok(oldBearer);
  // Use the real RS, outside D, to establish that publishing keys does not revoke a bearer.
  const oldTokenProbe = await tls.http(resource, undefined, {
    authorization: "Bearer " + oldBearer,
  });
  assert.equal(
    oldTokenProbe.status,
    405,
    "Authenticated GET is unsupported, rather than an invalid bearer",
  );
  const oldTokenState = await store.introspect(rsId, rsSecret, oldBearer);
  assert.equal(oldTokenState.active, true);
  assert.equal(oldTokenState.sub, first.subject);
  await client!.close();
  client = undefined;
  await session!.dispose(false);
  session = undefined;
  const newPermit = await fixture.client.registerValidatedTarget({
    identityRef: fixture.reference,
    policyRef: fixture.policyRef,
    discovery,
    requestedScopes: scopes,
  });
  try {
    const identity = await newPermit.getOAuthClientIdentity();
    assert.equal(identity.clientId, clientId);
    assert.equal(identity.version, rotation.version);
    assert.equal(identity.keyId, rotation.keyId);
  } finally {
    newPermit.dispose();
  }
  stage = "rotated-machine-connection";
  const second = await connect();
  assert.equal(second.subject, first.subject);
  assert.equal(tokenPosts, 2);
  assert.deepEqual(
    tokenAttempts.map((value) => value.kid),
    [initialKid, rotation.keyId],
  );
  assert.notEqual(tokenAttempts[0]!.tokenDigest, tokenAttempts[1]!.tokenDigest);
  const afterState = JSON.parse(await readFile(statePath, "utf8"));
  assert.ok(afterState.generation > beforeState.generation);
  assert.notEqual(afterState.partition, beforeState.partition);
  assert.ok(afterState.ciphertext);
  const machines = await pool.query(
    "SELECT subject FROM clients WHERE namespace=$1 AND client_id=$2",
    [store.namespace, clientId],
  );
  assert.equal(machines.rowCount, 1);
  assert.equal(machines.rows[0].subject, first.subject);
  assert.equal(
    (await store.introspect(rsId, rsSecret, oldBearer)).active,
    true,
  );
  assert.ok(
    publicReads >= 4,
    "AS must retrieve public material for the new kid",
  );
  await client!.close();
  client = undefined;
  await session!.dispose(false);
  session = undefined;

  // This is real C unregister/native-lease disposal, not a simulated OS keyring lock.
  stage = "real-provider-unregistration";
  const closure = await fixture.closeRegisteredProvider();
  assert.deepEqual(closure, {
    closed: "c-native-provider-registration",
    storeLocked: false,
  });
  const beforeUnavailable = {
    tokenPosts,
    resourceRequests,
    interactiveRequests,
  };
  unavailableSession = new MachineAuthenticationSession(
    fixture.context,
    {
      ...config,
      connectionId: "rotation-native-provider-closed",
      stateRoot: join(root, "closed-provider"),
    },
    resource,
    send,
  );
  const providerCode = await rejectedCode(
    unavailableSession.fetch(resource, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 901, method: "tools/list" }),
    }),
    ["provider_unavailable"],
  );
  assert.deepEqual(
    { tokenPosts, resourceRequests, interactiveRequests },
    beforeUnavailable,
  );
  await unavailableSession.dispose(false);
  unavailableSession = undefined;
  assert.equal(interactiveRequests, 0);
  for (const [name, path] of Object.entries(sourceFiles))
    assert.equal(
      await hash(path),
      sourceSha256[name],
      "Source changed during module component: " + name,
    );
  const git = (source: string, args: string[]) =>
    execFileSync("git", ["-C", source, ...args], { encoding: "utf8" }).trim();
  process.stdout.write(
    JSON.stringify({
      passed: true,
      lane: "S09-M12-real-C-A-B-D-E-PG-TLS-MCP",
      identitySourceCommit: git(identitySource, ["rev-parse", "HEAD"]),
      harnessSourceCommit: git(harnessSource, ["rev-parse", "HEAD"]),
      publisherSourceCommit: git(publisherSource, ["rev-parse", "HEAD"]),
      identitySourceDirty: Boolean(
        git(identitySource, ["status", "--porcelain"]),
      ),
      harnessSourceDirty: Boolean(
        git(harnessSource, ["status", "--porcelain"]),
      ),
      publisherSourceDirty: Boolean(
        git(publisherSource, ["status", "--porcelain"]),
      ),
      sourceSha256,
      publication:
        "actual-B-registration-enrollment-prepare-bind-activate-raw-readback",
      tools: ["identity_get", "catalog_list"],
      oldLeaseCode,
      oldSessionCode,
      oldBindingPhysicalRequests: 0,
      oldPartitionUnchangedOnRejection: true,
      sameClientId: true,
      sameAsSubject: true,
      rotation: {
        previousVersion: rotation.previous.version,
        version: rotation.version,
        metadataSha256: rotation.metadataSha256,
        jwksSha256: rotation.jwksSha256,
      },
      tokenRequests: tokenPosts,
      nativeAssertionChecks,
      distinctTokenPartitions: true,
      previousBearerStillActiveAfterPublication: true,
      providerUnavailable: {
        control: closure.closed,
        storeLocked: false,
        code: providerCode,
        tokenRequests: 0,
        resourceRequests: 0,
        interactiveOAuthRequests: 0,
      },
      osKeyringLock: "not-tested-no-native-lock-interface",
      systemProductE2E: "not-run",
    }) + "\n",
  );
} catch (error) {
  process.stderr.write(
    JSON.stringify({
      passed: false,
      stage,
      tokenPosts,
      resourceRequests,
      tokenRejections,
      authenticationFailures,
      nativeAssertionChecks,
      publishedKeyShapes: fixture
        ? JSON.parse(fixture.publicMaterials.jwks).keys.map(
            (key: Record<string, unknown>) => ({
              kidLength: typeof key.kid === "string" ? key.kid.length : 0,
              kty: key.kty,
              crv: key.crv,
              alg: key.alg,
              use: key.use,
              key_ops: key.key_ops,
            }),
          )
        : [],
      sourceSha256,
    }) + "\n",
  );
  throw error;
} finally {
  await client?.close().catch(() => {});
  await unavailableSession?.dispose(false).catch(() => {});
  await session?.dispose(false).catch(() => {});
  releaseOldLease?.();
  bearerByKid.clear();
  await fixture?.dispose();
  await tls.close();
  await pool.end();
  await rm(root, { recursive: true, force: true });
}
