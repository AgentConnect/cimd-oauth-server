/** Actual DSH PAP engine + local native identity + HTTPS demo; no model or account OAuth. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { decodeJwt } from "jose";
import { tlsFixture } from "../tests/helpers.js";
import { PapSessionVerifier } from "../packages/pap/session.js";
import { createPapApp } from "../examples/minimal-pap-server/app.js";

assert.equal(process.env.NODE_ENV, "test");
const identityRoot = resolve(
  process.env.PAP_DEMO_IDENTITY_SOURCE ??
    fileURLToPath(new URL("../../../anp-identity", import.meta.url)),
);
const papRoot = resolve(
  process.env.PAP_DEMO_PAP_SOURCE ??
    fileURLToPath(new URL("../../../dsh-pap", import.meta.url)),
);
const load = (path: string) => import(pathToFileURL(path).href);
const { createNativeProtocolFixture } = await load(
  join(
    identityRoot,
    "packages/dsh-anp-identity/test/helpers/native-protocol-fixture.ts",
  ),
);
const { PapClient } = await load(join(papRoot, "src/client.ts"));
const { ProtocolIdentityHost } = await load(
  join(papRoot, "src/protocol-adapter.ts"),
);
const { SafeHttpsTransport } = await load(join(papRoot, "src/network.ts"));
const tls = await tlsFixture();
const root = await mkdtemp(join(tmpdir(), "pap-hello-demo-"));
let fixture: any, client: any, host: any;
const master = randomBytes(32);
try {
  let materials: { metadata: string; jwks: string } | undefined;
  const publisher = await tls.start((req, res) => {
    res.setHeader("content-type", "application/json");
    if (
      !materials ||
      !["client.json", "jwks.json"].some((part) => req.url?.endsWith(part))
    ) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.end(
      req.url?.endsWith("client.json") ? materials.metadata : materials.jwks,
    );
  }, "identity.example");
  const company = "https://other.test";
  const verifier = new PapSessionVerifier(tls.fetcher(), company);
  const app = createPapApp(verifier);
  const observations: Array<{ sid: unknown; jti: unknown; account: boolean }> =
    [];
  const server = await tls.start((req, res) => {
    if (req.url?.startsWith("/api/hello")) {
      const proof = req.headers["poppy-session"];
      if (typeof proof === "string") {
        const claims = decodeJwt(proof);
        observations.push({
          sid: claims.sid,
          jti: claims.jti,
          account: req.headers.authorization !== undefined,
        });
      }
    }
    app(req, res);
  }, "other.test");
  fixture = await createNativeProtocolFixture({
    consumer: "@agentconnect/dsh-pap/plugin",
    profiles: ["pap_session"],
    scopes: ["pap.read"],
    issuers: [company],
    resources: [company],
    publicationOrigin: publisher.origin,
    publicationCapabilities: {
      mcpMachine: true,
      papSession: true,
      papAccount: false,
    },
  });
  materials = fixture.publicMaterials;
  const metadata = JSON.parse(materials!.metadata);
  host = new ProtocolIdentityHost(fixture.client, fixture.policyRef);
  const transport = new SafeHttpsTransport({
    ca: tls.cert,
    privateOrigins: [company],
    portOverrides: { [company]: Number(new URL(server.origin).port) },
    lookup: async () => [{ address: "127.0.0.1", family: 4 }],
  });
  client = new PapClient(
    {
      stateRoot: join(root, "pap-state"),
      binding: {
        identityRef: fixture.reference,
        ownerRef: "@agent-network-protocol/dsh-anp-identity",
        clientId: metadata.client_id,
      },
      secretStore: {
        getEncryptionKey: async () => master,
        getOrCreateEncryptionKey: async () => master,
      },
      identityHost: host,
    },
    transport,
  );
  const discovered = await client.resolvePapCompany("other.test");
  assert.equal(discovered.authMode, "no_as");
  const subject = await client.getOrCreatePapUser(discovered.companyRef);
  const session = await client.openPapSession(subject.subjectRef);
  for (let i = 0; i < 2; i++) {
    const response = await client.dispatchPap(session.sessionRef, {
      url: company + "/api/hello",
    });
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(Buffer.from(response.body).toString()), {
      message: "Hello from PAP demo",
      authenticated: true,
    });
  }
  assert.equal(verifier.sessionCount, 1);
  assert.equal(observations.length, 2);
  assert.equal(observations[0]!.sid, observations[1]!.sid);
  assert.notEqual(observations[0]!.jti, observations[1]!.jti);
  assert(observations.every((request) => !request.account));
  const missing = await tls.http(server.origin + "/api/hello", undefined, {
    host: "other.test",
  });
  assert.equal(missing.status, 400);
  for (const path of [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
  ]) {
    assert.equal((await tls.http(server.origin + path)).status, 404);
  }
  console.log(
    JSON.stringify({
      passed: true,
      requests: 2,
      sessions: 1,
      freshRequestProofs: true,
      humanInteraction: false,
      accountOAuth: false,
      nativeSigning: true,
      discovery: "PAP 0.3 NoAS",
      publication: "local fixture; no User Service registration acceptance",
    }),
  );
} finally {
  client?.close();
  host?.dispose();
  await fixture?.dispose();
  await tls.close();
  master.fill(0);
  await rm(root, { recursive: true, force: true });
}
