/** Actual local C/A identity, DSH ANP/PAP clients, HTTPS AS/RS and PostgreSQL. */
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL, fileURLToPath } from "node:url";
import { resolve, join } from "node:path";
import { Pool } from "pg";
import { tlsFixture } from "../tests/helpers.js";
import { createServiceAgent } from "../packages/service-agent/index.js";
import {
  createWebsiteServices,
  type ProtocolDocument,
} from "../packages/service-agent/website.js";
import { AnpVerifier } from "../packages/anp/index.js";
import { PapSessionVerifier } from "../packages/pap/session.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { createAuthorizationServer } from "../packages/oauth-as/app.js";
import { PostgresStore } from "../packages/store-postgres/store.js";

export async function nativeWebsiteRoundTrip() {
  const workspace = fileURLToPath(new URL("../../../", import.meta.url));
  const load = (path: string) =>
    import(pathToFileURL(resolve(workspace, path)).href);
  const { createNativeProtocolFixture } = await load(
    "anp-identity/packages/dsh-anp-identity/test/helpers/native-protocol-fixture.ts",
  );
  const anpPlugin = await load("dsh-anp/src/plugin.ts");
  const { PapClient } = await load("dsh-pap/src/client.ts");
  const { ProtocolIdentityHost } = await load(
    "dsh-pap/src/protocol-adapter.ts",
  );
  const { SafeHttpsTransport } = await load("dsh-pap/src/network.ts");
  const tls = await tlsFixture();
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  let fixture: any, pap: any, signer: any, host: any;
  const originalFetch = globalThis.fetch;
  const master = randomBytes(32);
  try {
    const publisher = await tls.start((req, res) => {
      res.setHeader("content-type", "application/json");
      const material = fixture?.publicMaterials;
      if (!material) {
        res.writeHead(503);
        res.end();
        return;
      }
      if (req.url?.endsWith("client.json")) res.end(material.metadata);
      else if (req.url?.endsWith("jwks.json")) res.end(material.jwks);
      else
        fixture.publicDocument().then(
          (document: object) => res.end(JSON.stringify(document)),
          () => {
            res.writeHead(503);
            res.end();
          },
        );
    }, "identity.example");
    let app: ReturnType<typeof createServiceAgent>;
    const server = await tls.start((req, res) => app(req, res), "other.test");
    const origin = server.origin,
      scopes = ["protocol.read", "message.write"];
    fixture = await createNativeProtocolFixture({
      consumer: "@agentconnect/dsh-pap/plugin",
      additionalConsumers: [{ consumer: anpPlugin.name }],
      httpAllowedOrigins: { [anpPlugin.name]: [origin] },
      profiles: ["pap_session", "mcp_machine"],
      scopes,
      issuers: [origin],
      resources: [origin, origin + "/mcp"],
      publicationOrigin: publisher.origin,
      publicationCapabilities: {
        mcpMachine: true,
        papSession: true,
        papAccount: false,
      },
    });
    const store = new PostgresStore(pool, origin);
    await store.configureRequestLimits({
      globalMinute: 1000,
      originMinute: 1000,
      clientMinute: 1000,
      sourceMinute: 1000,
    });
    await store.configurePolicy({
      resource: origin + "/mcp",
      scopes,
      enabled: true,
      ttl: 60,
      maxNewClientsHour: 100,
      maxRequestsClientMinute: 100,
      maxRequestsMinute: 100,
      custodyCondition: "Actual task-isolated native local custody",
    });
    await store.provisionResourceServer("native-website", "n".repeat(48), [
      origin + "/mcp",
    ]);
    let catalog: ProtocolDocument[] = [
      {
        version: "1.1",
        language: "en",
        document: "white-paper",
        content: "# Native ANP 1.1",
        sourceUrl: origin + "/specs/1.1/white-paper",
      },
    ];
    if (process.env.SERVICE_AGENT_WEBSITE_CATALOG_FILE) {
      catalog = JSON.parse(
        await readFile(process.env.SERVICE_AGENT_WEBSITE_CATALOG_FILE, "utf8"),
      );
    }
    const expectedContent = catalog.find(
      (document) =>
        document.version === "1.1" &&
        document.language === "en" &&
        document.document === "white-paper",
    )?.content;
    assert.ok(expectedContent);
    const services = await createWebsiteServices(catalog, pool);
    app = createServiceAgent({
      origin,
      services,
      // The fixture DID has no port. Map its public resolution to the isolated TLS publisher.
      anp: new AnpVerifier(async (did) => {
        assert.equal(did, fixture.reference.did);
        const response = await tls.http(publisher.origin + "/native/did.json");
        assert.equal(response.status, 200);
        return JSON.parse(response.body);
      }),
      pap: new PapSessionVerifier(tls.fetcher(), origin),
      mcp: new TokenVerifier(tls.fetcher(), {
        issuer: origin,
        introspectionEndpoint: origin + "/oauth/introspect",
        resource: origin + "/mcp",
        rsId: "native-website",
        rsSecret: "n".repeat(48),
        allowedScopes: scopes,
      }),
      authorizationServer: createAuthorizationServer(
        store,
        new ClientAuthenticator(tls.fetcher(), origin),
        scopes,
      ),
    });
    const transport = async (request: Request): Promise<Response> => {
      const response = await tls.http(
        request.url,
        request.body ? await request.text() : undefined,
        Object.fromEntries(request.headers),
        request.method,
      );
      return new Response(response.body, {
        status: response.status,
        headers: {
          "content-type": String(
            response.headers["content-type"] ?? "application/json",
          ),
        },
      });
    };
    globalThis.fetch = (input: any, init?: RequestInit) =>
      transport(input instanceof Request ? input : new Request(input, init));
    const installed = fixture.getConsumer(anpPlugin.name).context;
    const tools = new Map<string, any>();
    installed.provide("tools", {
      register(tool: any) {
        tools.set(tool.name, tool);
      },
    });
    anpPlugin.apply(installed, {
      enabled: true,
      identityRef: fixture.reference,
      allowedOrigins: [origin],
    });
    assert.equal(tools.size, 4);
    const invoke = async (name: string, args: object) => {
      const result = await tools.get(name).execute(args, { agent: {} });
      assert.equal(result.ok, true, result.error);
      return result.value;
    };
    const directory = await invoke("anp_discover", {
      domain: new URL(origin).host,
    });
    assert.equal(directory.count, 1);
    const first = await tools
      .get("anp_describe")
      .execute({ agentRef: directory.agents[0].agentRef }, { agent: {} });
    assert.equal(first.error, "identity_authorization_required");
    const pending = (await fixture.management.listRequests()).find(
      (request: any) => request.caller.consumer === anpPlugin.name,
    );
    assert.ok(pending);
    const review = await fixture.management.getRequest(pending.id);
    await fixture.management.decide({
      requestId: pending.id,
      expectedVersion: pending.version,
      decision: "approve",
      identity: fixture.reference,
      mode: "permanent",
      reviewedSnapshot: review.snapshot,
    });
    const description = await invoke("anp_describe", {
      agentRef: directory.agents[0].agentRef,
    });
    await invoke("anp_read", {
      resourceRef: description.links.find(
        (link: any) => link.kind === "information",
      ).resourceRef,
    });
    const api = await invoke("anp_read", {
      resourceRef: description.links.find(
        (link: any) => link.kind === "interface",
      ).resourceRef,
    });
    const operation = (name: string) =>
      api.operations.find((operation: any) => operation.operationId === name)
        .operationRef;
    const document = await invoke("anp_call", {
      operationRef: operation("protocol_get"),
      path: { version: "1.1", document: "white-paper" },
    });
    assert.equal(document.content.content, expectedContent);
    const missingVersion = await tools
      .get("anp_call")
      .execute(
        {
          operationRef: operation("protocol_get"),
          path: { version: "9.9", document: "white-paper" },
        },
        { agent: {} },
      );
    assert.equal(missingVersion.ok, false);
    const receipt = await invoke("anp_call", {
      operationRef: operation("message_create"),
      body: { message: "native ANP" },
    });
    assert.ok(receipt.content.id);
    const grant = (await fixture.management.grants(fixture.reference)).find(
      (grant: any) => grant.caller.consumer === anpPlugin.name,
    );
    await fixture.management.revoke({
      grantId: grant.id,
      expectedVersion: grant.version,
    });
    const revoked = await tools.get("anp_call").execute(
      {
        operationRef: operation("message_create"),
        body: { message: "revoked ANP" },
      },
      { agent: {} },
    );
    assert.equal(revoked.ok, false);
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int AS count FROM website_messages WHERE content='revoked ANP'",
        )
      ).rows[0].count,
      0,
    );
    host = new ProtocolIdentityHost(fixture.client, fixture.policyRef);
    pap = new PapClient(
      {
        stateRoot: join(fixture.root, "pap-website"),
        binding: {
          identityRef: fixture.reference,
          ownerRef: "@agent-network-protocol/dsh-anp-identity",
          clientId: JSON.parse(fixture.publicMaterials.metadata).client_id,
        },
        identityHost: host,
        secretStore: {
          getEncryptionKey: async () => master,
          getOrCreateEncryptionKey: async () => master,
        },
      },
      new SafeHttpsTransport({
        ca: tls.cert,
        privateOrigins: [origin],
        lookup: async () => [{ address: "127.0.0.1", family: 4 }],
      }),
    );
    const company = await pap.resolvePapCompany(new URL(origin).host);
    assert.equal(company.authMode, "no_as");
    const subject = await pap.getOrCreatePapUser(company.companyRef);
    const session = await pap.openPapSession(subject.subjectRef);
    const papDocument = await pap.dispatchPap(session.sessionRef, {
      url: origin + "/pap/api/protocols/1.1/white-paper",
    });
    assert.equal(papDocument.status, 200);
    assert.equal(
      JSON.parse(Buffer.from(papDocument.body).toString()).content,
      expectedContent,
    );
    const papReceipt = await pap.dispatchPap(session.sessionRef, {
      url: origin + "/pap/api/messages",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: Buffer.from(JSON.stringify({ message: "native PAP" })),
    });
    assert.equal(papReceipt.status, 200);
    const discovery = await tls.http(
      origin + "/.well-known/oauth-authorization-server",
    );
    assert.equal(discovery.status, 200);
    signer = await fixture.client.registerValidatedTarget({
      identityRef: fixture.reference,
      policyRef: fixture.policyRef,
      requestedScopes: scopes,
      discovery: {
        profile: "mcp_machine",
        issuer: origin,
        resource: origin + "/mcp",
        tokenEndpoint: origin + "/oauth/token",
        metadataDigest: createHash("sha256")
          .update(discovery.body)
          .digest("hex"),
        expiresAt: Date.now() + 60000,
        sources: {
          resource: origin + "/.well-known/oauth-protected-resource/mcp",
          authorizationServer:
            origin + "/.well-known/oauth-authorization-server",
        },
      },
    });
    const assertion = await signer.signOAuthClientAssertion(signer.targetRef);
    const clientId = (await signer.getOAuthClientIdentity()).clientId;
    const token = await tls.http(
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
    assert.equal(token.status, 200, token.body);
    const call = (name: string, args: object) =>
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
          authorization: "Bearer " + JSON.parse(token.body).access_token,
        },
      );
    const mcpDoc = await call("protocol_get", {
      version: "1.1",
      document: "white-paper",
    });
    assert.equal(mcpDoc.status, 200);
    assert.equal(
      JSON.parse(JSON.parse(mcpDoc.body).result.content[0].text).content,
      expectedContent,
    );
    const mcpReceipt = await call("message_create", { message: "native MCP" });
    assert.equal(mcpReceipt.status, 200);
    const saved = await pool.query(
      "SELECT protocol FROM website_messages WHERE content IN ('native ANP', 'native PAP', 'native MCP') ORDER BY protocol",
    );
    assert.deepEqual(
      saved.rows.map((row) => row.protocol),
      ["anp", "mcp", "pap"],
    );
    process.stdout.write(
      "Native shared-identity ANP/MCP/PAP website round trip passed\n",
    );
  } finally {
    signer?.dispose();
    globalThis.fetch = originalFetch;
    host?.dispose();
    if (pap) await pap.close();
    if (fixture) await fixture.dispose();
    await tls.close();
    await pool.end();
    master.fill(0);
  }
}
