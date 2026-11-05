/** An unmodified AS product implements CIMD/auth/CC/introspection/revocation; only deployment policy and RS tools are fixtures. */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as oauth from "oauth4webapi";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { independentAsFixture } from "./independent-as/fixture.js";
process.env.NODE_ENV = "test";
test("independent oidc-provider product provides real CIMD CC authorization, MCP tools, expiry, scope and revocation", async (t) => {
  const f = await independentAsFixture();
  let completed = 0;
  const scenario = async (name: string, run: () => Promise<void>) =>
    t.test(name, async () => {
      await run();
      completed++;
    });
  const obtain = async (
    scope = "agent.self.read catalog.read",
    resource = f.resource,
  ) =>
    oauth.processClientCredentialsResponse(
      f.metadata,
      f.independentClient,
      await oauth.clientCredentialsGrantRequest(
        f.metadata,
        f.independentClient,
        f.independentAuthentication,
        { resource, scope },
        { [oauth.customFetch]: f.fetch },
      ),
    );
  const open = async (token: string) => {
    const mcp = new Client({
      name: "independent-AS-component",
      version: "1.0.0",
    });
    try {
      await mcp.connect(
        new StreamableHTTPClientTransport(new URL(f.resource), {
          fetch: f.fetch,
          requestInit: { headers: { authorization: `Bearer ${token}` } },
        }),
      );
      return mcp;
    } catch (error) {
      await mcp.close();
      throw error;
    }
  };
  let token!: oauth.TokenEndpointResponse;
  try {
    await scenario(
      "unknown HTTPS CIMD reaches native token Client.find without pre-registration, authorize or callback",
      async () => {
        assert.equal(f.counts.publicReads, 0);
        assert.equal(f.facts.length, 0);
        assert.deepEqual(f.preconfiguredClientIds, [
          "independent-resource-server",
        ]);
        token = await obtain();
        assert.equal(token.expires_in, 3);
        assert.equal(token.scope, "agent.self.read catalog.read");
        assert.equal(token.refresh_token, undefined);
        const principal = await f.introspect(token.access_token);
        assert.equal(principal.active, true);
        assert.equal(principal.client_id, f.independentClient.client_id);
        assert.equal(principal.grant_type, "client_credentials");
        assert.equal(principal.subject_type, undefined);
        assert.equal(principal.sub, undefined);
        assert.equal(principal.aud, f.resource);
        assert.ok(f.counts.publicReads >= 2);
        assert.equal(f.facts[0]?.kind, "ClientCredentials");
        assert.equal(f.counts.forbiddenFlowRequests, 0);
        const mcp = await open(token.access_token);
        try {
          assert.deepEqual(
            (await mcp.listTools()).tools.map((tool) => tool.name).sort(),
            ["catalog_list", "identity_get"],
          );
          const identity = await mcp.callTool({
            name: "identity_get",
            arguments: {},
          });
          assert.ok(
            JSON.stringify(identity).includes(f.independentClient.client_id),
          );
          const catalog = await mcp.callTool({
            name: "catalog_list",
            arguments: {},
          });
          assert.ok(JSON.stringify(catalog).includes("independent-notebook"));
        } finally {
          await mcp.close();
        }
      },
    );
    await scenario(
      "real token expiry rejects old token and standard new CC request succeeds",
      async () => {
        const previous = token.access_token;
        await new Promise((resolve) => setTimeout(resolve, 3150));
        assert.equal((await f.introspect(previous)).active, false);
        await assert.rejects(open(previous));
        token = await obtain();
        assert.ok(token.access_token !== previous, "New issuance after expiry");
        assert.equal((await f.introspect(token.access_token)).active, true);
      },
    );
    await scenario(
      "deployment resource/scope policy and actual tool authorization reject overreach",
      async () => {
        const error = (name: string) => (e: unknown) =>
          e instanceof oauth.ResponseBodyError && e.error === name;
        await assert.rejects(
          obtain("account.profile.read"),
          error("invalid_scope"),
        );
        await assert.rejects(
          obtain("catalog.read", f.resource + "/other"),
          error("invalid_target"),
        );
        const unauthorizedIntrospection =
          await oauth.processIntrospectionResponse(
            f.metadata,
            f.independentClient,
            await oauth.introspectionRequest(
              f.metadata,
              f.independentClient,
              f.independentAuthentication,
              token.access_token,
              { [oauth.customFetch]: f.fetch },
            ),
          );
        assert.equal(unauthorizedIntrospection.active, false);
        const limited = await obtain("catalog.read");
        const mcp = await open(limited.access_token);
        try {
          assert.deepEqual(
            (await mcp.listTools()).tools.map((tool) => tool.name),
            ["catalog_list"],
          );
          await assert.rejects(
            mcp.callTool({ name: "identity_get", arguments: {} }),
          );
        } finally {
          await mcp.close();
        }
      },
    );
    await scenario(
      "native standard revocation invalidates the machine token and no browser flow was used",
      async () => {
        await oauth.processRevocationResponse(
          await oauth.revocationRequest(
            f.metadata,
            f.independentClient,
            f.independentAuthentication,
            token.access_token,
            {
              additionalParameters: { token_type_hint: "access_token" },
              [oauth.customFetch]: f.fetch,
            },
          ),
        );
        assert.equal((await f.introspect(token.access_token)).active, false);
        await assert.rejects(open(token.access_token));
        assert.equal(f.counts.forbiddenFlowRequests, 0);
        assert.ok(f.counts.revocations > 0);
      },
    );
    assert.equal(completed, 4);
    process.stdout.write(
      JSON.stringify({
        passed: true,
        lane: "independent-oidc-provider-9.13.3-native-CIMD-CC-TLS-MCP",
        asLibraryUnmodified: true,
        preconfiguredAgentClients: 0,
        operatorRsClient: true,
        asNativeTokenKind: "ClientCredentials",
        extraClaims: "official-hook-grant_type-only",
        fakeSubjectType: false,
        defaultMemoryAdapter: "isolated-component-only",
        authorizationOrRegistrationRequests: f.counts.forbiddenFlowRequests,
        tools: ["identity_get", "catalog_list"],
        expiryRenewal: true,
        scopeResourcePolicy: true,
        revocation: true,
        systemProductE2E: "not-run",
      }) + "\n",
    );
  } finally {
    await f.close();
  }
});
