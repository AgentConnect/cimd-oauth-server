import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  digest,
  form,
  httpsUrl,
  metadataPath,
  scopes,
  strictJson,
} from "../packages/oauth-core/parse.js";
import { SafeHttpFetcher } from "../packages/oauth-core/fetch.js";
import { authorizationServerMetadata } from "../packages/oauth-as/app.js";
process.env.NODE_ENV = "test";
test("closed JSON parser rejects duplicate nested names, escaped aliases, BOM and invalid UTF-8", () => {
  for (const raw of [
    '{"a":1,"a":2}',
    '{"a":{"x":1,"\\u0078":2}}',
    "\ufeff{}",
    "[1,]",
    '{"a":true,}',
    "[true false]",
  ])
    assert.throws(() => strictJson(raw));
  assert.throws(() => strictJson(Buffer.from([0xff])));
  assert.throws(() => strictJson(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])));
  assert.deepEqual(strictJson('{"a":[1,true,null,"x"]}'), {
    a: [1, true, null, "x"],
  });
});
test("token form rejects duplicates, unknown fields, malformed escapes and normalizes explicit scopes", () => {
  assert.throws(() => form("resource=a&resource=b", ["resource"]));
  assert.throws(() => form("client_secret=a", ["resource"]));
  assert.throws(() => form("resource=%Q1", ["resource"]));
  assert.deepEqual(scopes("catalog.read agent.self.read catalog.read"), [
    "agent.self.read",
    "catalog.read",
  ]);
  for (const s of ["", "a  b", " a", "a "]) assert.throws(() => scopes(s));
});
test("URL policy preserves identifiers while refusing ambiguous path forms", () => {
  for (const u of [
    "http://a/c",
    "https://user@a/c",
    "https://a/c#x",
    "https://a/a/../c",
    "https://a/%2e%2e/c",
    "https://a\\b/c",
  ])
    assert.throws(() => httpsUrl(u));
  assert.equal(
    metadataPath("https://as.test/tenant", "oauth-authorization-server"),
    "/.well-known/oauth-authorization-server/tenant",
  );
  assert.equal(
    metadataPath("https://rs.test/api/mcp", "oauth-protected-resource"),
    "/.well-known/oauth-protected-resource/api/mcp",
  );
  const m = authorizationServerMetadata("https://as.test/tenant", [
    "catalog.read",
  ]);
  assert.equal(m.token_endpoint, "https://as.test/tenant/oauth/token");
  assert.deepEqual(m.grant_types_supported, ["client_credentials"]);
  assert.equal(m.authorization_endpoint, undefined);
});
test("address policy denies every special-use family and mixed DNS candidates", () => {
  for (const ip of [
    "127.0.0.1",
    "10.1.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "192.168.1.1",
    "192.0.2.3",
    "198.51.100.1",
    "203.0.113.1",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "::ffff:8.8.8.8",
    "fe80::1",
    "fc00::1",
    "2001:db8::1",
    "2002::1",
    "3fff::1",
    "4000::1",
  ])
    assert.equal(SafeHttpFetcher.publicAddress(ip), false, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    assert.equal(SafeHttpFetcher.publicAddress(ip), true, ip);
  process.env.NODE_ENV = "production";
  assert.throws(
    () => new SafeHttpFetcher({ mode: "test", ca: "", addresses: {} }),
  );
  process.env.NODE_ENV = "test";
});
test("B shared publication fixture preserves raw CIMD digest, CC-only and PAP coexistence", async () => {
  const f = JSON.parse(
    await readFile(
      new URL(
        "../packages/testkit/fixtures/awiki-publication-v2.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(f.vectors.length, 5);
  for (const v of f.vectors) {
    assert.equal(digest(v.metadata), v.metadata_sha256);
    const m = strictJson(v.metadata) as Record<string, unknown>;
    assert.equal(m.token_endpoint_auth_method, "private_key_jwt");
    assert.equal(m.token_endpoint_auth_signing_alg, "ES256");
  }
});

test("B standard public-key fixture is accepted for MCP combinations without interpreting PAP grants", async () => {
  const { ClientAuthenticator } = await import(
    "../packages/oauth-core/client.js"
  );
  const { importJWK, SignJWT } = await import("jose");
  const f = JSON.parse(
    await readFile(
      new URL(
        "../packages/testkit/fixtures/awiki-publication-v2.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  for (const v of f.vectors) {
    const m = JSON.parse(v.metadata);
    const jwks = JSON.parse(v.jwks);
    const jwk = jwks.keys[0];
    // RFC P-256 generator point has scalar 1. This is a public synthetic test vector.
    const key = await importJWK(
      { ...jwk, d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" },
      "ES256",
    );
    class FixtureFetcher extends SafeHttpFetcher {
      override async request(url: string) {
        if (url === m.client_id) return Buffer.from(v.metadata);
        if (url === m.jwks_uri) return Buffer.from(v.jwks);
        throw new Error("Unexpected fixture URL");
      }
    }
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({
      iss: m.client_id,
      sub: m.client_id,
      aud: "https://auth.example.test",
      iat: now,
      exp: now + 60,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: "ES256", kid: jwk.kid })
      .sign(key);
    const result = new ClientAuthenticator(
      new FixtureFetcher(),
      "https://auth.example.test",
    ).authenticate(m.client_id, assertion);
    if (v.request.capabilities.mcp_machine)
      assert.equal((await result).metadataDigest, v.metadata_sha256);
    else await assert.rejects(result, /invalid_client/);
  }
});
