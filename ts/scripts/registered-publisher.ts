/** Real C/A/B publisher preflight, without loading any D source or making an AS token request. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { independentAsFixture } from "../tests/independent-as/fixture.js";
assert.equal(process.env.NODE_ENV, "test");
assert.ok(process.argv[2], "Pass the native identity source root");
const source = resolve(process.argv[2]!);
const helper = join(
  source,
  "packages/dsh-anp-identity/test/helpers/registered-protocol-fixture.ts",
);
const hash = (value: string | Buffer) =>
  createHash("sha256").update(value).digest("hex");
const initialHash = hash(await readFile(helper));
const { createRegisteredProtocolFixture } = await import(
  pathToFileURL(helper).href
);
const f = await independentAsFixture();
let identity:
  | Awaited<ReturnType<typeof createRegisteredProtocolFixture>>
  | undefined;
try {
  identity = await createRegisteredProtocolFixture({
    publicationOrigin: f.nativePublisher,
    consumer: "@deepseek-ai/dsh-mcp-client",
    profiles: ["mcp_machine"],
    scopes: ["agent.self.read", "catalog.read", "account.profile.read"],
    issuers: [f.issuer],
    resources: [f.resource],
  });
  const materials = identity.publicMaterials;
  f.setNativePublication(materials);
  const metadata = JSON.parse(materials.metadata);
  assert.equal(new URL(metadata.client_id).origin, f.nativePublisher);
  assert.deepEqual(metadata.grant_types, ["client_credentials"]);
  assert.deepEqual(metadata.response_types, []);
  assert.deepEqual(metadata.redirect_uris, []);
  assert.equal(
    await (await f.fetch(metadata.client_id)).text(),
    materials.metadata,
  );
  assert.equal(await (await f.fetch(metadata.jwks_uri)).text(), materials.jwks);
  const document = await identity.publicDocument();
  const services = (document.service ?? []).filter(
    (service: Record<string, unknown>) => service.type === "ANPCIMD",
  );
  assert.equal(services.length, 1);
  assert.equal(services[0].serviceEndpoint, metadata.client_id);
  assert.equal(services[0].anp_metadata_sha256, hash(materials.metadata));
  assert.equal(identity.provenance.publisher, "user-service");
  assert.equal(identity.provenance.registration, "production-command");
  assert.equal(
    identity.provenance.publication,
    "prepare-bind-activate-readback",
  );
  assert.equal(identity.provenance.machineOnly, true);
  assert.equal(f.counts.tokenRequests, 0);
  assert.equal(f.facts.length, 0);
  assert.equal(hash(await readFile(helper)), initialHash);
  process.stdout.write(
    JSON.stringify({
      passed: true,
      lane: "actual-C-approval-native-A-B-registered-publisher-raw-TLS-readback",
      registeredHelperSha256: initialHash,
      metadataSha256: hash(materials.metadata),
      jwksSha256: hash(materials.jwks),
      realRegistration: true,
      rawBytesUnchanged: true,
      nativeAnpCimdBinding: true,
      publicReads: f.counts.publicReads,
      tokenRequests: 0,
      dSourceLoaded: false,
      managementTransport: "local-ASGI-bridge-private-MySQL",
      publicationTransport: "actual-TLS-original-B-bytes",
      domain: "isolated-localhost-test-origin-not-awiki-info",
      keyring: "injected-isolated-native-test-root",
      systemProductE2E: "not-run",
    }) + "\n",
  );
} finally {
  await identity?.dispose();
  await f.close();
}
