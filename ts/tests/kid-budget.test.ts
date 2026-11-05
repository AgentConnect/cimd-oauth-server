/** Shared A/B/C permits complete DID key IDs up to 1024 characters; verify the real JOSE/TLS boundary. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT, jwtVerify } from "jose";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { tlsFixture } from "./helpers.js";
process.env.NODE_ENV = "test";
test("full DID key identifiers accept 132 and 1024 while blank, control and oversized JWT/JWKS kids fail", async () => {
  const tls = await tlsFixture();
  const pair = await generateKeyPair("ES256");
  const pub = {
    ...(await exportJWK(pair.publicKey)),
    alg: "ES256",
    use: "sig",
  };
  let keys: Array<Record<string, unknown>> = [],
    origin = "";
  let metadataGets = 0;
  const issuer = "https://issuer.example";
  const prefix = "did:wba:identity.example:awiki:user:";
  const suffix = "#oauth-rotation-132";
  const long132 =
    prefix + "a".repeat(132 - prefix.length - suffix.length) + suffix;
  const max1024 = prefix + "b".repeat(1024 - prefix.length - 6) + "#oauth";
  assert.equal(long132.length, 132);
  assert.equal(max1024.length, 1024);
  try {
    const listener = await tls.start((request, response) => {
      response.setHeader("content-type", "application/json");
      if (request.url === "/jwks.json") response.end(JSON.stringify({ keys }));
      else if (request.url === "/client.json") {
        metadataGets++;
        response.end(
          JSON.stringify({
            client_id: origin + "/client.json",
            jwks_uri: origin + "/jwks.json",
            grant_types: ["client_credentials"],
            response_types: [],
            redirect_uris: [],
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "ES256",
          }),
        );
      } else {
        response.statusCode = 404;
        response.end("{}");
      }
    });
    origin = listener.origin;
    const id = origin + "/client.json";
    const sign = async (kid: string) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: id,
        sub: id,
        aud: issuer,
        iat: now,
        exp: now + 60,
        jti: crypto.randomUUID(),
      })
        .setProtectedHeader({ alg: "ES256", kid })
        .sign(pair.privateKey);
    };
    for (const kid of [long132, max1024]) {
      keys = [{ ...pub, kid }];
      const assertion = await sign(kid);
      await jwtVerify(assertion, pair.publicKey, {
        algorithms: ["ES256"],
        issuer: id,
        subject: id,
        audience: issuer,
      });
      const verified = await new ClientAuthenticator(
        tls.fetcher(),
        issuer,
      ).authenticate(id, assertion);
      assert.equal(verified.clientId, id);
    }
    const invalid = [
      "",
      " ",
      "\n",
      "visible\u0000key",
      "visible\u007fkey",
      "visible\u0085key",
      "k".repeat(1025),
    ];
    for (const kid of invalid) {
      keys = [{ ...pub, kid: "valid-key" }];
      const assertion = await sign(kid);
      await jwtVerify(assertion, pair.publicKey, {
        algorithms: ["ES256"],
        issuer: id,
        subject: id,
        audience: issuer,
      });
      const before = metadataGets;
      await assert.rejects(
        new ClientAuthenticator(tls.fetcher(), issuer).authenticate(
          id,
          assertion,
        ),
        /invalid_client/,
      );
      assert.equal(
        metadataGets,
        before,
        "Invalid JWT kid must fail before untrusted retrieval",
      );
      keys = [
        { ...pub, kid: "valid-key" },
        { ...pub, kid },
      ];
      await assert.rejects(
        new ClientAuthenticator(tls.fetcher(), issuer).authenticate(
          id,
          await sign("valid-key"),
        ),
        /invalid_client/,
      );
    }
    // Existing ambiguity and private-key protections remain active with the larger bounded label.
    keys = [
      { ...pub, kid: long132 },
      { ...pub, kid: long132 },
    ];
    await assert.rejects(
      new ClientAuthenticator(tls.fetcher(), issuer).authenticate(
        id,
        await sign(long132),
      ),
      /invalid_client/,
    );
    keys = [{ ...pub, kid: long132, d: "forbidden-private-material" }];
    await assert.rejects(
      new ClientAuthenticator(tls.fetcher(), issuer).authenticate(
        id,
        await sign(long132),
      ),
      /invalid_client/,
    );
  } finally {
    await tls.close();
  }
});
