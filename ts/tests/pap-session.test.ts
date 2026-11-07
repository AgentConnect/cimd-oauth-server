import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  calculateJwkThumbprint,
} from "jose";
import { PapSessionVerifier } from "../packages/pap/session.js";
import { loadClientMaterials } from "../packages/oauth-core/metadata.js";
import { tlsFixture } from "./helpers.js";
process.env.NODE_ENV = "test";
test("PAP 0.3 signed-out verification and continuity", async (t) => {
  const tls = await tlsFixture();
  t.after(() => tls.close());
  const identity = await generateKeyPair("ES256"),
    delegated = await generateKeyPair("ES256");
  const publicKey = {
    ...(await exportJWK(identity.publicKey)),
    kid: "identity",
    alg: "ES256",
  };
  const key = await exportJWK(delegated.publicKey);
  let clientId = "";
  const publisher = await tls.start((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify(
        req.url === "/client.json"
          ? {
              client_id: clientId,
              jwks_uri: clientId.replace("client.json", "jwks.json"),
            }
          : { keys: [publicKey] },
      ),
    );
  });
  clientId = publisher.origin + "/client.json";
  const company = "https://other.test",
    verifier = new PapSessionVerifier(tls.fetcher(), company);
  const now = Math.floor(Date.now() / 1000);
  const delegation = (claims: object = {}) =>
    new SignJWT({
      iss: clientId,
      cnf: { jwk: key },
      iat: now,
      exp: now + 3600,
      jti: randomUUID(),
      ...claims,
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "poppy-delegation+jwt",
        kid: "identity",
      })
      .sign(identity.privateKey);
  const sign = async (claims: object = {}, dlg?: string) =>
    new SignJWT({
      iss: clientId,
      aud: company,
      sid: "one",
      sub: "pairwise-user",
      htm: "GET",
      htu: company + "/api/hello",
      iat: now,
      jti: randomUUID(),
      ...claims,
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "poppy-session+jwt",
        kid: await calculateJwkThumbprint(key),
        poppy_dlg: dlg ?? (await delegation()),
      })
      .sign(delegated.privateKey);
  const verify = (token: string) =>
    verifier.verify(token, "GET", company + "/api/hello?view=demo");
  await t.test("no exp or OAuth grant needed; same sid continues", async () => {
    await loadClientMaterials(tls.fetcher(), clientId);
    await verify(await sign());
    await verify(await sign());
    assert.equal(verifier.sessionCount, 1);
  });
  for (const [name, claims] of Object.entries({
    target: { aud: "https://wrong.test" },
    method: { htm: "POST" },
    url: { htu: company + "/wrong" },
    query: { htu: company + "/api/hello?q=1" },
    stale: { iat: now - 100 },
    tokenHash: { ath: "not-allowed" },
    user: { sub: "other-user" },
    agent: { agent_id: "changed" },
  })) {
    await t.test(`rejects ${name}`, async () => {
      await assert.rejects(verify(await sign(claims)), {
        code: "invalid_session",
      });
    });
  }
  await t.test("rejects replay and tampering", async () => {
    const token = await sign();
    await verify(token);
    await assert.rejects(verify(token));
    const parts = (await sign()).split(".");
    parts[1] = Buffer.from(JSON.stringify({ sub: "tampered" })).toString(
      "base64url",
    );
    await assert.rejects(verify(parts.join(".")));
  });
  await t.test("rejects invalid delegations", async () => {
    for (const claims of [
      { exp: now - 1 },
      { exp: now + 86401 },
      { sub: "leaked-user" },
    ])
      await assert.rejects(verify(await sign({}, await delegation(claims))));
  });
  await t.test(
    "rejects absent delegation and direct identity signature",
    async () => {
      const token = await new SignJWT({ iss: clientId })
        .setProtectedHeader({
          alg: "ES256",
          typ: "poppy-session+jwt",
          kid: "identity",
        })
        .sign(identity.privateKey);
      await assert.rejects(verify(token));
    },
  );
});
