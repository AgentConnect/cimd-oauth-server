import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { tlsFixture } from "./helpers.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import { SafeHttpFetcher } from "../packages/oauth-core/fetch.js";
process.env.NODE_ENV = "test";
test("real TLS socket uses pinned fixture address, certificate hostname, redirect and byte bounds", async () => {
  const f = await tlsFixture();
  let hits = 0;
  try {
    const { origin } = await f.start((req, res) => {
      hits++;
      res.setHeader("content-type", "application/json");
      if (req.url === "/redirect") {
        res.writeHead(302, { location: "/ok" });
        res.end();
      } else if (req.url === "/large") res.end("x".repeat(65537));
      else if (req.url === "/compressed") {
        res.setHeader("content-encoding", "gzip");
        res.end("small");
      } else res.end('{"ok":true}');
    });
    assert.equal(
      (await f.fetcher().request(`${origin}/ok`)).toString(),
      '{"ok":true}',
    );
    for (const path of ["/redirect", "/large", "/compressed"])
      await assert.rejects(f.fetcher().request(origin + path));
    assert.equal(hits, 4);
    await assert.rejects(new SafeHttpFetcher().request(origin));
    const wrong = origin.replace("identity.test", "other.test");
    await assert.rejects(
      new SafeHttpFetcher({
        mode: "test",
        ca: f.cert,
        addresses: { "other.test": [{ address: "127.0.0.2", family: 4 }] },
      }).request(wrong),
    );
  } finally {
    await f.close();
  }
});
test("CIMD + JOSE validates draft fields, exact identity, public keys, rotation and assertion boundary", async () => {
  const f = await tlsFixture();
  const pair = await generateKeyPair("ES256");
  const publicJwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: "one",
    alg: "ES256",
    use: "sig",
  };
  let mode = "02",
    jwks: unknown = { keys: [publicJwk] },
    origin = "";
  let keyHits = 0;
  try {
    const started = await f.start((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/jwks") {
        keyHits++;
        res.end(JSON.stringify(jwks));
        return;
      }
      const m: Record<string, unknown> = {
        client_id: `${origin}/client`,
        jwks_uri: `${origin}/jwks`,
        grant_types: [
          "client_credentials",
          "authorization_code",
          "refresh_token",
        ],
        response_types: ["code"],
        redirect_uris: ["https://callback.test/real"],
      };
      if (mode === "02") m.token_endpoint_auth_method = "private_key_jwt";
      else if (mode === "03")
        m.token_endpoint_auth_methods_supported = ["none", "private_key_jwt"];
      else {
        m.token_endpoint_auth_method = "private_key_jwt";
        m.token_endpoint_auth_methods_supported = ["none"];
      }
      res.end(JSON.stringify(m));
    });
    origin = started.origin;
    const id = `${origin}/client`,
      issuer = "https://auth.test";
    const auth = new ClientAuthenticator(f.fetcher(), issuer);
    const sign = async (
      extra: Record<string, unknown> = {},
      header: Record<string, unknown> = {},
    ) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: id,
        sub: id,
        aud: issuer,
        iat: now,
        exp: now + 60,
        jti: crypto.randomUUID(),
        ...extra,
      })
        .setProtectedHeader({ alg: "ES256", kid: "one", ...header })
        .sign(pair.privateKey);
    };
    const first = await auth.authenticate(id, await sign());
    assert.equal(first.clientId, id);
    assert.equal(first.metadataDigest.length, 64);
    for (const extra of [
      { iss: id + "x" },
      { sub: id + "x" },
      { aud: issuer + "/" },
      { aud: [issuer] },
      { iat: Math.floor(Date.now() / 1000) + 10 },
      { exp: Math.floor(Date.now() / 1000) - 10 },
      { jti: "" },
    ])
      await assert.rejects(auth.authenticate(id, await sign(extra)));
    await assert.rejects(
      auth.authenticate(id, await sign({}, { jwk: publicJwk })),
    );
    const before = keyHits;
    await assert.rejects(
      auth.authenticate(id, await sign({}, { kid: "unknown" })),
    );
    assert.equal(keyHits, before + 1);
    mode = "03";
    assert.equal(
      (
        await new ClientAuthenticator(f.fetcher(), issuer).authenticate(
          id,
          await sign(),
        )
      ).clientId,
      id,
    );
    mode = "conflict";
    await assert.rejects(
      new ClientAuthenticator(f.fetcher(), issuer).authenticate(
        id,
        await sign(),
      ),
    );
    mode = "02";
    jwks = { keys: [publicJwk, publicJwk] };
    await assert.rejects(
      new ClientAuthenticator(f.fetcher(), issuer).authenticate(
        id,
        await sign(),
      ),
    );
    jwks = { keys: [{ ...publicJwk, d: "private-material" }] };
    await assert.rejects(
      new ClientAuthenticator(f.fetcher(), issuer).authenticate(
        id,
        await sign(),
      ),
    );
  } finally {
    await f.close();
  }
});

test("real UDP DNS rebinding and mixed answers cannot change pinned TLS destination", async () => {
  const { createSocket } = await import("node:dgram");
  const { Resolver } = await import("node:dns/promises");
  const f = await tlsFixture();
  const dns = createSocket("udp4");
  let queries = 0,
    httpHits = 0,
    mixed = false;
  dns.on("message", (query, peer) => {
    queries++;
    const addresses = mixed
      ? ["127.0.0.1", "127.0.0.2"]
      : [queries === 1 ? "127.0.0.1" : "127.0.0.2"];
    const header = Buffer.from(query.subarray(0, 12));
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(addresses.length, 6);
    header.writeUInt16BE(0, 8);
    header.writeUInt16BE(0, 10);
    const answers = addresses.map((ip) =>
      Buffer.concat([
        Buffer.from("c00c00010001000000010004", "hex"),
        Buffer.from(ip.split(".").map(Number)),
      ]),
    );
    dns.send(
      Buffer.concat([header, query.subarray(12), ...answers]),
      peer.port,
      peer.address,
    );
  });
  await new Promise<void>((resolve) => dns.bind(0, "127.0.0.1", resolve));
  const addr = dns.address();
  const resolver = new Resolver({ timeout: 1000, tries: 1 });
  resolver.setServers([`127.0.0.1:${addr.port}`]);
  try {
    const { origin } = await f.start((_req, res) => {
      httpHits++;
      res.setHeader("content-type", "application/json");
      res.end("{}");
    });
    const fetcher = new SafeHttpFetcher({
      mode: "test",
      ca: f.cert,
      addresses: { "identity.test": [{ address: "127.0.0.1", family: 4 }] },
      resolver: async (host) =>
        (await resolver.resolve4(host)).map((address) => ({
          address,
          family: 4,
        })),
    });
    assert.equal((await fetcher.request(origin + "/client")).toString(), "{}");
    assert.equal(queries, 1);
    assert.equal(httpHits, 1);
    await assert.rejects(fetcher.request(origin + "/client"), /unsafe_address/);
    assert.equal(queries, 2);
    assert.equal(httpHits, 1);
    mixed = true;
    await assert.rejects(fetcher.request(origin + "/client"), /unsafe_address/);
    assert.equal(httpHits, 1);
    const wrongHostname = new SafeHttpFetcher({
      mode: "test",
      ca: f.cert,
      addresses: { "evil.test": [{ address: "127.0.0.1", family: 4 }] },
    });
    await assert.rejects(
      wrongHostname.request(
        origin.replace("identity.test", "evil.test") + "/client",
      ),
      /fetch_failed/,
    );
  } finally {
    dns.close();
    resolver.cancel();
    await f.close();
  }
});
