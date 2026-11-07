import { test } from "node:test";
import assert from "node:assert/strict";
import type { Express } from "express";
import { tlsFixture } from "./helpers.js";
import { TokenVerifier } from "../packages/oauth-rs/index.js";
import { createMcpApp } from "../examples/minimal-mcp-server/app.js";
process.env.NODE_ENV = "test";

test("authenticated modern discovery reaches the legacy dispatcher without bypassing tool scopes", async () => {
  const f = await tlsFixture();
  let app: Express;
  let origin = "";
  try {
    origin = (
      await f.start((req, res) => {
        if (req.url === "/introspect") {
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              active: true,
              iss: origin,
              aud: origin + "/mcp",
              subject_type: "client",
              client_id: origin + "/client.json",
              sub: "fixture",
              exp: Math.floor(Date.now() / 1000) + 60,
              scope: "catalog.read",
            }),
          );
        } else app(req, res);
      })
    ).origin;
    app = createMcpApp(
      new TokenVerifier(f.fetcher(), {
        issuer: origin,
        introspectionEndpoint: origin + "/introspect",
        resource: origin + "/mcp",
        rsId: "fixture-rs",
        rsSecret: "r".repeat(32),
        allowedScopes: ["agent.self.read", "catalog.read"],
      }),
    );
    const request = (method: string, params = {}, authorized = true) =>
      f.http(
        origin + "/mcp",
        JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...(authorized ? { authorization: "Bearer " + "t".repeat(32) } : {}),
        },
        "POST",
      );
    const discovery = await request("server/discover");
    assert.equal(discovery.status, 200);
    assert.equal(JSON.parse(discovery.body).error.code, -32601);
    const modernProbe = await f.http(
      origin + "/mcp",
      JSON.stringify({
        jsonrpc: "2.0",
        id: "modern-probe",
        method: "server/discover",
        params: {},
      }),
      {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer " + "t".repeat(32),
        "mcp-protocol-version": "2026-07-28",
      },
      "POST",
    );
    assert.equal(modernProbe.status, 200);
    assert.deepEqual(JSON.parse(modernProbe.body), {
      jsonrpc: "2.0",
      id: "modern-probe",
      error: { code: -32601, message: "Method not found" },
    });
    assert.equal((await request("server/discover", {}, false)).status, 401);
    assert.equal(
      (await request("tools/call", { name: "identity_get", arguments: {} }))
        .status,
      403,
    );
    assert.equal(
      (await request("tools/call", { name: "catalog_list", arguments: {} }))
        .status,
      200,
    );
    assert.equal((await request("unknown-method")).status, 403);
  } finally {
    await f.close();
  }
});
