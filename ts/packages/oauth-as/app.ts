import express, { type ErrorRequestHandler } from "express";
import { ClientAuthenticator } from "../oauth-core/client.js";
import { ProtocolError, fail } from "../oauth-core/errors.js";
import { form, httpsUrl, metadataPath, scopes } from "../oauth-core/parse.js";
import { PostgresStore } from "../store-postgres/store.js";
export function authorizationServerMetadata(
  issuer: string,
  supportedScopes: string[],
): Record<string, unknown> {
  const base = issuer.replace(/\/$/, "");
  return {
    issuer,
    token_endpoint: `${base}/oauth/token`,
    introspection_endpoint: `${base}/oauth/introspect`,
    revocation_endpoint: `${base}/oauth/revoke`,
    client_id_metadata_document_supported: true,
    grant_types_supported: ["client_credentials"],
    token_endpoint_auth_methods_supported: ["private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported: ["ES256"],
    introspection_endpoint_auth_methods_supported: ["client_secret_basic"],
    revocation_endpoint_auth_methods_supported: ["private_key_jwt"],
    revocation_endpoint_auth_signing_alg_values_supported: ["ES256"],
    scopes_supported: supportedScopes,
  };
}
export function createAuthorizationServer(
  store: PostgresStore,
  authenticator: ClientAuthenticator,
  supportedScopes: string[],
) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  if (store.issuer !== authenticator.issuer)
    fail("invalid_issuer_configuration");
  const issuer = store.issuer;
  const path = httpsUrl(issuer).pathname.replace(/\/$/, "");
  let activeAuthentications = 0;
  app.get(metadataPath(issuer, "oauth-authorization-server"), (_req, res) =>
    res.json(authorizationServerMetadata(issuer, supportedScopes)),
  );
  app.get("/ready", async (_req, res) => {
    await store.ready();
    res.json({ ready: true });
  });
  app.use(
    `${path}/oauth`,
    express.text({ type: "application/x-www-form-urlencoded", limit: "24kb" }),
    (_req, res, next) => {
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      next();
    },
  );
  const authenticate = async (f: Record<string, string>, source: string) => {
    if (
      !f.client_id ||
      !f.client_assertion ||
      f.client_assertion_type !==
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
      fail("invalid_client", 401);
    if (activeAuthentications >= 8) fail("temporarily_unavailable", 429);
    activeAuthentications++;
    try {
      await store.preflight(f.client_id!, source);
      if (await store.isBlocked(f.client_id!)) fail("invalid_client", 401);
      try {
        return await authenticator.authenticate(
          f.client_id!,
          f.client_assertion!,
        );
      } catch (error) {
        if (error instanceof ProtocolError && error.status === 429) throw error;
        return fail("invalid_client", 401);
      }
    } finally {
      activeAuthentications--;
    }
  };
  app.post(`${path}/oauth/token`, async (req, res) => {
    if (typeof req.body !== "string" || req.headers.authorization)
      fail("invalid_request");
    const f = form(req.body, [
      "grant_type",
      "client_id",
      "client_assertion_type",
      "client_assertion",
      "resource",
      "scope",
    ]);
    if (f.grant_type !== "client_credentials") fail("unsupported_grant_type");
    if (!f.resource || !f.scope) fail("invalid_request");
    const verified = await authenticate(
      f,
      req.socket.remoteAddress ?? "unknown",
    );
    let requested: string[];
    try {
      requested = scopes(f.scope!);
    } catch {
      return store.rejectVerified(verified, "invalid_scope");
    }
    res.json(await store.issue(verified, f.resource!, requested));
  });
  app.post(`${path}/oauth/revoke`, async (req, res) => {
    if (typeof req.body !== "string" || req.headers.authorization)
      fail("invalid_request");
    const f = form(req.body, [
      "client_id",
      "client_assertion_type",
      "client_assertion",
      "token",
      "token_type_hint",
    ]);
    if (!f.token) fail("invalid_request");
    if (f.token_type_hint && f.token_type_hint !== "access_token")
      fail("unsupported_token_type");
    await store.revoke(
      await authenticate(f, req.socket.remoteAddress ?? "unknown"),
      f.token!,
    );
    res.status(200).end();
  });
  app.post(`${path}/oauth/introspect`, async (req, res) => {
    if (typeof req.body !== "string") fail("invalid_request");
    const f = form(req.body, ["token", "token_type_hint"]);
    if (!f.token) fail("invalid_request");
    const auth = req.headers.authorization;
    if (!auth || !/^Basic [A-Za-z0-9+/]+={0,2}$/.test(auth))
      fail("invalid_client", 401);
    const decoded = Buffer.from(auth!.slice(6), "base64").toString("utf8");
    const colon = decoded.indexOf(":");
    if (colon < 1 || decoded.length > 4096) fail("invalid_client", 401);
    let id: string, secret: string;
    try {
      id = decodeURIComponent(decoded.slice(0, colon).replace(/\+/g, " "));
      secret = decodeURIComponent(decoded.slice(colon + 1).replace(/\+/g, " "));
    } catch {
      return fail("invalid_client", 401);
    }
    res.json(await store.introspect(id, secret, f.token!));
  });
  app.use(((err, req, res, _next) => {
    const e =
      err instanceof ProtocolError
        ? err
        : new ProtocolError("server_error", 503);
    if (e.status === 429) res.set("Retry-After", "60");
    if (e.status === 401 && req.path.endsWith("/oauth/introspect"))
      res.set("WWW-Authenticate", 'Basic realm="introspection"');
    res.status(e.status).json({ error: e.code });
  }) satisfies ErrorRequestHandler);
  return app;
}
