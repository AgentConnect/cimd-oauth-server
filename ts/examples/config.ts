import { readFileSync } from "node:fs";
import { createServer as httpsServer } from "node:https";
import type { Express } from "express";
import { Pool } from "pg";
import { SafeHttpFetcher } from "../packages/oauth-core/fetch.js";
import { PostgresStore } from "../packages/store-postgres/store.js";
import { fail } from "../packages/oauth-core/errors.js";
import { httpsUrl } from "../packages/oauth-core/parse.js";
export function required(name: string): string {
  return process.env[name] || fail("missing_configuration");
}
export function productionFetcher(): SafeHttpFetcher {
  if (
    process.env.CIMD_TEST_NETWORK ||
    process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
    process.env.NODE_ENV === "test"
  )
    fail("test_configuration_forbidden");
  return new SafeHttpFetcher();
}
export function storeFromEnv(): PostgresStore {
  const issuer = required("OAUTH_ISSUER");
  const u = httpsUrl(issuer);
  if (u.search || issuer.endsWith("/")) fail("invalid_issuer");
  return new PostgresStore(
    new Pool({
      connectionString: required("DATABASE_URL"),
      max: 8,
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
    }),
    issuer,
  );
}
export function listen(app: Express, defaultPort: number): void {
  const port = Number(process.env.PORT ?? defaultPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail("invalid_port");
  // Plain HTTP is restricted to an explicit loopback reverse-proxy listener.
  const host = process.env.BIND_HOST ?? "127.0.0.1";
  if (process.env.TLS_KEY_FILE && process.env.TLS_CERT_FILE) {
    httpsServer(
      {
        key: readFileSync(process.env.TLS_KEY_FILE),
        cert: readFileSync(process.env.TLS_CERT_FILE),
      },
      app,
    ).listen(port, host);
  } else {
    if (
      !["127.0.0.1", "::1"].includes(host) ||
      process.env.ALLOW_LOOPBACK_PROXY !== "true"
    )
      fail("tls_required");
    app.listen(port, host);
  }
  process.stdout.write(JSON.stringify({ event: "listening", port }) + "\n");
}
