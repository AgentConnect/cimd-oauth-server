/** Test-only separate-process entrypoint around the production AS or RS public factory. */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import { createHash } from "node:crypto";
import { userInfo } from "node:os";
import type { Pool } from "pg";
import {
  SafeHttpFetcher,
  type TestNetwork,
} from "../packages/oauth-core/fetch.js";

export type ProcessWorkerConfig = {
  role: "as" | "rs";
  issuer: string;
  resource: string;
  port: number;
  tlsKeyFile: string;
  tlsCertFile: string;
  fetchCa: string;
  addresses: TestNetwork["addresses"];
  scopes: string[];
  rsId?: string;
  rsSecret?: string;
};

assert.equal(process.env.NODE_ENV === "test", true, "This worker is test-only");
assert.equal(
  process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0",
  false,
  "TLS verification must remain enabled",
);
let server: Server | undefined;
let pool: Pool | undefined;
let configuration: ProcessWorkerConfig | undefined;
let shutdown: Promise<void> | undefined;
const counts = {
  requests: 0,
  tokenRequests: 0,
  introspections: 0,
  resourceRequests: 0,
};
let pgPoolConstructed = false;
const hasDatabaseEnvironment = () =>
  Object.keys(process.env).some(
    (name) => name === "DATABASE_URL" || name.startsWith("PG"),
  );
const emit = (message: Record<string, unknown>) => {
  if (!process.connected) return;
  try {
    process.send?.(message, () => {});
  } catch {
    /* The owning parent may already have closed its IPC channel. */
  }
};
const statistics = () => ({
  role: configuration?.role,
  pid: process.pid,
  ...counts,
  databaseEnvironment: hasDatabaseEnvironment(),
  pgPoolConstructed,
  configContainsDatabase: Object.keys(configuration ?? {}).some((name) =>
    /database|postgres/i.test(name),
  ),
});
async function stop(): Promise<void> {
  shutdown ??= (async () => {
    server?.closeAllConnections();
    if (server?.listening)
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    await pool?.end();
  })();
  await shutdown;
}
async function start(config: ProcessWorkerConfig): Promise<void> {
  assert.equal(
    configuration === undefined,
    true,
    "A worker has exactly one role",
  );
  assert.equal(config.role === "as" || config.role === "rs", true);
  assert.equal(
    Number.isInteger(config.port) && config.port > 1024 && config.port < 65536,
    true,
  );
  const issuer = new URL(config.issuer),
    resource = new URL(config.resource);
  assert.equal(
    issuer.protocol === "https:" && issuer.hostname === "auth.test",
    true,
  );
  assert.equal(
    resource.protocol === "https:" &&
      resource.hostname === "mcp.test" &&
      resource.pathname === "/mcp",
    true,
  );
  assert.equal(
    Number((config.role === "as" ? issuer : resource).port) === config.port,
    true,
  );
  assert.equal(
    Object.keys(config).some((name) => /database|postgres/i.test(name)),
    false,
  );
  for (const path of [config.tlsKeyFile, config.tlsCertFile])
    assert.equal(
      ((await stat(path)).mode & 0o077) === 0,
      true,
      "Fixture TLS files must be private",
    );
  configuration = config;
  const fetcher = new SafeHttpFetcher({
    mode: "test",
    ca: config.fetchCa,
    addresses: config.addresses,
  });
  let handler: (
    request: import("node:http").IncomingMessage,
    response: import("node:http").ServerResponse,
  ) => void;
  if (config.role === "as") {
    const database = new URL(
      process.env.DATABASE_URL ?? "postgresql:///missing",
    );
    assert.equal(
      database.protocol === "postgresql:" &&
        database.hostname === "" &&
        database.username === "" &&
        database.password === "",
      true,
      "Use a private credential-free database",
    );
    assert.equal(
      /^\/tmp\/cimd-pg\.[A-Za-z0-9]+\/socket$/u.test(
        database.searchParams.get("host") ?? "",
      ),
      true,
    );
    assert.equal(
      /^\/(?:cimd_component|cimd_recovery_[a-f0-9]{16})$/u.test(
        database.pathname,
      ),
      true,
    );
    const { Pool: ActualPool } = await import("pg");
    const { PostgresStore } = await import(
      "../packages/store-postgres/store.js"
    );
    const { ClientAuthenticator } = await import(
      "../packages/oauth-core/client.js"
    );
    const { createAuthorizationServer } = await import(
      "../packages/oauth-as/app.js"
    );
    pool = new ActualPool({
      host: database.searchParams.get("host")!,
      database: database.pathname.slice(1),
      user: userInfo().username,
      max: 4,
      connectionTimeoutMillis: 5000,
      application_name: "cimd-process-recovery-as",
    });
    pgPoolConstructed = true;
    const store = new PostgresStore(pool, config.issuer);
    await store.ready();
    handler = createAuthorizationServer(
      store,
      new ClientAuthenticator(fetcher, config.issuer),
      config.scopes,
    );
  } else {
    assert.equal(
      hasDatabaseEnvironment(),
      false,
      "RS environment must not contain database configuration",
    );
    assert.equal(
      typeof config.rsId === "string" &&
        typeof config.rsSecret === "string" &&
        config.rsSecret.length >= 32,
      true,
    );
    // The RS branch never imports pg, PostgresStore or the AS/config entrypoint.
    const { TokenVerifier } = await import("../packages/oauth-rs/index.js");
    const { createMcpApp } = await import(
      "../examples/minimal-mcp-server/app.js"
    );
    handler = createMcpApp(
      new TokenVerifier(fetcher, {
        issuer: config.issuer,
        introspectionEndpoint: config.issuer + "/oauth/introspect",
        resource: config.resource,
        rsId: config.rsId!,
        rsSecret: config.rsSecret!,
        allowedScopes: config.scopes,
      }),
    );
    assert.equal(pgPoolConstructed, false);
  }
  server = createServer(
    {
      key: await readFile(config.tlsKeyFile),
      cert: await readFile(config.tlsCertFile),
    },
    (request, response) => {
      counts.requests++;
      if (request.url === "/oauth/token") counts.tokenRequests++;
      if (request.url === "/oauth/introspect") counts.introspections++;
      if (request.url === "/mcp") counts.resourceRequests++;
      handler(request, response);
    },
  );
  await new Promise<void>((resolve, reject) => {
    server!.once("error", reject);
    server!.listen(config.port, "127.0.0.1", () => {
      server!.removeListener("error", reject);
      resolve();
    });
  });
  emit({ event: "ready", ...statistics() });
}
async function fail(error: unknown): Promise<void> {
  const digest = createHash("sha256")
    .update(
      error instanceof Error ? error.name + ":" + error.message : "unknown",
    )
    .digest("hex");
  emit({
    event: "failure",
    reason: "worker_failure",
    errorDigest: digest,
    pid: process.pid,
  });
  await stop().catch(() => {});
  process.exitCode = 1;
  if (process.connected) process.disconnect();
}
process.on("message", (message) => {
  const input = message as {
    event: string;
    configuration?: ProcessWorkerConfig;
    id?: number;
  };
  void (async () => {
    if (input.event === "start" && input.configuration)
      await start(input.configuration);
    else if (input.event === "stats")
      emit({ event: "stats", id: input.id, ...statistics() });
    else if (input.event === "stop") {
      await stop();
      emit({ event: "stopped", ...statistics() });
      if (process.connected) process.disconnect();
    } else throw new Error("Unknown worker command");
  })().catch(fail);
});
process.on("disconnect", () => {
  void stop().finally(() => process.exit(process.exitCode ?? 0));
});
process.on("SIGTERM", () => {
  void stop().finally(() => process.exit(0));
});
process.on("uncaughtException", (error) => {
  void fail(error);
});
process.on("unhandledRejection", (error) => {
  void fail(error);
});
