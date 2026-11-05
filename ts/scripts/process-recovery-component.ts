/** Separate-process AS/RS and operator-runbook backup recovery; not a deployment/System lane. */
import assert from "node:assert/strict";
import { fork, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  mkdtemp,
  open,
  readFile,
  rm,
  chmod,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer as createPortReservation } from "node:net";
import { request } from "node:https";
import { setTimeout as delay } from "node:timers/promises";
import { performance } from "node:perf_hooks";
import { Pool } from "pg";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  PostgresStore,
  type Policy,
} from "../packages/store-postgres/store.js";
import { tlsFixture } from "../tests/helpers.js";
import { ClientAuthenticator } from "../packages/oauth-core/client.js";
import type { ProcessWorkerConfig } from "../tests/process-recovery.worker.js";

assert.equal(
  process.env.NODE_ENV === "test",
  true,
  "Use the owning private PostgreSQL runner",
);
let database: URL;
try {
  database = new URL(process.env.DATABASE_URL ?? "postgresql:///missing");
} catch {
  throw new Error("Use the owning private PostgreSQL runner");
}
assert.equal(
  database.protocol === "postgresql:" &&
    database.hostname === "" &&
    database.username === "" &&
    database.password === "" &&
    database.pathname === "/cimd_component",
  true,
  "Only the owning credential-free database is permitted",
);
const socket = database.searchParams.get("host") ?? "";
assert.equal(
  /^\/tmp\/cimd-pg\.[A-Za-z0-9]+\/socket$/u.test(socket),
  true,
  "Only the owning private socket is permitted",
);
const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const workerPath = join(sourceRoot, "tests/process-recovery.worker.ts");
const root = await mkdtemp(join(tmpdir(), "cimd-process-recovery-"));
await chmod(root, 0o700);
const sourceFiles = [
  workerPath,
  fileURLToPath(import.meta.url),
  join(sourceRoot, "packages/oauth-as/app.ts"),
  join(sourceRoot, "packages/oauth-rs/index.ts"),
  join(sourceRoot, "examples/minimal-mcp-server/app.ts"),
  join(sourceRoot, "packages/store-postgres/store.ts"),
  join(sourceRoot, "packages/oauth-core/client.ts"),
  join(sourceRoot, "packages/oauth-core/fetch.ts"),
  join(sourceRoot, "packages/oauth-core/parse.ts"),
];
const sha = (value: string | Buffer) =>
  createHash("sha256").update(value).digest("hex");
const before = Object.fromEntries(
  await Promise.all(
    sourceFiles.map(async (path) => [path, sha(await readFile(path))]),
  ),
);
const baseEnvironment: NodeJS.ProcessEnv = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  LANG: "C.UTF-8",
  TZ: "UTC",
  NODE_ENV: "test",
};
const pgBin = process.env.POSTGRES_BIN_DIR ?? "/usr/lib/postgresql/14/bin";
const restoredName = "cimd_recovery_" + randomBytes(8).toString("hex");
const restoredUrl = new URL(database);
restoredUrl.pathname = "/" + restoredName;
const pgEnvironment = {
  ...baseEnvironment,
  PGHOST: socket,
  PGCONNECT_TIMEOUT: "5",
  PGPASSFILE: join(root, "empty.pgpass"),
  PGSERVICEFILE: join(root, "empty.pgservice"),
};
await writeFile(pgEnvironment.PGPASSFILE, "", { mode: 0o600 });
await writeFile(pgEnvironment.PGSERVICEFILE, "", { mode: 0o600 });
let stage = "prepare";
const stages: Array<{ stage: string; elapsedMs: number }> = [];
const started = performance.now();
const mark = (name: string) => {
  stage = name;
  const value = {
    stage: name,
    elapsedMs: Math.round(performance.now() - started),
  };
  stages.push(value);
  process.stdout.write(JSON.stringify({ event: "phase", ...value }) + "\n");
};
const secrets = new Set<string>();
const workers: RunningWorker[] = [];
const allChildren = new Map<ChildProcess, Promise<void>>();
type WorkerStats = {
  event: string;
  role: "as" | "rs";
  pid: number;
  requests: number;
  tokenRequests: number;
  introspections: number;
  resourceRequests: number;
  databaseEnvironment: boolean;
  configContainsDatabase: boolean;
  pgPoolConstructed: boolean;
  id?: number;
};
type RunningWorker = {
  child: ChildProcess;
  ready: WorkerStats;
  stats(): Promise<WorkerStats>;
  stop(abrupt?: boolean): Promise<void>;
  closed: Promise<void>;
  output: () => {
    stdoutBytes: number;
    stderrBytes: number;
    stdoutSha256: string;
    stderrSha256: string;
    secretSeen: boolean;
  };
};
function startWorker(
  configuration: ProcessWorkerConfig,
  databaseUrl?: string,
): Promise<RunningWorker> {
  const environment = {
    ...baseEnvironment,
    ...(configuration.role === "as" ? { DATABASE_URL: databaseUrl } : {}),
  };
  assert.equal(
    configuration.role !== "rs" || !("DATABASE_URL" in environment),
    true,
  );
  assert.equal(
    configuration.role !== "rs" ||
      !Object.keys(configuration).some((name) =>
        /database|postgres/i.test(name),
      ),
    true,
  );
  const child = fork(workerPath, [], {
    cwd: sourceRoot,
    env: environment,
    execArgv: ["--import", import.meta.resolve("tsx/esm")],
    stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  const stdout: Buffer[] = [],
    stderr: Buffer[] = [];
  let stdoutBytes = 0,
    stderrBytes = 0,
    requestId = 0;
  const requests = new Map<
    number,
    {
      resolve(value: WorkerStats): void;
      reject(error: Error): void;
      timer: NodeJS.Timeout;
    }
  >();
  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );
  allChildren.set(child, closed);
  child.stdout!.on("data", (chunk: Buffer) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes <= 65536) stdout.push(chunk);
    else child.kill("SIGKILL");
  });
  child.stderr!.on("data", (chunk: Buffer) => {
    stderrBytes += chunk.length;
    if (stderrBytes <= 65536) stderr.push(chunk);
    else child.kill("SIGKILL");
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("worker_start_timeout"));
    }, 10000);
    const failure = () => {
      clearTimeout(timer);
      reject(new Error("worker_failed"));
      for (const pending of requests.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("worker_failed"));
      }
      requests.clear();
    };
    child.once("error", failure);
    child.on("message", (raw) => {
      const message = raw as WorkerStats;
      if (message.event === "failure") {
        failure();
        return;
      }
      if (message.event === "stats" && message.id !== undefined) {
        const pending = requests.get(message.id);
        if (pending) {
          clearTimeout(pending.timer);
          requests.delete(message.id);
          pending.resolve(message);
        }
        return;
      }
      if (message.event !== "ready") return;
      clearTimeout(timer);
      const worker: RunningWorker = {
        child,
        ready: message,
        closed,
        stats: () =>
          new Promise<WorkerStats>((complete, failed) => {
            const id = ++requestId;
            const deadline = setTimeout(() => {
              requests.delete(id);
              failed(new Error("worker_stats_timeout"));
            }, 5000);
            requests.set(id, {
              resolve: complete,
              reject: failed,
              timer: deadline,
            });
            child.send({ event: "stats", id }, (error) => {
              if (error) {
                clearTimeout(deadline);
                requests.delete(id);
                failed(new Error("worker_stats_unavailable"));
              }
            });
          }),
        stop: async (abrupt = false) => {
          if (child.exitCode !== null || child.signalCode !== null) {
            await closed;
            return;
          }
          if (abrupt) child.kill("SIGKILL");
          else child.send({ event: "stop" }, () => {});
          const force = setTimeout(() => child.kill("SIGKILL"), 8000);
          try {
            await closed;
          } finally {
            clearTimeout(force);
          }
        },
        output: () => {
          const out = Buffer.concat(stdout),
            err = Buffer.concat(stderr);
          const secretSeen = [...secrets].some(
            (value) =>
              out.includes(Buffer.from(value)) ||
              err.includes(Buffer.from(value)),
          );
          return {
            stdoutBytes,
            stderrBytes,
            stdoutSha256: sha(out),
            stderrSha256: sha(err),
            secretSeen,
          };
        },
      };
      workers.push(worker);
      resolve(worker);
    });
    child.once("close", () => {
      clearTimeout(timer);
      for (const pending of requests.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("worker_closed"));
      }
      requests.clear();
      reject(new Error("worker_closed_before_ready"));
    });
    child.send({ event: "start", configuration }, (error) => {
      if (error) failure();
    });
  });
}
async function port(): Promise<number> {
  const server = createPortReservation();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.equal(!!address && typeof address !== "string", true);
  const value = (address as { port: number }).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return value;
}
function pg(command: string, args: string[]): void {
  const result = spawnSync(join(pgBin, command), args, {
    env: pgEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(
    result.status === 0,
    true,
    "Owned PostgreSQL administrative command must succeed: " + command,
  );
}
const json = (response: Response): Promise<Record<string, unknown>> =>
  response
    .json()
    .then((value) => {
      assert.equal(
        !!value && typeof value === "object" && !Array.isArray(value),
        true,
      );
      return value as Record<string, unknown>;
    })
    .catch(() => {
      throw new Error("Expected JSON response");
    });
let asWorker: RunningWorker | undefined, rsWorker: RunningWorker | undefined;
let originalPool: Pool | undefined, restoredPool: Pool | undefined;
let createdRestoredDatabase = false;
let publisherTls: Awaited<ReturnType<typeof tlsFixture>> | undefined;
try {
  const keyFile = join(root, "tls.key.pem"),
    certFile = join(root, "tls.cert.pem");
  for (const path of [keyFile, certFile]) {
    const file = await open(path, "wx", 0o600);
    await file.close();
  }
  const certificate = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-subj",
      "/CN=auth.test",
      "-addext",
      "subjectAltName=DNS:auth.test,DNS:mcp.test",
      "-days",
      "1",
      "-keyout",
      keyFile,
      "-out",
      certFile,
    ],
    { env: baseEnvironment, stdio: "ignore", timeout: 10000 },
  );
  assert.equal(
    certificate.status === 0,
    true,
    "Private TLS fixture creation must succeed",
  );
  const ca = await readFile(certFile, "utf8");
  const issuer = "https://auth.test:" + (await port());
  const resource = "https://mcp.test:" + (await port()) + "/mcp";
  const unknownResource = "https://unreconciled.example/mcp";
  const asPort = Number(new URL(issuer).port),
    rsPort = Number(new URL(resource).port);
  assert.equal(
    asPort !== rsPort,
    true,
    "AS and RS require distinct owned listener ports",
  );
  const pair = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: "process-recovery-es256",
    alg: "ES256",
    use: "sig",
  };
  publisherTls = await tlsFixture();
  let publisherOrigin = "";
  const publisher = await publisherTls.start((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/jwks.json")
      res.end(JSON.stringify({ keys: [publicJwk] }));
    else if (req.url === "/client-a.json" || req.url === "/client-b.json")
      res.end(
        JSON.stringify({
          client_id: publisherOrigin + req.url,
          jwks_uri: publisherOrigin + "/jwks.json",
          grant_types: ["client_credentials"],
          response_types: [],
          redirect_uris: [],
          token_endpoint_auth_method: "private_key_jwt",
          token_endpoint_auth_signing_alg: "ES256",
        }),
      );
    else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  publisherOrigin = publisher.origin;
  const clientA = publisherOrigin + "/client-a.json",
    clientB = publisherOrigin + "/client-b.json";
  const rsId = "process-recovery-rs",
    rsSecret = randomBytes(32).toString("base64url");
  secrets.add(rsSecret);
  const scopes = ["agent.self.read", "catalog.read"];
  const policy: Policy = {
    resource,
    scopes,
    ttl: 600,
    maxNewClientsHour: 100,
    maxRequestsClientMinute: 1000,
    maxRequestsMinute: 1000,
    custodyCondition:
      "Isolated process-recovery component; not production custody attestation",
    enabled: true,
  };
  const limits = {
    globalMinute: 2000,
    originMinute: 1000,
    clientMinute: 1000,
    sourceMinute: 1000,
  };
  originalPool = new Pool({
    connectionString: database.href,
    max: 4,
    connectionTimeoutMillis: 5000,
    application_name: "cimd-process-recovery-operator",
  });
  const original = new PostgresStore(originalPool, issuer);
  await original.configureRequestLimits(limits);
  await original.configurePolicy(policy);
  await original.configurePolicy({ ...policy, resource: unknownResource });
  await original.provisionResourceServer(rsId, rsSecret, [resource]);
  await original.ready();
  const asConfiguration: ProcessWorkerConfig = {
    role: "as",
    issuer,
    resource,
    port: asPort,
    tlsKeyFile: keyFile,
    tlsCertFile: certFile,
    fetchCa: publisherTls.cert,
    addresses: { "identity.test": [{ address: "127.0.0.1", family: 4 }] },
    scopes,
  };
  const rsConfiguration: ProcessWorkerConfig = {
    role: "rs",
    issuer,
    resource,
    port: rsPort,
    tlsKeyFile: keyFile,
    tlsCertFile: certFile,
    fetchCa: ca,
    addresses: { "auth.test": [{ address: "127.0.0.1", family: 4 }] },
    scopes,
    rsId,
    rsSecret,
  };
  const allowedOrigins = new Set([issuer, new URL(resource).origin]);
  const send: typeof fetch = async (input, init) => {
    const outgoing = new Request(input, init);
    const target = new URL(outgoing.url);
    assert.equal(
      allowedOrigins.has(target.origin) && target.protocol === "https:",
      true,
      "Only the owned AS/RS HTTPS origins may be contacted",
    );
    const body = outgoing.body
      ? Buffer.from(await outgoing.arrayBuffer())
      : undefined;
    return new Promise<Response>((resolve, reject) => {
      const connection = request(
        target,
        {
          method: outgoing.method,
          headers: Object.fromEntries(outgoing.headers),
          ca,
          rejectUnauthorized: true,
          agent: false,
          signal: AbortSignal.any([outgoing.signal, AbortSignal.timeout(5000)]),
          lookup: ((
            _host: string,
            options: { all?: boolean },
            done: Function,
          ) =>
            options.all
              ? done(null, [{ address: "127.0.0.1", family: 4 }])
              : done(null, "127.0.0.1", 4)) as never,
        },
        (incoming) => {
          const chunks: Buffer[] = [];
          let bytes = 0;
          incoming.on("data", (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > 65536)
              incoming.destroy(new Error("fixture_response_too_large"));
            else chunks.push(chunk);
          });
          incoming.once("error", reject);
          incoming.once("end", () => {
            const headers = new Headers();
            for (const [name, value] of Object.entries(incoming.headers)) {
              if (Array.isArray(value))
                value.forEach((item) => headers.append(name, item));
              else if (value !== undefined) headers.set(name, value);
            }
            const status = incoming.statusCode!;
            resolve(
              new Response(
                [204, 205, 304].includes(status) ? null : Buffer.concat(chunks),
                { status, headers },
              ),
            );
          });
        },
      );
      connection.once("error", () =>
        reject(new Error("fixture_https_unavailable")),
      );
      connection.end(body);
    });
  };
  const sign = async (id: string, futureIatSeconds = 0) => {
    const now = Math.floor(Date.now() / 1000),
      jti = randomUUID();
    const compact = await new SignJWT({
      iss: id,
      sub: id,
      aud: issuer,
      iat: now + futureIatSeconds,
      exp: now + futureIatSeconds + 60,
      jti,
    })
      .setProtectedHeader({ alg: "ES256", kid: publicJwk.kid })
      .sign(pair.privateKey);
    secrets.add(compact);
    return {
      compact,
      jtiDigest: sha(jti),
      createdAt: now,
      issuedAt: now + futureIatSeconds,
      expires: now + futureIatSeconds + 60,
    };
  };
  const tokenRequest = (id: string, compact: string, target = resource) =>
    send(issuer + "/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: id,
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: compact,
        resource: target,
        scope: scopes.join(" "),
      }),
    });
  const obtain = async (id: string, futureIatSeconds = 0) => {
    const proof = await sign(id, futureIatSeconds),
      response = await tokenRequest(id, proof.compact);
    assert.equal(response.status, 200, "A valid machine issuance must succeed");
    const value = await json(response);
    assert.equal(typeof value.access_token === "string", true);
    const token = value.access_token as string;
    secrets.add(token);
    return { token, proof };
  };
  const resourceRequest = (token: string) =>
    send(resource, {
      method: "POST",
      headers: {
        authorization: "Bearer " + token,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2025-11-25",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
  const tools = async (token: string) => {
    const sdk = new Client({
      name: "process-recovery-owning-component",
      version: "1",
    });
    try {
      await sdk.connect(
        new StreamableHTTPClientTransport(new URL(resource), {
          fetch: send,
          requestInit: { headers: { authorization: "Bearer " + token } },
        }),
      );
      const listed = await sdk.listTools();
      assert.equal(listed.tools.length, 2);
      for (const name of ["identity_get", "catalog_list"]) {
        const result = await sdk.callTool({ name, arguments: {} });
        assert.equal(
          result.isError === true,
          false,
          "The real MCP tool must succeed",
        );
      }
    } finally {
      await sdk.close();
    }
  };
  const inactive = async (store: PostgresStore, token: string) => {
    const value = await store.introspect(rsId, rsSecret, token);
    assert.equal(
      value.active === false,
      true,
      "Old or banned credentials must be inactive",
    );
  };
  mark("separate-process-servers");
  asWorker = await startWorker(asConfiguration, database.href);
  rsWorker = await startWorker(rsConfiguration);
  assert.equal(
    asWorker.ready.pid !== rsWorker.ready.pid &&
      asWorker.ready.pid !== process.pid &&
      rsWorker.ready.pid !== process.pid,
    true,
  );
  assert.equal(
    rsWorker.ready.databaseEnvironment ||
      rsWorker.ready.configContainsDatabase ||
      rsWorker.ready.pgPoolConstructed,
    false,
  );
  const first = await obtain(clientA),
    banned = await obtain(clientB);
  await tools(first.token);
  const originalSubject = (
    await original.introspect(rsId, rsSecret, first.token)
  ).sub;
  assert.equal(typeof originalSubject === "string", true);
  const firstRsPid = rsWorker.ready.pid;
  await rsWorker.stop();
  rsWorker = await startWorker(rsConfiguration);
  assert.equal(rsWorker.ready.pid !== firstRsPid, true);
  await tools(first.token);
  const statsBeforeRestart = await asWorker.stats();
  assert.equal(statsBeforeRestart.introspections > 0, true);
  assert.equal(
    first.proof.expires > Date.now() / 1000 + 5,
    true,
    "RS restart replay probe remains unexpired",
  );
  assert.equal(
    (await tokenRequest(clientA, first.proof.compact)).status,
    401,
    "Replay survives a new RS process",
  );

  mark("actual-backup-before-new-security-facts");
  const dump = join(root, "snapshot.dump");
  const dumpHandle = await open(dump, "wx", 0o600);
  await dumpHandle.close();
  pg("pg_dump", [
    "--format=custom",
    "--file",
    dump,
    "--dbname",
    "cimd_component",
    "--no-owner",
    "--no-privileges",
  ]);
  const backupDigest = sha(await readFile(dump));
  await original.blockClient(clientB, true);
  const banFact = { clientId: clientB, blocked: true, recordedAt: Date.now() };
  const banWitnessDigest = sha(JSON.stringify(banFact));
  await inactive(original, banned.token);
  assert.equal(
    (await tokenRequest(clientB, (await sign(clientB)).compact)).status,
    401,
    "Ban denies fresh assertions before process restart",
  );
  const replayBeforeAsRestart = await obtain(clientA);
  const firstAsPid = asWorker.ready.pid;
  await asWorker.stop();
  asWorker = await startWorker(asConfiguration, database.href);
  assert.equal(asWorker.ready.pid !== firstAsPid, true);
  await tools(first.token);
  assert.equal(
    replayBeforeAsRestart.proof.expires > Date.now() / 1000 + 5,
    true,
    "Replay proof remains within its actual acceptance lifetime",
  );
  assert.equal(
    (await tokenRequest(clientA, replayBeforeAsRestart.proof.compact)).status,
    401,
    "Actual AS process restart must preserve durable assertion replay",
  );
  assert.equal(
    (await tokenRequest(clientB, (await sign(clientB)).compact)).status,
    401,
    "Actual AS process restart must preserve the ban",
  );
  await inactive(original, banned.token);
  assert.equal(
    (await resourceRequest(banned.token)).status,
    401,
    "The separate RS observes the durable ban through HTTP introspection",
  );
  // Accept the worst legal future-iat vector immediately before isolating AS ingress.
  const late = await obtain(clientA, 5);
  assert.equal(late.proof.issuedAt - late.proof.createdAt, 5);
  assert.equal(late.proof.expires - late.proof.issuedAt, 60);
  mark("as-outage-rs-fail-closed");
  await asWorker.stop(true);
  asWorker = undefined;
  const quarantineStart = { wall: Date.now(), monotonic: performance.now() };
  assert.equal(
    (await resourceRequest(first.token)).status,
    503,
    "The real RS must fail closed when HTTP introspection is unavailable",
  );
  assert.equal(
    rsWorker.child.exitCode === null,
    true,
    "The independent RS remains running during AS failure",
  );

  mark("restore-to-new-owned-database-offline");
  pg("createdb", [restoredName]);
  createdRestoredDatabase = true;
  pg("pg_restore", [
    "--exit-on-error",
    "--no-owner",
    "--no-privileges",
    "--dbname",
    restoredName,
    dump,
  ]);
  restoredPool = new Pool({
    connectionString: restoredUrl.href,
    max: 4,
    connectionTimeoutMillis: 5000,
    application_name: "cimd-process-recovery-restored-operator",
  });
  const restored = new PostgresStore(restoredPool, issuer);
  const missingReplay = async () =>
    Number(
      (
        await restoredPool!.query(
          "SELECT count(*)::integer AS count FROM assertion_replays WHERE namespace=$1 AND client_id=$2 AND jti_digest=$3",
          [restored.namespace, clientA, late.proof.jtiDigest],
        )
      ).rows[0].count,
    );
  assert.equal(
    await missingReplay(),
    0,
    "A later accepted assertion is genuinely missing from the backup",
  );
  assert.equal(
    Number(
      (
        await restoredPool.query(
          "SELECT count(*)::integer AS count FROM client_blocks WHERE namespace=$1 AND client_id=$2 AND blocked=true",
          [restored.namespace, clientB],
        )
      ).rows[0].count,
    ),
    0,
    "The later trusted ban is genuinely absent from the backup",
  );
  await restored.invalidateForRecovery();
  const disabled = await restoredPool.query(
    "SELECT enabled FROM admission_policies WHERE namespace=$1",
    [restored.namespace],
  );
  assert.equal(disabled.rowCount, 2);
  assert.equal(
    disabled.rows.every((row) => row.enabled === false),
    true,
  );
  await inactive(restored, first.token);
  await inactive(restored, banned.token);
  assert.equal(
    asWorker === undefined,
    true,
    "Restored ingress stays offline before reconciliation",
  );
  await restored.blockClient(banFact.clientId, banFact.blocked);
  const waitUntilElapsed = async (milliseconds: number) => {
    let remaining =
      milliseconds - (performance.now() - quarantineStart.monotonic);
    while (remaining > 0) {
      await delay(Math.min(remaining, 30000));
      assert.equal(asWorker === undefined, true);
      mark("offline-replay-quarantine");
      remaining =
        milliseconds - (performance.now() - quarantineStart.monotonic);
    }
  };
  await waitUntilElapsed(65050);
  assert.equal(await missingReplay(), 0);
  const boundaryAuthenticator = new ClientAuthenticator(
    publisherTls.fetcher(),
    issuer,
  );
  assert.equal(
    boundaryAuthenticator.clockTolerance,
    5,
    "Keep the production clock policy unchanged",
  );
  const acceptedAtLegacy65 = await boundaryAuthenticator.authenticate(
    clientA,
    late.proof.compact,
  );
  assert.equal(acceptedAtLegacy65.jtiDigest === late.proof.jtiDigest, true);
  assert.equal(
    acceptedAtLegacy65.issuedAt === late.proof.createdAt + 5 &&
      acceptedAtLegacy65.expires === late.proof.createdAt + 65,
    true,
  );
  const legacy65AcceptanceElapsedMs = Math.round(
    performance.now() - quarantineStart.monotonic,
  );
  const legacy65RemainingAcceptanceMs = Math.floor(
    (late.proof.expires + 5) * 1000 - Date.now(),
  );
  assert.equal(
    legacy65AcceptanceElapsedMs >= 65000 && legacy65RemainingAcceptanceMs > 0,
    true,
    "The worst legal assertion is still authenticatable after the old 65-second isolation",
  );
  assert.equal(
    await missingReplay(),
    0,
    "The native authentication probe must not consume replay or mint a Token",
  );
  assert.equal(
    (
      await restoredPool.query(
        "SELECT enabled FROM admission_policies WHERE namespace=$1",
        [restored.namespace],
      )
    ).rows.every((row) => row.enabled === false),
    true,
  );
  mark("legacy-65-window-insufficient-native-authentication-accepted");
  await waitUntilElapsed(71050);
  const quarantineMilliseconds = performance.now() - quarantineStart.monotonic;
  assert.equal(
    quarantineMilliseconds >= 71000 &&
      Date.now() - quarantineStart.wall >= 71000,
    true,
    "Observe future iat5 + lifetime60 + exp tolerance5, plus a conservative one-second margin",
  );
  await assert.rejects(
    boundaryAuthenticator.authenticate(clientA, late.proof.compact),
  );
  assert.equal(await missingReplay(), 0);
  assert.equal(
    Date.now() / 1000 > late.proof.expires + 5,
    true,
    "The missing accepted assertion is no longer valid",
  );
  await restored.configureRequestLimits(limits);
  await restored.provisionResourceServer(rsId, rsSecret, [resource]);
  await restored.configurePolicy(policy);
  assert.equal(
    (
      await restoredPool.query(
        "SELECT enabled FROM admission_policies WHERE namespace=$1 AND resource=$2",
        [restored.namespace, unknownResource],
      )
    ).rows[0]?.enabled,
    false,
    "Unreconciled policy remains disabled",
  );
  const oldRecord = await restoredPool.query(
    "SELECT expires_at FROM access_tokens WHERE namespace=$1 AND digest=$2",
    [restored.namespace, sha(first.token)],
  );
  assert.equal(
    oldRecord.rows[0]?.expires_at.getTime() > Date.now() + 5000,
    true,
    "The old token is still within its lifetime; generation must fence it",
  );
  mark("reopen-only-reconciled-policy");
  asWorker = await startWorker(asConfiguration, restoredUrl.href);
  assert.equal(
    (await resourceRequest(first.token)).status,
    401,
    "Restored pre-invalidation token must stay refused after policy reconfiguration",
  );
  assert.equal((await resourceRequest(banned.token)).status, 401);
  assert.equal(
    (await tokenRequest(clientA, late.proof.compact)).status,
    401,
    "Missing replay cannot revive an old assertion after the full offline window",
  );
  assert.equal(await missingReplay(), 0);
  assert.equal(
    (await tokenRequest(clientB, (await sign(clientB)).compact)).status,
    401,
    "Rebuilt trusted ban denies new assertions",
  );
  assert.equal(
    (
      await tokenRequest(
        clientA,
        (await sign(clientA)).compact,
        unknownResource,
      )
    ).status,
    400,
    "Unknown recovery facts do not re-enable an unreconciled policy",
  );
  const fresh = await obtain(clientA);
  assert.equal(
    (await restored.introspect(rsId, rsSecret, fresh.token)).sub ===
      originalSubject,
    true,
    "Explicitly recovered subject remains stable",
  );
  await tools(fresh.token);
  assert.equal((await tokenRequest(clientA, fresh.proof.compact)).status, 401);
  await rsWorker.stop();
  rsWorker = await startWorker(rsConfiguration);
  await tools(fresh.token);
  const finalAs = await asWorker.stats(),
    finalRs = await rsWorker.stats();
  assert.equal(
    finalAs.introspections > 0 && finalRs.resourceRequests > 0,
    true,
  );
  assert.equal(
    finalRs.databaseEnvironment ||
      finalRs.configContainsDatabase ||
      finalRs.pgPoolConstructed,
    false,
  );
  const after = Object.fromEntries(
    await Promise.all(
      sourceFiles.map(async (path) => [path, sha(await readFile(path))]),
    ),
  );
  assert.equal(
    JSON.stringify(after) === JSON.stringify(before),
    true,
    "Executed core and worker sources stay fixed",
  );
  for (const worker of workers) await worker.stop();
  const outputs = workers.map((worker) => ({
    role: worker.ready.role,
    pid: worker.ready.pid,
    ...worker.output(),
  }));
  assert.equal(
    outputs.every(
      (output) =>
        !output.secretSeen &&
        output.stdoutBytes <= 65536 &&
        output.stderrBytes <= 65536,
    ),
    true,
    "Worker output must not expose known private material",
  );
  process.stdout.write(
    JSON.stringify({
      passed: true,
      lane: "actual-independent-AS-RS-Node-processes-TLS-PG-dump-restore-operator-runbook",
      asProcessIds: workers
        .filter((worker) => worker.ready.role === "as")
        .map((worker) => worker.ready.pid),
      rsProcessIds: workers
        .filter((worker) => worker.ready.role === "rs")
        .map((worker) => worker.ready.pid),
      parentPid: process.pid,
      tools: ["identity_get", "catalog_list"],
      rsDatabaseEnvironment: false,
      rsDatabaseConfiguration: false,
      rsPgPoolConstructed: false,
      realHttpIntrospectionObserved: true,
      independentRsCredential: true,
      restartPreservesTokenReplayBan: true,
      asOutageRsFailClosed: true,
      actualPgDumpRestoreNewDatabase: true,
      backupSha256: backupDigest,
      externalOperatorBanFactDigest: banWitnessDigest,
      restoredMissingReplayObserved: true,
      quarantineMilliseconds: Math.round(quarantineMilliseconds),
      futureIatSeconds: 5,
      assertionLifetimeSeconds: 60,
      expirationToleranceSeconds: 5,
      worstAcceptedWindowSeconds: 70,
      conservativeQuarantineSeconds: 71,
      legacy65NativeAuthenticationAccepted: true,
      legacy65AcceptanceElapsedMs,
      legacy65RemainingAcceptanceMs,
      legacy65ProbeDidNotIssueTokenOrConsumeReplay: true,
      fullWindowNativeAuthenticationRejected: true,
      oldUnexpiredTokenInvalidAfterRecovery: true,
      incompleteReplayCannotAuthorize: true,
      trustedBanRebuilt: true,
      unknownFactsRemainDisabled: true,
      stages,
      sourceSha256: after,
      workerOutputs: outputs,
      boundary: {
        maliciousDbaRollbackDetection: false,
        durableIndependentSecurityWitness: false,
        trustedOperatorFactsRequired: true,
        testOnlyTlsWorkers: true,
        productionEntrypointDeployment: false,
        systemProductE2E: "not-run",
      },
    }) + "\n",
  );
} catch {
  process.stderr.write(
    JSON.stringify({
      passed: false,
      stage,
      error: "process_recovery_component_failed",
    }) + "\n",
  );
  process.exitCode = 1;
} finally {
  for (const worker of workers) await worker.stop().catch(() => {});
  for (const [child, closed] of allChildren) {
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
    await closed;
  }
  await publisherTls?.close().catch(() => {});
  await restoredPool?.end();
  await originalPool?.end();
  if (createdRestoredDatabase)
    pg("dropdb", ["--if-exists", "--force", restoredName]);
  await rm(root, { recursive: true, force: true });
}
