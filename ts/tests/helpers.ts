import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createServer, request } from "node:https";
import type { RequestListener } from "node:http";
import type { Server } from "node:https";
import { SafeHttpFetcher } from "../packages/oauth-core/fetch.js";
export async function tlsFixture() {
  const dir = await mkdtemp(join(tmpdir(), "cimd-tls-"));
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      join(dir, "key.pem"),
      "-out",
      join(dir, "cert.pem"),
      "-days",
      "1",
      "-subj",
      "/CN=identity.test",
      "-addext",
      "subjectAltName=DNS:identity.test,DNS:other.test,DNS:auth.test,DNS:mcp.test",
    ],
    { stdio: "ignore" },
  );
  const key = await readFile(join(dir, "key.pem"), "utf8");
  const cert = await readFile(join(dir, "cert.pem"), "utf8");
  const servers: Server[] = [];
  const start = async (handler: RequestListener, host = "identity.test") => {
    const server = createServer({ key, cert }, handler);
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Invalid fixture address");
    return { server, origin: `https://${host}:${address.port}` };
  };
  const fetcher = () =>
    new SafeHttpFetcher({
      mode: "test",
      ca: cert,
      addresses: Object.fromEntries(
        ["identity.test", "other.test", "auth.test", "mcp.test"].map((h) => [
          h,
          [{ address: "127.0.0.1", family: 4 }],
        ]),
      ),
    });
  const http = (
    url: string,
    body?: string,
    headers: Record<string, string> = {},
    method = body === undefined ? "GET" : "POST",
  ) =>
    new Promise<{
      status: number;
      headers: import("node:http").IncomingHttpHeaders;
      body: string;
    }>((resolve, reject) => {
      const req = request(
        url,
        {
          method,
          ca: cert,
          agent: false,
          lookup: ((_h: unknown, o: { all?: boolean }, cb: Function) =>
            o.all
              ? cb(null, [{ address: "127.0.0.1", family: 4 }])
              : cb(null, "127.0.0.1", 4)) as never,
          headers,
        },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () =>
            resolve({
              status: res.statusCode!,
              headers: res.headers,
              body: data,
            }),
          );
        },
      );
      req.on("error", reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  const close = async () => {
    for (const server of servers) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await rm(dir, { recursive: true, force: true });
  };
  return { start, fetcher, http, close, cert };
}
