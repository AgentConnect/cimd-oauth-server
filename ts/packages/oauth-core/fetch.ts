import https from "node:https";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";
import { fail, ProtocolError } from "./errors.js";
import { httpsUrl } from "./parse.js";
export type Address = { address: string; family: number };
export type TestNetwork = {
  mode: "test";
  addresses: Record<string, Address[]>;
  ca: string;
  resolver?: (host: string) => Promise<Address[]>;
};
export class SafeHttpFetcher {
  private inflight = 0;
  private origins = new Map<string, number>();
  constructor(private readonly testNetwork?: TestNetwork) {
    if (testNetwork && process.env.NODE_ENV !== "test")
      fail("test_network_forbidden");
    if (
      testNetwork &&
      Object.values(testNetwork.addresses).some(
        (list) =>
          !list.length ||
          list.some(
            (a) =>
              !isIP(a.address) ||
              ipaddr.parse(a.address).range() !== "loopback",
          ),
      )
    )
      fail("invalid_test_network");
  }
  static publicAddress(address: string): boolean {
    try {
      const p = ipaddr.parse(address);
      if (p.range() !== "unicast") return false;
      if (p.kind() === "ipv6") {
        const v = p as ipaddr.IPv6;
        return (
          !v.isIPv4MappedAddress() &&
          v.match(ipaddr.parse("2000::") as ipaddr.IPv6, 3) &&
          !v.match(ipaddr.parse("2001::") as ipaddr.IPv6, 23) &&
          !v.match(ipaddr.parse("2001:db8::") as ipaddr.IPv6, 32) &&
          !v.match(ipaddr.parse("2002::") as ipaddr.IPv6, 16) &&
          !v.match(ipaddr.parse("3fff::") as ipaddr.IPv6, 20)
        );
      }
      return true;
    } catch {
      return false;
    }
  }
  async request(
    url: string,
    options: {
      method?: "GET" | "POST";
      body?: string;
      headers?: Record<string, string>;
      timeoutMs?: number;
      mediaTypes?: readonly string[];
    } = {},
  ): Promise<Buffer> {
    const u = httpsUrl(url);
    if (this.inflight >= 8 || (this.origins.get(u.origin) ?? 0) >= 2)
      fail("temporarily_unavailable", 429);
    if (this.origins.size > 512 && !this.origins.has(u.origin))
      fail("temporarily_unavailable", 429);
    const timeout = options.timeoutMs ?? 10_000;
    if (!Number.isInteger(timeout) || timeout <= 0 || timeout > 10_000)
      fail("fetch_timeout");
    const deadline = AbortSignal.timeout(timeout);
    this.inflight++;
    this.origins.set(u.origin, (this.origins.get(u.origin) ?? 0) + 1);
    try {
      const host = u.hostname.replace(/^\[|\]$/g, "");
      const overridden = this.testNetwork?.addresses[host];
      const addresses =
        (this.testNetwork?.resolver
          ? await this.testNetwork.resolver(host)
          : overridden) ??
        (isIP(host)
          ? [{ address: host, family: isIP(host) }]
          : await Promise.race([
              lookup(host, { all: true, verbatim: true }),
              new Promise<never>((_, reject) =>
                deadline.addEventListener(
                  "abort",
                  () => reject(new ProtocolError("fetch_timeout")),
                  { once: true },
                ),
              ),
            ]));
      if (
        !addresses.length ||
        addresses.length > 32 ||
        addresses.some(
          (a) =>
            !isIP(a.address) ||
            (overridden
              ? !overridden.some(
                  (allowed) =>
                    allowed.address === a.address &&
                    allowed.family === a.family,
                )
              : !SafeHttpFetcher.publicAddress(a.address)),
        )
      )
        fail("unsafe_address");
      const selected = addresses[0]!;
      // The TLS socket uses only this checked address. No proxy or pooled socket is used.
      return await new Promise<Buffer>((resolve, reject) => {
        const req = https.request(
          u,
          {
            method: options.method ?? "GET",
            agent: false,
            signal: deadline,
            ca: this.testNetwork?.ca,
            servername: isIP(host) ? undefined : host,
            lookup: ((
              _hostname: string,
              opts: { all?: boolean },
              cb: Function,
            ) =>
              opts.all
                ? cb(null, [selected])
                : cb(null, selected.address, selected.family)) as never,
            headers: {
              accept: "application/json",
              "accept-encoding": "identity",
              ...options.headers,
            },
          },
          (res) => {
            const type = (res.headers["content-type"] ?? "")
              .split(";")[0]
              ?.toLowerCase();
            if (
              res.statusCode !== 200 ||
              !(options.mediaTypes ?? ["application/json"]).includes(
                type ?? "",
              ) ||
              (res.headers["content-encoding"] &&
                res.headers["content-encoding"] !== "identity")
            ) {
              res.destroy();
              reject(new ProtocolError("fetch_rejected"));
              return;
            }
            let size = 0;
            const chunks: Buffer[] = [];
            res.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size > 65536) {
                res.destroy(new ProtocolError("response_too_large"));
              } else chunks.push(chunk);
            });
            res.on("error", reject);
            res.on("end", () => resolve(Buffer.concat(chunks)));
          },
        );
        req.on("error", () => reject(new ProtocolError("fetch_failed")));
        if (options.body) req.write(options.body);
        req.end();
      });
    } finally {
      this.inflight--;
      const active = (this.origins.get(u.origin) ?? 1) - 1;
      if (active) this.origins.set(u.origin, active);
      else this.origins.delete(u.origin);
    }
  }
}
