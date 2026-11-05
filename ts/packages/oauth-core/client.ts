import { calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from "jose";
import { SafeHttpFetcher } from "./fetch.js";
import { digest, httpsUrl, object, strictJson } from "./parse.js";
import { fail } from "./errors.js";
// Match the shared publication contract while retaining bounded, exact key identifiers.
const MAX_KEY_ID_LENGTH = 1024;
function validKeyId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_KEY_ID_LENGTH &&
    value.trim().length > 0 &&
    !/\p{Cc}/u.test(value)
  );
}
const verified = Symbol("verified-client");
export type VerifiedClient = Readonly<{
  [verified]: true;
  issuer: string;
  clientId: string;
  thumbprint: string;
  metadataDigest: string;
  jwksDigest: string;
  metadataExpires: number;
  jtiDigest: string;
  issuedAt: number;
  expires: number;
}>;
type Snapshot = {
  keys: JWK[];
  metadataDigest: string;
  jwksDigest: string;
  expires: number;
};
export class ClientAuthenticator {
  private cache = new Map<string, Snapshot>();
  private pending = new Map<string, Promise<Snapshot>>();
  constructor(
    private readonly fetcher: SafeHttpFetcher,
    public readonly issuer: string,
    public readonly clockTolerance = 5,
  ) {
    httpsUrl(issuer);
  }
  private async resolve(clientId: string, refresh = false): Promise<Snapshot> {
    const cached = this.cache.get(clientId);
    if (!refresh && cached && cached.expires > Date.now() / 1000) return cached;
    if (this.pending.has(clientId)) return this.pending.get(clientId)!;
    const promise = this.load(clientId);
    this.pending.set(clientId, promise);
    try {
      return await promise;
    } finally {
      this.pending.delete(clientId);
    }
  }
  private async load(clientId: string): Promise<Snapshot> {
    const u = httpsUrl(clientId);
    if (u.search || !/^https:\/\/[^/?#]+\//i.test(clientId))
      fail("invalid_client", 401);
    const deadline = Date.now() + 10_000;
    const bytes = await this.fetcher.request(clientId, {
      timeoutMs: deadline - Date.now(),
    });
    const m = object(strictJson(bytes));
    if (
      m.client_id !== clientId ||
      typeof m.jwks_uri !== "string" ||
      httpsUrl(m.jwks_uri).origin !== u.origin ||
      m.jwks !== undefined ||
      m.client_secret !== undefined ||
      m.client_secret_expires_at !== undefined
    )
      fail("invalid_client", 401);
    const legacy = m.token_endpoint_auth_method;
    const modern = m.token_endpoint_auth_methods_supported;
    if (
      modern === undefined &&
      legacy !== undefined &&
      legacy !== "private_key_jwt"
    )
      fail("invalid_client", 401);
    if (
      modern !== undefined &&
      (!Array.isArray(modern) ||
        !modern.includes("private_key_jwt") ||
        modern.length > 8 ||
        modern.some(
          (v) =>
            typeof v !== "string" ||
            [
              "client_secret_basic",
              "client_secret_post",
              "client_secret_jwt",
            ].includes(v),
        ) ||
        new Set(modern).size !== modern.length ||
        (legacy !== undefined && !modern.includes(legacy)))
    )
      fail("invalid_client", 401);
    if (legacy === undefined && modern === undefined)
      fail("invalid_client", 401);
    if (
      m.token_endpoint_auth_signing_alg !== undefined &&
      m.token_endpoint_auth_signing_alg !== "ES256"
    )
      fail("invalid_client", 401);
    if (
      !Array.isArray(m.grant_types) ||
      !m.grant_types.includes("client_credentials")
    )
      fail("invalid_client", 401);
    const jwksBytes = await this.fetcher.request(m.jwks_uri as string, {
      timeoutMs: deadline - Date.now(),
      mediaTypes: ["application/json", "application/jwk-set+json"],
    });
    const jwks = object(strictJson(jwksBytes));
    if (!Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 8)
      fail("invalid_client", 401);
    const kids = new Set<string>();
    const keys: JWK[] = [];
    for (const raw of jwks.keys as unknown[]) {
      const k = object(raw);
      if (
        k.kty !== "EC" ||
        k.crv !== "P-256" ||
        typeof k.x !== "string" ||
        typeof k.y !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(k.x) ||
        !/^[A-Za-z0-9_-]{43}$/.test(k.y) ||
        !validKeyId(k.kid) ||
        kids.has(k.kid) ||
        ["d", "p", "q", "dp", "dq", "qi", "k"].some((s) => s in k) ||
        (k.alg !== undefined && k.alg !== "ES256") ||
        (k.use !== undefined && k.use !== "sig") ||
        (k.key_ops !== undefined &&
          (!Array.isArray(k.key_ops) ||
            k.key_ops.length !== 1 ||
            k.key_ops[0] !== "verify"))
      )
        fail("invalid_client", 401);
      await importJWK(k as JWK, "ES256");
      kids.add(k.kid as string);
      keys.push(k as JWK);
    }
    const s = {
      keys,
      metadataDigest: digest(bytes),
      jwksDigest: digest(jwksBytes),
      expires: Math.floor(Date.now() / 1000) + 60,
    };
    if (this.cache.size >= 256)
      this.cache.delete(this.cache.keys().next().value!);
    this.cache.set(clientId, s);
    return s;
  }
  async authenticate(
    clientId: string,
    assertion: string,
  ): Promise<VerifiedClient> {
    if (Buffer.byteLength(assertion) > 16384) fail("invalid_client", 401);
    const parts = assertion.split(".");
    if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p)))
      fail("invalid_client", 401);
    const header = object(strictJson(Buffer.from(parts[0]!, "base64url")));
    const claims = object(strictJson(Buffer.from(parts[1]!, "base64url")));
    if (
      header.alg !== "ES256" ||
      !validKeyId(header.kid) ||
      Object.keys(header).some((k) => !["alg", "kid", "typ"].includes(k)) ||
      (header.typ !== undefined &&
        !["JWT", "client-authentication+jwt"].includes(header.typ as string))
    )
      fail("invalid_client", 401);
    const now = Math.floor(Date.now() / 1000);
    if (
      claims.iss !== clientId ||
      claims.sub !== clientId ||
      claims.aud !== this.issuer ||
      typeof claims.jti !== "string" ||
      !claims.jti ||
      claims.jti.length > 256 ||
      !Number.isInteger(claims.iat) ||
      !Number.isInteger(claims.exp) ||
      (claims.exp as number) <= (claims.iat as number) ||
      (claims.exp as number) - (claims.iat as number) > 60 ||
      (claims.iat as number) > now + this.clockTolerance ||
      (claims.iat as number) < now - 60 - this.clockTolerance
    )
      fail("invalid_client", 401);
    let snapshot = await this.resolve(clientId);
    let key = snapshot.keys.find((k) => k.kid === header.kid);
    if (!key) {
      snapshot = await this.resolve(clientId, true);
      key = snapshot.keys.find((k) => k.kid === header.kid);
    }
    if (!key) fail("invalid_client", 401);
    await jwtVerify(assertion, await importJWK(key!, "ES256"), {
      algorithms: ["ES256"],
      issuer: clientId,
      subject: clientId,
      audience: this.issuer,
      clockTolerance: this.clockTolerance,
      requiredClaims: ["iat", "exp", "jti"],
    });
    return Object.freeze({
      [verified]: true as const,
      issuer: this.issuer,
      clientId,
      thumbprint: await calculateJwkThumbprint(key!, "sha256"),
      metadataDigest: snapshot.metadataDigest,
      jwksDigest: snapshot.jwksDigest,
      metadataExpires: snapshot.expires,
      jtiDigest: digest(claims.jti as string),
      issuedAt: claims.iat as number,
      expires: claims.exp as number,
    });
  }
}
