import { loadClientMaterials, validKeyId, type Snapshot } from "./metadata.js";
import { calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from "jose";
import { SafeHttpFetcher } from "./fetch.js";
import { digest, httpsUrl, object, strictJson } from "./parse.js";
import { fail } from "./errors.js";
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
    const s = await loadClientMaterials(this.fetcher, clientId, (m) => {
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
    });
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
