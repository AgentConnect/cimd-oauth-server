import { importJWK, type JWK } from "jose";
import { SafeHttpFetcher } from "./fetch.js";
import { digest, httpsUrl, object, strictJson } from "./parse.js";
import { fail } from "./errors.js";
// Match the shared publication contract while retaining bounded, exact key identifiers.
const MAX_KEY_ID_LENGTH = 1024;
export function validKeyId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_KEY_ID_LENGTH &&
    value.trim().length > 0 &&
    !/\p{Cc}/u.test(value)
  );
}
export type Snapshot = {
  keys: JWK[];
  metadataDigest: string;
  jwksDigest: string;
  expires: number;
};

/** Shared public CIMD/JWKS loading; grant requirements belong to the caller. */
export async function loadClientMaterials(
  fetcher: SafeHttpFetcher,
  clientId: string,
  validateMetadata: (metadata: Record<string, unknown>) => void = () => {},
): Promise<Snapshot> {
  const u = httpsUrl(clientId);
  if (u.search || !/^https:\/\/[^/?#]+\//i.test(clientId))
    fail("invalid_client", 401);
  const deadline = Date.now() + 10_000;
  const bytes = await fetcher.request(clientId, {
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
  validateMetadata(m);
  const jwksBytes = await fetcher.request(m.jwks_uri as string, {
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
  return s;
}
