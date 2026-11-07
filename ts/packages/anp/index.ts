import {
  RequestVerifier,
  extractSignatureMetadata,
  type DidDocument,
  type DidResolver,
} from "@awiki/anp-typescript-sdk";
import { SafeHttpFetcher } from "../oauth-core/fetch.js";
import { fail } from "../oauth-core/errors.js";
import { httpsUrl, strictJson } from "../oauth-core/parse.js";

/** Resolve only public material. No server identity or signing key is required. */
export function publicDidResolver(fetcher: SafeHttpFetcher): DidResolver {
  return async (did) => {
    if (!did.startsWith("did:wba:")) fail("unsupported_did", 401);
    const parts = did.slice(8).split(":");
    const domain = decodeURIComponent(parts.shift()!);
    const path = parts.map((part) => {
      const value = decodeURIComponent(part);
      if (!value || value === "." || value === ".." || /[/\\?#]/.test(value))
        fail("invalid_did", 401);
      return encodeURIComponent(value);
    });
    const origin = httpsUrl(`https://${domain}`).origin;
    const url = `${origin}/${path.length ? path.join("/") : ".well-known"}/did.json`;
    const document = strictJson(await fetcher.request(url)) as DidDocument;
    if (document.id !== did) fail("invalid_did", 401);
    return document;
  };
}

export class AnpVerifier {
  private readonly verifier: RequestVerifier;
  constructor(resolve: DidResolver = publicDidResolver(new SafeHttpFetcher())) {
    this.verifier = new RequestVerifier({
      allowHttpSignatures: true,
      allowLegacyDidwba: false,
      requireNonceForHttpSignatures: true,
      didResolver: async (did) => {
        if (!did.startsWith("did:wba:")) fail("unsupported_did", 401);
        const document = await resolve(did);
        if (!document || document.id !== did) fail("invalid_did", 401);
        return document;
      },
    });
  }
  async verify(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array,
  ): Promise<Readonly<{ did: string }>> {
    try {
      const normalized = Object.fromEntries(
        Object.entries(headers).map(([key, value]) => [
          key.toLowerCase(),
          value,
        ]),
      );
      if (normalized.authorization) fail("invalid_signature", 401);
      const metadata = extractSignatureMetadata(normalized);
      const required = ["@method", "@target-uri"];
      if (body !== undefined) required.push("content-digest");
      if (required.some((name) => !metadata.components.includes(name)))
        fail("invalid_signature_coverage", 401);
      if (
        !Number.isSafeInteger(metadata.created) ||
        (metadata.expires !== undefined &&
          (!Number.isSafeInteger(metadata.expires) ||
            metadata.expires < metadata.created))
      )
        fail("invalid_signature_time", 401);
      const result = await this.verifier.verifyRequest(
        method,
        url,
        normalized,
        body,
      );
      return Object.freeze({ did: result.did });
    } catch {
      return fail("invalid_signature", 401);
    }
  }
}
