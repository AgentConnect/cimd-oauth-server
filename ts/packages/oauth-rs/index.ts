import { SafeHttpFetcher } from "../oauth-core/fetch.js";
import { fail } from "../oauth-core/errors.js";
import { httpsUrl, object, scopes, strictJson } from "../oauth-core/parse.js";
const trusted = Symbol("verified-principal");
export type VerifiedPrincipal = Readonly<{
  [trusted]: true;
  issuer: string;
  clientId: string;
  subject: string;
  resource: string;
  scopes: readonly string[];
  expires: number;
}>;
export const TOOL_SCOPES: Readonly<Record<string, string>> = Object.freeze({
  identity_get: "agent.self.read",
  catalog_list: "catalog.read",
});
export class TokenVerifier {
  constructor(
    private readonly fetcher: SafeHttpFetcher,
    readonly config: {
      issuer: string;
      introspectionEndpoint: string;
      resource: string;
      rsId: string;
      rsSecret: string;
      allowedScopes: string[];
    },
  ) {
    httpsUrl(config.issuer);
    httpsUrl(config.introspectionEndpoint);
    httpsUrl(config.resource);
    if (!config.rsId || Buffer.byteLength(config.rsSecret) < 32)
      fail("invalid_rs_configuration");
  }
  private async introspect(token: string): Promise<Record<string, unknown>> {
    const c = this.config;
    const encoded = (s: string) => encodeURIComponent(s).replace(/%20/g, "+");
    try {
      return object(
        strictJson(
          await this.fetcher.request(c.introspectionEndpoint, {
            method: "POST",
            body: new URLSearchParams({
              token,
              token_type_hint: "access_token",
            }).toString(),
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              authorization: `Basic ${Buffer.from(`${encoded(c.rsId)}:${encoded(c.rsSecret)}`).toString("base64")}`,
            },
          }),
        ),
      );
    } catch {
      return fail("temporarily_unavailable", 503);
    }
  }
  async ready(): Promise<void> {
    const response = await this.introspect("readiness-probe-unknown-token");
    if (response.active !== false) fail("introspection_unhealthy", 503);
  }
  async verify(authorization: string | undefined): Promise<VerifiedPrincipal> {
    if (
      !authorization ||
      !/^Bearer [A-Za-z0-9._~+/-]{20,4096}={0,2}$/.test(authorization)
    )
      fail("invalid_token", 401);
    const c = this.config;
    const m = await this.introspect(authorization!.slice(7));
    if (
      m.active !== true ||
      (m.iss !== undefined && m.iss !== c.issuer) ||
      m.aud !== c.resource ||
      m.subject_type !== "client" ||
      typeof m.client_id !== "string" ||
      typeof m.sub !== "string" ||
      !m.sub ||
      !Number.isInteger(m.exp) ||
      (m.exp as number) <= Date.now() / 1000 ||
      typeof m.scope !== "string"
    )
      fail("invalid_token", 401);
    let actual: string[];
    try {
      httpsUrl(m.client_id as string);
      actual = scopes(m.scope as string);
    } catch {
      return fail("invalid_token", 401);
    }
    if (actual.some((s) => !c.allowedScopes.includes(s)))
      fail("invalid_token", 401);
    return Object.freeze({
      [trusted]: true as const,
      issuer: c.issuer,
      clientId: m.client_id as string,
      subject: m.sub as string,
      resource: c.resource,
      scopes: Object.freeze(actual),
      expires: m.exp as number,
    });
  }
}
export function authorizeOperation(
  principal: VerifiedPrincipal,
  method: string,
  tool?: string,
): void {
  if (principal[trusted] !== true || principal.expires <= Date.now() / 1000)
    fail("invalid_token", 401);
  if (
    [
      "server/discover",
      "initialize",
      "notifications/initialized",
      "ping",
      "tools/list",
    ].includes(method)
  )
    return;
  if (
    method === "tools/call" &&
    tool &&
    TOOL_SCOPES[tool] &&
    principal.scopes.includes(TOOL_SCOPES[tool]!)
  )
    return;
  fail("insufficient_scope", 403);
}
export function protectedResourceMetadata(
  resource: string,
  issuer: string,
  allowedScopes: string[],
): Record<string, unknown> {
  return {
    resource,
    authorization_servers: [issuer],
    scopes_supported: allowedScopes,
    bearer_methods_supported: ["header"],
  };
}
