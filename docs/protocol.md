# Machine profile contract

The standalone [PAP 0.3 hello demo](../ts/docs/pap-demo.md) shares CIMD/JWKS loading with this machine profile. It authenticates signed-out Sessions on a separate Company origin and does not use machine Access Tokens.

## Fixed surface

The issuer and resource are operator-configured HTTPS identifiers. Exact client identity strings are retained; URL parsing never merges two client identifiers. This reference policy limits URLs to ASCII URI form, 2048 bytes, explicit CIMD path, no userinfo/fragment/query/dot segments/backslash. Percent-encoded non-ASCII paths remain possible. JWKS must use the same HTTPS origin as CIMD; this is a local policy, not a claim that CIMD universally requires same-origin JWKS. Only public P-256 signing keys with unique nonempty `kid` are accepted. JWKS and assertion key IDs share the published 1024-character bound, reject blank/control-character values, and remain exact opaque strings; the 64 KiB document, eight-key and 16 KiB JWT limits remain independent.

`GET /.well-known/oauth-authorization-server` advertises only implemented machine capabilities. An issuer with `/tenant` uses `/.well-known/oauth-authorization-server/tenant` and `/tenant/oauth/*` endpoints. No endpoint URL is derived from Host or forwarded headers. `/.well-known/oauth-protected-resource/mcp` is the public metadata location for resource `/mcp`; longer resource paths retain their full suffix.

| Endpoint            | Request                                                                                                                                                                                                   | Result                                                                                       |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `/oauth/token`      | Form: `grant_type=client_credentials`, `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `client_assertion`, exactly one `resource`, explicit nonempty `scope` | Bearer opaque access token, bounded `expires_in`, always actual `scope`; never refresh token |
| `/oauth/introspect` | Independent RS `client_secret_basic`; form `token`, optional `token_type_hint`                                                                                                                            | RFC 7662 active state restricted to that RS's configured resources                           |
| `/oauth/revoke`     | Fresh client assertion, `client_id`, assertion type, `token`, optional `token_type_hint=access_token`                                                                                                     | 200 for unknown/unowned token; only authenticated owner's record can change                  |
| `/mcp`              | Header Bearer access token, standard Streamable HTTP MCP request                                                                                                                                          | Real SDK negotiation, tools/list and tools/call                                              |

Forms are bounded to 24 KiB and 12 fields; unknown, empty or duplicate fields fail. JWTs are bounded to 16 KiB. Assertions use ES256, unique selected `kid`, exact `iss=sub=client_id`, exact scalar `aud=issuer`, integer `iat`/`exp`, lifetime 1–60 seconds and a new nonempty bounded `jti`. Clock tolerance is 5 seconds. Embedded JWK, `jku`, `x5u`, alternate alg and ambiguous keys fail. Optional `typ` may be `JWT` or `client-authentication+jwt`. The latter is supported for draft-03 compatibility; legacy `JWT` remains accepted for the fixed local-signing profile.

Requested scopes are deduplicated and sorted. Every requested scope must fit the operator policy; the AS returns exactly that set or `invalid_scope`. No permission is added or silently removed. `resource` must match a registered policy exactly. A verified policy denial consumes replay state in a committed transaction without creating a successful machine subject, grant or token. Unparseable/unauthenticated input does not acquire an authenticated identity.

CIMD draft-02's singular `token_endpoint_auth_method` and draft-03's array `token_endpoint_auth_methods_supported` are supported. Draft-03 can advertise additional nonsymmetric methods, but this AS selects only `private_key_jwt`. When both fields exist, the singular value must be in the array. No symmetric-secret auth methods or key material may be published. Missing method means incompatible, with no public-client downgrade. Shared metadata can include PAP's implemented code/refresh/callback capabilities; they never cause this AS to implement those grants. CC-only `response_types=[]`/`redirect_uris=[]` is valid.

## RS trust and MCP lane

The RS trusts exactly its configured issuer and introspection endpoint, with separate RS credentials. It has no database access and never discovers a validation endpoint from the incoming token. Active results are not cached. It checks issuer when supplied, scalar audience equal to configured resource, expiration, machine subject and client ID, explicit scopes within its configured set. This reference AS/RS additionally agrees on `subject_type=client`; that is an application profile, **not** a required RFC 7662 field for all AS implementations. An independent AS requires an explicitly compatible trusted introspection profile.

MCP SDK is fixed at `@modelcontextprotocol/sdk@1.29.0`. Its actual wire lane uses `initialize`, with negotiated protocol `2025-11-25` in the independent SDK component test. It supports the SDK's older versions through its normal negotiation. This implementation does not claim the 2026 `server/discover` lane. The 2026-07-28 Client Credentials extension is a separately frozen authorization source, not a replacement wire-version string.

| Tool           | Required scope    | Trusted result                                                         |
| -------------- | ----------------- | ---------------------------------------------------------------------- |
| `identity_get` | `agent.self.read` | Verified client ID, stable machine subject, resource and actual scopes |
| `catalog_list` | `catalog.read`    | Fixed read-only sample items                                           |

`tools/list` filters by the same operation policy enforced on `tools/call`. Every actual JSON-RPC operation is authorized; a Header or tool argument cannot substitute the caller/owner. `initialize`, initialized notification and ping need a valid token but no extra tool scope. Unknown methods/tools and missing scope fail closed. Unauthenticated metadata remains public. Missing/invalid token gets 401 with `resource_metadata`; insufficient scope gets 403. MCP Origin, if present, must match the configured resource origin.

未修改上游 OAuth provider 的实际兼容限制见 [独立验证记录](../ts/docs/upstream-sdk-compatibility.md)。SDK MCP 消息互通通过不等于其 OAuth 动态或静态 provider 已取得 Token。
