# PAP 0.3 unattended hello demo

This example implements PAP 0.3 signed-out Sessions. After Host identity and
operation permission setup, the Agent discovers OpenAPI and calls hello without
a browser, user account, Access Token or OAuth authorization server. A verified
Session identifies the Agent and its pairwise User; it grants no account access.

## Start

Run from `ts/` after `npm ci --ignore-scripts`. Configure an independent HTTPS
origin and TLS files in the protected environment (the usual loopback reverse
proxy option from the quickstart is also supported):

```sh
PAP_ORIGIN=https://pap-demo.example PORT=9444 npm run start:pap
```

`PAP_ORIGIN` is the externally visible canonical HTTPS origin, without a trailing
slash. TLS uses the existing `TLS_KEY_FILE` / `TLS_CERT_FILE` configuration. The
demo accepts any client with a valid ES256 PAP delegation and request signature.
It stores Session continuity and short-lived replay records in memory; a restart
clears this state. Use a single process for this demo.

| Endpoint                      | Purpose                                                           |
| ----------------------------- | ----------------------------------------------------------------- |
| `GET /.well-known/poppy.json` | PAP 0.3 Company and OpenAPI discovery                             |
| `GET /openapi.json`           | OpenAPI 3.1 operation `demo.hello`                                |
| `GET /api/hello`              | Requires `Poppy-Session`; returns hello and `authenticated: true` |

OAuth discovery returns 404. Clients create Sessions by making a signed API
request; the Company does not issue a Session token. Invalid Sessions return
HTTP 400 with `invalid_session`. The verifier checks the identity-signed
Delegation, delegated request signature, Company/method/URL, time window and
stable User/Agent identity for each client/sid. Request `htu` excludes query and
fragment, and signed-out requests omit `ath`. Each request has a fresh `jti`.

CIMD/JWKS loading, HTTPS address checks and ES256 verification dependencies are
shared with MCP. MCP's grant and client authentication requirements remain in
its own authenticator. The original AS/MCP commands and storage are independent.

## Verify with the real DSH PAP engine

```sh
npm run typecheck
node --import tsx --test tests/pap-session.test.ts
npm run test:pap-demo
```

The demo runner defaults to sibling `anp-identity` and `dsh-pap` source checkouts.
Set `PAP_DEMO_IDENTITY_SOURCE` and `PAP_DEMO_PAP_SOURCE` to use other absolute
source roots. Install their locked dependencies first; the identity checkout
must contain its matching native Node binding. The runner uses the real shared
identity service, its local native signer and the actual PAP engine. A local
publication fixture serves public CIMD/JWKS, so this is component compatibility
evidence, not User Service registration or deployed GUI acceptance.

The runner creates private temporary state and a TLS certificate, uses explicit
test-only DNS/TCP mapping with certificate verification, and removes all owned
listeners and temporary state. It verifies discovery, two fresh signed requests
with one Session, missing-header rejection and NoAS metadata absence. No model
API is used and no JWT, key or private User/Session identifier is printed.

Protocol baseline: [PAP 0.3 sections 3, 5 and 7](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/6fb46d381ac1b94265795132af13848ec442b6f6/content/versions/0.3/spec.mdx).
