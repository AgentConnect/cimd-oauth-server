# Three-protocol Service Agent

The public Apache-2.0 repository is now `AgentConnect/service-agent` (formerly
`cimd-oauth-server`). Existing AS, MCP and standalone PAP commands remain usable.
The repository-root package exposes the combined app, website services and
runtime; the original TypeScript project remains under `ts/`.

## Combined website service

One process hosts ANP HTTP signatures, CIMD machine OAuth MCP and PAP 0.3
signed-out Sessions. All adapters invoke the same list/read/message functions.
ANP requires no server DID or signing key and issues no access token. The ANP
adapter uses the published `@awiki/anp-typescript-sdk@0.9.4`, requires method/URL
coverage and body digests, and retains SDK binding/time/nonce verification.

From `ts/`, install dependencies, run `npm run migrate` and `npm run configure`
using the existing protected configuration. For the combined service set:

```dotenv
SERVICE_ORIGIN=https://agent-network-protocol.com
OAUTH_ISSUER=https://agent-network-protocol.com
MCP_RESOURCE=https://agent-network-protocol.com/mcp
INTROSPECTION_ENDPOINT=https://agent-network-protocol.com/oauth/introspect
OAUTH_SCOPES=protocol.read message.write
PROTOCOL_CATALOG_FILE=/absolute/path/to/protocol-catalog.json
```

Also set `DATABASE_URL`, `RS_ID`, `RS_SECRET`, admission limits and the explicit
`open_basic` policy as documented in quickstart. Configure TLS, or use an explicit
loopback proxy listener (`ALLOW_LOOPBACK_PROXY=true`, `BIND_HOST=127.0.0.1`). Nginx
must preserve the canonical Host and original path/query, and route OAuth metadata,
OAuth endpoints, `/mcp`, `/anp/`, `/pap/`, `/agents/official/ad.json` and the two
protocol discovery documents to this process. Do not rewrite signed paths.

Run `npm run start:combined`; built installations use `start:combined:built`.
The website builds the catalog from its versioned Markdown before startup. A
missing version/document returns 404; there is no latest-version substitution.
Messages are saved in PostgreSQL before a receipt is returned. This single-process
demo permits valid ANP and signed-out PAP identities to read and leave messages;
MCP tools additionally require `protocol.read` or `message.write` respectively.

PAP discovery stays public and advertises no account AS. The root protected-resource
metadata remains absent, while MCP metadata lives at
`/.well-known/oauth-protected-resource/mcp`. Presence of the machine AS does not
turn PAP into an account flow.

## Module API and verification

- `@agentconnect/service-agent`: `createServiceAgent`, service types and OpenAPI.
- `@agentconnect/service-agent/website`: catalog builder and PostgreSQL-backed
  `createWebsiteServices`.
- `@agentconnect/service-agent/runtime`: `startServiceAgent` and `startWebsite`.

`npm run typecheck` and `npm run build` run in either the repository root or TS
project. From `ts/`, `bash scripts/test-postgres.sh --website` creates and removes
an independent PostgreSQL instance and verifies all three protocols over HTTPS,
including the actual machine token/introspection path and persistent messages.
`node --import tsx --test tests/anp.test.ts tests/mcp-negotiation.test.ts tests/pap-session.test.ts`
covers ANP rejection paths and existing MCP/PAP compatibility. These are component
checks, separate from native Host and deployed website acceptance.

The native cross-repository check is `npm run test:website-native` from `ts/`.
It loads the actual dsh-anp plugin in a Cordis consumer context, approves the
request through the existing identity manager, exercises all four tools and
verifies revocation prevents a later message. The same native identity supplies
PAP Delegation/Session proofs and the MCP client assertion through C. Public
DID/CIMD publication and network mapping are isolated test fixtures; this is not
User Service registration, a browser UI check or a deployed-host result.
