# TypeScript controlled deployment

Run from `cimd-oauth-server/ts/`. Node 22.13+ is required; current evidence uses Node 22.23.1 on Linux. Registry dependencies and the exact resolved tree are locked. This is private source; no command below pushes an image or package.

## Build and isolated component verification

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
npm test
npm run test:postgres
```

`test:postgres` requires PostgreSQL server binaries and OpenSSL. It creates a fresh `/tmp/cimd-pg.*` cluster, listens only on its private Unix socket, creates an isolated database, runs the real migration, starts local test TLS/DNS servers, and removes the temporary cluster/certificates on exit. It does not reuse a host service or contact awiki.info. Override `POSTGRES_BIN_DIR` for another binary location. The default is `/usr/lib/postgresql/14/bin`. The test run must not point to a shared database; use the owning script.

The test CA and loopback address mappings exist only in test code. Production startup refuses test mode, test network configuration and disabled TLS checks. Tests are repository component evidence, not DSH/System Test/product E2E acceptance.

## Provision and start the two independent services

Configure public DNS and trusted TLS for the AS origin and MCP origin. CIMD/JWKS may be served by AWiki or an independent provider; their real DNS must resolve to allowed public addresses. Configure an HTTPS reverse proxy if binding the listeners only on loopback. AS issuer may be root or path-qualified; keep its string stable and omit trailing slash. Resource is the exact public MCP URL, not the well-known URL.

```sh
cp .env.example .env
chmod 600 .env
```

Edit the protected `.env`: replace all examples, provide independently random database and RS credentials, set public issuer/resource/introspection endpoint, choose explicit admission limits and record the accepted signing-key custody condition. For direct Node startup, `DATABASE_URL` refers to the runtime PostgreSQL role and `TLS_KEY_FILE`/`TLS_CERT_FILE` to actual PEM paths. A listener without TLS requires `ALLOW_LOOPBACK_PROXY=true` and a loopback bind; this permits a local reverse proxy without weakening outbound HTTPS policy.

Migrations and configuration use the administrative database role. Direct Node scripts read `.env`; exported environment values take precedence. Do not put credentials in shell history. Use a protected admin environment or temporarily select `DATABASE_URL` from a secret manager for these administrative commands:

```sh
npm run migrate
npm run configure
```

The configure script requires `ADMISSION_POLICY=open_basic`, nonempty explicit scopes, token TTL/quotas, all four prefetch limits and the key custody acceptance condition. It creates no per-client preregistration. Re-running it advances resource policy generation, invalidating previous tokens; use it as an intentional policy operation.

Create a runtime role without schema DDL. For example, as the database owner:

```sql
CREATE ROLE cimd_runtime LOGIN;
-- Set its password privately with psql \password or your secret manager.
GRANT CONNECT ON DATABASE cimd TO cimd_runtime;
GRANT USAGE ON SCHEMA public TO cimd_runtime;
GRANT SELECT ON schema_migrations,client_blocks TO cimd_runtime;
GRANT SELECT,UPDATE ON admission_policies,request_limits TO cimd_runtime;
GRANT SELECT,INSERT,UPDATE ON clients,machine_grants,access_tokens,rate_buckets TO cimd_runtime;
GRANT SELECT,INSERT ON metadata_snapshots,assertion_replays TO cimd_runtime;
GRANT INSERT ON audit_events TO cimd_runtime;
GRANT USAGE ON SEQUENCE audit_events_id_seq TO cimd_runtime;
```

Remove the administrative environment before starting AS. The application does not execute migrations. Start in separate terminals or process-manager units:

```sh
npm run start:as
npm run start:mcp
```

The MCP process needs only `OAUTH_ISSUER`, `INTROSPECTION_ENDPOINT`, `MCP_RESOURCE`, `OAUTH_SCOPES`, `RS_ID`, `RS_SECRET`, listener and TLS settings. It does not need `DATABASE_URL`. `/ready` checks AS schema/configuration for AS, and authenticated introspection connectivity for RS. Discovery endpoints remain publicly readable.

## Private local container reference

`Dockerfile` and `compose.yaml` pin public base images by version and digest. Registry manifest digests were checked on 2026-11-06. The image is built only as `cimd-oauth-server:local`. N5 已完成固定源码候选镜像构建及禁网 runtime/asset/fail-closed 检查，见 [候选镜像证据](n5-candidate-image.md)；配置完整的容器服务部署仍未执行。

Set `AS_TLS_DIRECTORY` and `RS_TLS_DIRECTORY` to directories readable by container UID 1000, each containing the appropriate `key.pem`/`cert.pem`. Configure the public reverse proxy to reach the loopback-mapped 8443/9443 ports; the RS still reaches the AS through its configured public HTTPS introspection origin. Internal Docker hostnames/private addresses are not an outbound network exception.

```sh
docker compose build as
docker compose up -d postgres
docker compose --profile setup run --rm migrate
```

Create the runtime role with the SQL above, privately set its password, and set `.env` `DATABASE_URL` to that role. `DATABASE_ADMIN_URL` remains restricted to setup services. Then:

```sh
docker compose --profile setup run --rm configure
docker compose up -d as rs
```

The RS container receives no database environment. No shared AWiki deployment, service restart or public publish is involved. For a configuration-only check with placeholders:

```sh
CIMD_ENV_FILE=.env.example docker compose --env-file .env.example config --quiet
```

## Independent identity publisher

This example owns only its isolated demonstration identity. Place its private state outside the repository, on a protected local volume. Supply `IDENTITY_STATE_DIR`, `IDENTITY_CLIENT_ID` and real public TLS/listener settings in a protected environment:

```sh
npm run identity:init
npm run start:identity
```

Initialization writes a new local ES256 private JWK with mode 0600 and refuses to overwrite it. The publisher exposes only the exact configured client metadata path and `/jwks.json`; it has no route for the private file and no signing API. DSH/A/C use their own approved local signer; this example is not an Agent-key hosting service.

## Administrative state and recovery

Use an admin database environment, never RS credentials. `CLIENT_ID` is the exact scoped identity; `GRANT_ID` is obtained from the operator's database view. Commands do not print secrets or supplied identifiers:

```sh
npm run admin -- block
npm run admin -- unblock
npm run admin -- disable-grant
npm run admin -- cleanup
npm run admin -- invalidate-recovery
```

Run cleanup periodically through your process manager. Keep bans and audit history; cleanup removes only expired protocol/cost state and tokens expired for more than a day. Before reopening restored data, follow [the recovery procedure](../../docs/security.md): invalidate policies/generations, reconcile trusted security facts, observe the full assertion window when replay completeness is unknown, and explicitly reconfigure policy only afterward.

需要显式组合本地 A/C/D 源码时，使用 [N2 native 组件入口](dsh-native-component.md)。它不替代普通 registry/发布验证，也不运行 System Test 或产品 E2E。

独立于 D 的标准客户端正向组件验证使用 `npm run test:independent-client`，见 [固定 oauth4webapi 组件证据](independent-client.md)。该 dev/test dependency 不进入服务运行时，且不替代独立 AS、System Test 或产品 E2E 验收。

独立 AS 产品的原生 CIMD/CC 组件使用 `npm run test:independent-as`；C/A→实际 D source→该独立 AS 的组合入口为 `npm run test:independent-as-native -- <identity source> <D source>`。见 [产品与夹具边界](independent-as.md)，正式 source 记录以对应 lane 最终证据为准。

真实默认 JWKS 传播窗口检查使用 `npm run test:cache-window`（实际约60秒，不改生产TTL），见 [S09时长与GET计数](cache-window.md)。

实际进程/备份恢复、真实C/B key旋转和共享PAP/MCP模块分别使用test:process-recovery、test:rotation-native与test:shared-protocol；证据见process-recovery.md、key-id-budget.md、shared-protocol.md。私有运行包使用npm run pack:runtime，按runtime-package.md运行built入口。
