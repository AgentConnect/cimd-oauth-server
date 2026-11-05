# Current repository verification evidence

Execution date: 2026-11-06, Linux x86_64. Node 22.23.1, npm 10.9.8, TypeScript 5.9.3; isolated PostgreSQL 14 server binaries. All new source/configuration is under `ts/`; no deployment or shared-service change occurred.

| Command                                                                            | Current result                                    | Scope                                                                                                                    |
| ---------------------------------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `npm ci --ignore-scripts --no-audit --no-fund`                                     | Passed                                            | Exact registry lock installation; no lifecycle publish/test hook                                                         |
| `npm run typecheck`                                                                | Passed                                            | Core, PostgreSQL store, AS, RS, examples, scripts and tests                                                              |
| `npm run build`                                                                    | Passed                                            | JavaScript output and real migration asset copied into `dist/`                                                           |
| `npm run format:check`                                                             | Passed                                            | Maintained TypeScript/config/docs formatting                                                                             |
| `npm test`                                                                         | 9 passed, 0 failed                                | Closed parsers, URL/IP rules, B public fixtures, real HTTPS/UDP DNS boundaries and JOSE                                  |
| `npm run test:postgres`                                                            | 16 child cases + parent passed (TAP 17), 0 failed | Fresh PostgreSQL, real migrations, two independent pools, real HTTPS AS/RS listeners and independent official SDK client |
| `CIMD_ENV_FILE=.env.example docker compose --env-file .env.example config --quiet` | Passed                                            | Compose syntax/interpolation only; no containers started                                                                 |

Core/network coverage includes duplicate nested/escaped JSON names, invalid UTF-8/BOM, form duplicates/unknown fields/malformed escapes, explicit scope normalization, path-qualified discovery, special-use IPv4/IPv6, prod refusal of test exceptions, public CIMD digest preservation, B's five shared capability combinations, draft-02/03 method compatibility/conflicts, wrong iss/sub/scalar aud/time/jti/header, unknown-kid bounded refresh, duplicate/private JWKs, redirects, oversized/compressed responses and TLS hostname validation. An actual UDP DNS server returns a permitted address and then a changed/mixed answer: the request never resolves twice for its socket, and the changed/mixed candidates are rejected before another HTTP request.

PostgreSQL/HTTP/MCP cases（另含未修改上游 OAuth provider 的预期兼容失败回归；详见 [兼容证据](upstream-sdk-compatibility.md)）:

1. Unknown client standard first token request, stable machine subject and digest-only access token.
2. Near-limit random client/resource/scope combinations; fixed grant digest avoids oversized PostgreSQL composite indexes and canonical scope sets reuse one grant.
3. Two HTTPS providers, different ES256 keys and draft metadata methods accepted by the same admission policy.
4. Actual JWKS key rotation keeps machine subject; previously issued token remains valid until its independent expiry/revocation/generation rule.
5. Eight concurrent first visits through two pools yield one subject; same jti succeeds once, including cross-resource reuse rejection.
6. Verified invalid-scope denial commits replay without creating client/grant/token.
7. Official SDK `initialize → tools/list → tools/call`; catalog-only token cannot call identity tool, forged owner argument does not alter identity, assertion cannot act as access token.
8. Independent RS authentication, unauthorized resource inactive, wrong issuer, broken introspection source and AS errors fail closed.
9. Owned/unowned token revocation and replay of a revocation assertion.
10. Client ban/issuance race, grant disable, policy generation and new store instance preserve refusal.
11. Cross-pool prefetch budgets reject before metadata access; rejected global limit does not allocate a new client bucket; cleanup removes expired minute/hour state while preserving live buckets and bans.
12. Real PostgreSQL COMMIT succeeds, a test transport wrapper drops only its receipt; no store retry occurs, same assertion cannot issue again, new assertion reuses the one subject.
13. Expired token, malformed-scope authenticated replay and explicit recovery disable/generation checks.
14. Wrong signature creates no machine subject.

A Buffer BOM bypass found by H was corrected with `TextDecoder(ignoreBOM:true)` and a raw `EF BB BF` Buffer test.

Observed failures were corrected before the current passing runs: Node 22 lookup callbacks can request `all=true` and require address arrays; rate-bucket SQL needed explicit bigint casts; minute/hour bucket cleanup now uses explicit expiry. Long tuple-index risk was removed with a SHA-256 canonical grant key while preserving exact fields and an integrity check.

These tests use in-process component fixtures and separate TLS listeners/origins, not full product E2E and not remote acceptance. AS/RS production startup commands are independent; multi-process production deployment and Docker image build have not been exercised. The COMMIT-loss case is explicit fault injection against a real committed transaction, not a network partition drill. Recovery validation checks refusal/generations, not a full backup restoration. The B compatibility fixture is synthetic/public and does not prove a live AWiki publication or DID binding.

Not run: System Test, DSH Web/product E2E, DSH↔this AS live acceptance, other-platform tests, remote deployment/restarts, Docker build/container acceptance, external independent-AS acceptance, production custody review, full backup/restore drill or public/private registry publication. These are outside this component task's authorization or require H-owned controlled acceptance inputs. No HTML report was generated for ordinary component checks. Tests never point to awiki.info or a shared database, and no token/assertion/private key/RS secret is written to logs or Git.

The official upstream dynamic/static OAuth provider auth attempts fail on real CC-only metadata. Lower-level unmodified fetchToken diagnostics also fail because both providers omit explicit client_id; dynamic JWT additionally omits kid. These expected-failure assertions pass as compatibility regression checks, but neither OAuth provider leg is a successful independent authentication acceptance. See the dedicated compatibility evidence for primary registry SRI and exact source digests.

## 提交前有效期修正（2026-11-06）

H review 发现：旧候选 `8aa12e6` 在 replay 阶段检查有效期后，可能等待 PostgreSQL 政策行锁直到 metadata/assertion 已过期，随后仍提交 Token。已用真实 PG `FOR UPDATE` 锁复现：有效期仅剩约一秒，观察 `pg_stat_activity` 确认政策锁等待，过期 50ms 后释放，旧代码仍返回 Bearer。该旧候选及其交付包已作废。

现在 `issue`、`revoke`、`rejectVerified` 将 VerifiedClient 绑定到事务，并在所有 SQL 工作及锁等待之后、发送 COMMIT 前同步检查 issuer、metadata 到期、assertion 到期含固定 5 秒容差及未来 iat 窗口。检查失败抛 invalid_client 并原子回滚，不返回 Token，也不保留该事务产生的 replay/client/grant/token/metadata/audit 或撤销修改。

新增用例分别使用真实政策行锁、Token 行锁和 audit 表锁，覆盖 metadata 到期、真实签名 assertion 接受窗口到期、撤销和已认证拒绝的到期回滚；正常有效的 invalid_scope 拒绝仍提交 replay。修后 `npm run test:postgres` 为 16 子项及父项共 TAP 17/17；`npm run typecheck`、`npm run build`、`npm run format:check` 通过。本修正未改 lock、migration 或网络解析代码，unit/network 9/9 沿用前次对应源码通过结果；没有为日志重复运行。
