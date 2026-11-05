# N2：真实 C/A → D → E 组件链

这条 owner 组件链使用真实 C Context 和 ANP Identity native signer，由官方 D `MachineAuthenticationSession` 完成发现、私钥断言、标准 Token 表单和资源认证，再经 E 的真实 TLS AS/RS、独立 PostgreSQL 事务与官方 MCP SDK 调用 `identity_get`、`catalog_list`。没有构造假 Token，没有调用 E 既有测试的 `tokenRequest`，没有绕过 D 的凭据存储或认证流程。

执行入口：

```sh
npm run test:dsh-native -- /absolute/path/to/anp-identity-source /absolute/path/to/deepseek-harness-source
```

与 `test:postgres` 共用临时 PostgreSQL owner 入口：新建 `/tmp/cimd-pg.*` cluster、仅私有 Unix socket、执行真实 migration、结束时停止并清理。该选项只执行新的 source integration script，不顺带重跑 owner PostgreSQL 套件。需要 OpenSSL、PostgreSQL binaries、源码各自所需的既有 dependencies，以及准确的已构建 native addon。

脚本显式使用 Harness 的 `tsconfig.base.json` source face。首次尝试未指定 source face 时，D `machine-store.ts` 的 `@deepseek-ai/dsh-subprocess` package main 指向未构建 `lib/index.js`，因此在任何协议请求前停止；按 D owner 指定的 `tsx --tsconfig` 入口改为真实源码解析，没有生成假 lib、安装本地替代产品依赖或改变正式 E registry lock。此为授权的本地源码组件证据，不是 registry 安装/发行验证。

组件过程及断言：

1. C helper 新建真实 native ES256 身份，使用本机临时加密状态，建立真实 installed caller Context 和显式 `mcp_machine` policy。
2. 仅发布 fixture 的 MCP machine 能力；`grant_types=[client_credentials]`，`response_types=[]`、`redirect_uris=[]`。原始 metadata/JWKS 在独立 TLS listener 发布，E resolver 实际抓取；native 公文档包含唯一 ANPCIMD URL 和匹配的原始 metadata SHA-256。
3. PostgreSQL 最初没有 client 行。D 通过资源 metadata、AS metadata 发现真实端点，经 C/A native 签断言并自己获取 Token。
4. 官方 SDK 使用 `session.fetch` 完成 initialize、tools/list、两个 tools/call。identity 工具返回的机器 subject 与 PostgreSQL 唯一主体一致，catalog 返回两个只读样例。多个 MCP 请求复用一个 Token，本链只发生一次 Token 请求。
5. D 本地 credential 文件权限为 0600，持久内容包含 AES-GCM 密文/iv/tag，不含明文 token 字段。
6. 第二个 D session 请求 `account.profile.read`，由 C 的实际 scope policy 在 Token 请求前拒绝，AS Token 请求计数不增加。
7. `dispose(true)` 经 C/A 使用新断言向 E 发起标准撤销，E 更新真实 Token 行，D 状态为 remote revocation confirmed；本地持久 disabled fence 生效且密文清空，后续 fetch 拒绝。
8. 输出已脱敏 JSON，记录 source commit/dirty、关键代码前后不变的 SHA-256、native addon digest、调用/撤销计数及实际证据边界，不记录 assertion、Token、私钥、RS secret 或本地主密钥。

测试网络例外仅在 `NODE_ENV=test` 使用：每个 AS/RS origin 分别建立 A/D 的 `createTestMachineFetch({origin,ca})`，dispatcher 只允许两个预先配置的精确 origin。证书包含 localhost/127.0.0.1，实际连接仍是 DNS 绑定与 TLS 校验；E 的独立公开材料 fetcher 也仅使用显式本地测试地址和临时 CA。没有占用共享 443 端口或修改系统 DNS/证书。

边界必须保留：C helper 的 publication prepare/activate/发布确认是显式 fixture，不代表 B 的真实控制面、外部域名、线上 DID 发布或 read-back 验收；原生密钥保管使用隔离注入测试根密钥，D credential master 由测试 credentials fixture 提供，不代表真实 OS keyring。C 接受的是 Host 明确配置的可信 D adapter Context 的受保护发现证据，并独立检查 policy/TTL/profile/scopes/publication generation；本链不宣称 C 再次从网络抓取 discovery。AS/RS 是不同 TLS listener/origin，仍处于本机组件进程，不是正式多进程部署。System Test、产品 E2E、公开 SDK registry 发行和远程部署均未执行。

未修改官方 SDK 1.29.0 动态/静态 OAuth provider 的不兼容证据继续保留在 [独立兼容记录](upstream-sdk-compatibility.md)。本链通过的是项目明确实现的 D machine profile，与原上游 provider 完整 OAuth 发现结果分别记录。

## 2026-11-06 当前执行结果

完整脚本通过，输出 `passed=true`，lane 为 `real-C-context-A-native-D-machine-E-TLS-Postgres-MCP`。工具为 `identity_get` / `catalog_list`，标准 Token 请求 **1** 次，确认远端撤销 **1** 次；唯一机器主体、0600 加密本地凭据、C scope policy 在 Token 前拒绝与断开后的持久禁用围栏全部通过。

执行时 Identity source HEAD 为 `8ff4042ef3fa159c89d51007cd3b78d23d5ddceb`，Harness source HEAD 为 `f58a0ee2b5496911516264c63acff39ef88ae35b`；两者均如实输出 `SourceDirty=true`，因为 A/C/D 正在同一授权开发窗口收尾。证据绑定下面的实际源文件摘要，并在导入前及整条验证完成后比较一致；不是仅用旧 HEAD 冒称新实现已提交。A owner 随后确认 `dNetwork` 为最终生产源码摘要，不再修改该文件。

| 输入                         | SHA-256                                                            |
| ---------------------------- | ------------------------------------------------------------------ |
| Native addon                 | `e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef` |
| D machine-auth.ts            | `cd41bc82e629821d9f7c887ee4f93535c2fc42753f02b9324e4bb3b61db4d63b` |
| D machine-http.ts            | `27585977ff2a2e8828e8574af7c030059f0e77bf30beffa2d31d10a1e635841b` |
| D machine-store.ts           | `e375f492f8d46565e65d43d7ba84019069474e71cd74e4eac77642bc8bb867d2` |
| D machine-discovery.ts       | `1dccfc5395ce144cb196fb6485b19447b91105a5ac36e853344d619e683f828f` |
| Harness tsconfig.base.json   | `7ad5e6e3aec49257deb1ec78776955bf18d7e7df8a71bff6558561c34be5cc6f` |
| C native-protocol-fixture.ts | `df4e29f10b99857a272a6f079583e4fc53ccd78f441ec116c69964812f775869` |
| C target-policy.ts           | `2c910eed25fad4922d3903f535c8d77f7b60ea777a6a3c1a2dc77a92920d1856` |
| C index.ts                   | `4a4df172c789cea52174e3d188854be8fe71306e8eb381e5f3e0046275181f05` |
| C publication.ts             | `b932de70da290718d97a33aa3f70184adfdffe45770bac380c133adba687cf5d` |

原有 E PostgreSQL owner 套件没有为该新 lane 顺带重跑；其当前产品源码验证仍为提交前有效期修正后的 TAP 17/17。新 lane 实际复用同一独立 PG migration/cleanup 入口。由于 TLS helper 为 localhost 增加了 SAN，相关 `npm test` 9/9 本轮重新通过；`typecheck`、`build`、`format:check` 也通过。正式 registry lock 与 migration 均未更改。
