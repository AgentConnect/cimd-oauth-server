# I02 独立客户端正向组件证据

`oauth4webapi@3.8.8` 未修改上游库已完成对本参考 AS/RS 的正向互通：真实 RFC 8414 发现、ES256 `private_key_jwt`、`client_credentials` 表单和 Token 响应处理，然后使用官方 MCP SDK 调用 `identity_get` 与 `catalog_list`。陌生 HTTPS CIMD 在数据库无预建 client 时准入成功。执行入口为：

```sh
npm run test:independent-client
```

该入口复用本仓临时 PostgreSQL owner：新建 cluster/Unix socket/database、执行真实 migration、运行独立 test file，结束后清理。不会顺带执行原 owner 全套、D source/native lane、System Test、产品 E2E 或部署。

## 固定的独立实现与来源

本次新增的 `oauth4webapi` **仅为 dev/test dependency**，精确固定 `3.8.8`，没有修改它的代码、AS 机器 profile 或 DSH 身份规则。

| 来源                            | 固定值                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------- |
| Primary registry tarball        | `https://registry.npmjs.org/oauth4webapi/-/oauth4webapi-3.8.8.tgz`                                |
| SRI                             | `sha512-8N28E+a/oxfXWBgOMt+ZP/JUf/XR+IFbvkAEPP3gznXOMv9BpAAwiIj0TFNz3tGTPc0ZQ8zmWBNgN1nAys0gng==` |
| 官方 tag / commit               | `v3.8.8` → `916b97952dbf431d8b72f369840de54f5a286e4d`                                             |
| 已安装 `build/index.js` SHA-256 | `72a5f6d84416e92b659c6b8fd837c5fa38d44b7f2e18f91daa1fe57da677c7ad`                                |
| License                         | MIT；`LICENSE.md` SHA-256 `81e7b4b0196e8caa43cf243131512e5e4ab04fc312623335e783abae6ff46d79`      |
| 新 `package-lock.json` SHA-256  | `17060b6905a3f6d69b31c41042f608f1a6e0cf3a235443ab173dcf4023595ea6`                                |

Primary 依据为固定发行版的 [PrivateKeyJwt API](https://github.com/panva/oauth4webapi/blob/v3.8.8/docs/functions/PrivateKeyJwt.md)、[CC 请求 API](https://github.com/panva/oauth4webapi/blob/v3.8.8/docs/functions/clientCredentialsGrantRequest.md)、[发现 API](https://github.com/panva/oauth4webapi/blob/v3.8.8/docs/functions/discoveryRequest.md)及[精确 commit 源码](https://github.com/panva/oauth4webapi/blob/916b97952dbf431d8b72f369840de54f5a286e4d/src/index.ts)。实际源码默认 assertion audience 就是 AS issuer，期限就是 60 秒；正向用例无需 `modifyAssertion`。`PrivateKeyJwt({key,kid})` 自行设置 `client_id`、assertion type 和签名断言，`clientCredentialsGrantRequest` 自行设置 grant type。

## 实际链路与边界

外部非 DSH 客户端使用上游 `generateKeyPair('ES256')` 创建独立本地临时密钥；私钥仅存在于该测试进程内，public JWK/CIMD 经独立真实 TLS listener 提供。这不是 DSH key custody 或 A/C signer 的替代，也没有给 AS 增加 Agent 密钥托管/代签。

调用顺序为上游 `discoveryRequest({algorithm:'oauth2'})` / `processDiscoveryResponse` → `PrivateKeyJwt` → `clientCredentialsGrantRequest` / `processClientCredentialsResponse` → 官方 MCP SDK message transport。撤销同样由上游 `revocationRequest` / `processRevocationResponse` 构造和处理。没有调用 D `MachineAuthenticationSession`、E 自家 `tokenRequest`、手工补 client_id、伪造 authorize endpoint、预建 client 或修改上游源码。

`customFetch` 只承担测试网络传输：限定已配置的精确 AS/RS origins，固定实际 socket 到隔离 loopback、显式临时 CA 与 hostname 验证、禁用共享 agent、5 秒请求期限、24 KiB 请求/64 KiB 响应边界、manual redirect。它将上游参数原样发送到真实 HTTPS server，再把真实 status/header/body 转成标准 Response；不会修改表单、声明或 metadata，也不 mock 响应。观察仅保留字段名、公开绑定信息和 jti 摘要，不记录 Token、完整 assertion 或私钥。

实际观测到的 Token 表单恰好为 `client_assertion`、`client_assertion_type`、`client_id`、`grant_type`、`resource`、`scope` 六项；头部为 ES256 + 显式 kid，iss/sub 与 client_id 相等、aud 为精确 issuer、exp−iat 为 60 秒。AS metadata 没有 authorization endpoint，仍由上游成功处理。

## 当前通过结果

2026-11-06，Linux / Node 22.23.1 / 独立 PostgreSQL 14：**4 子项及父项，TAP 5/5 通过**。

1. 首次陌生 CIMD 准入，实际 Bearer/TTL/scope、无 refresh token；数据库唯一机器主体；官方 SDK initialize、tools/list 和两个 tools/call 成功。
2. 实际配置 3 秒 Access Token TTL，等待超过期限，旧 Token 内省 inactive、MCP 拒绝；新的上游 CC 请求得到新 Token、新 iat/exp/jti，机器 subject 保持不变。
3. 未授权 resource 和账户 scope 拒绝；仅为负向向量使用上游官方 `modifyAssertion` hook，重复 jti、过期断言、错误 audience 均拒绝；Token 不能用于另一 resource 的 RS verifier。
4. 另一个真实签名客户端不能撤销原客户端 Token；原 owner 上游标准撤销后 Token inactive、MCP 拒绝。成功请求的 jti 摘要互不重复，拒绝没有额外创建机器主体。

干净 primary registry `npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org`、`typecheck`、`build`、`format:check` 均通过。未运行无改动的其他 owner suites。

原 [SDK 1.29 动态/静态 OAuth provider 的真实不兼容证据](upstream-sdk-compatibility.md)保持不变。独立客户端正向通过与那个负向结果分别记录；本结果不代表已验证另一个独立 AS，也不代表 System/产品 E2E 或线上接入。

[N5 b65 候选镜像](n5-candidate-image.md)和其旧锁/source/provenance 保留为历史事实，本次没有重建或重新标记镜像。旧镜像固定 b65e5b3 与旧 lock `f7a5fc3…36f23`，不包含本次 dev dependency 或新测试；不能把它宣称为当前新锁/新 source 的镜像。
