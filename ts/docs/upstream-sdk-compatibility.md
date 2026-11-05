# 官方 SDK OAuth provider 兼容证据

本记录区分官方 SDK 的 MCP 消息互通与其 OAuth provider 互通。当前真实 TLS / PostgreSQL 下，SDK `Client` + `StreamableHTTPClientTransport` 的 initialize、工具列表和两工具调用已经通过；**未修改的 SDK 1.29.0 OAuth provider 尚未与本参考 AS 正向互通**。下面的预期失败回归通过，不等于 OAuth 获取 Token 成功。

执行：`npm run test:postgres` 中 `unmodified upstream dynamic/static JWT providers expose frozen-profile interoperability limits`。真实 AS/RS/陌生 HTTPS CIMD 均使用隔离环境；未修改上游文件，未伪造 Token、authorization endpoint 或标准表单字段。

| 实际路径                                          | 配置                                                                                         | 实际结果                                                                                                                                          |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 上游 `auth(PrivateKeyJwtProvider)` 完整发现       | HTTPS URL client ID、ES256 私有 JWK、60 秒、两个 scope；audience 使用真实 AS metadata issuer | 在任何 Token 请求前，`OAuthMetadataSchema` 因缺 `authorization_endpoint` 和 `response_types_supported` 抛出 ZodError；没有 Token，没有创建 client |
| 上游 `auth(StaticPrivateKeyJwtProvider)` 完整发现 | 独立标准 `jose.SignJWT` 生成带 kid、精确 iss/sub/aud、新 jti、60 秒的单次断言                | 同样在完整发现阶段失败，没有 Token，没有创建 client                                                                                               |
| 上游底层 `fetchToken(dynamic)` 诊断               | 直接传入从真实 AS GET 得到且未补字段的 metadata；由上游生成表单与 JWT                        | 实际表单缺 `client_id`，JWT header 另缺 kid，AS 返回 invalid_client；audience 为精确 issuer、lifetime 为 60 秒                                    |
| 上游底层 `fetchToken(static)` 诊断                | 传同一真实 metadata；带 kid 合规断言由外部标准库产生后交上游 static provider                 | 上游表单仍缺 `client_id`，AS 返回 invalid_client；未重用静态断言或自家 tokenRequest 补字段                                                        |

底层诊断显式绕过的仅是上游 metadata **schema 调用层**，不是完整发现成功；它用于定位第二个兼容限制，不计作产品或独立 OAuth 验收。请求观察只保存字段名、kid 是否存在、audience 是否精确和生命周期，不记录 assertion、Token、私钥或 Authorization Header。

上游来源为 primary npm registry 的 `@modelcontextprotocol/sdk@1.29.0`：

- Tarball: `https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.29.0.tgz`
- SRI: `sha512-zo37mZA9hJWpULgkRpowewez1y6ML5GsXJPY8FI0tBBCd77HEvza4jDqRKOXgHNn867PVGCyTdzqpz0izu5ZjQ==`
- `dist/esm/client/auth.js` SHA-256: `05dbfcb1da2e99e17034e61d36bdc5c7ac8e546740865d84e218208187de0917`
- `dist/esm/client/auth-extensions.js` SHA-256: `dfbba8290dcd3aa7d69bb23eab6bf7424c2e2d0b4b6e14f11d941c3e61a1d4ef`
- `dist/esm/shared/auth.js` SHA-256: `70c91ecdc56d2aaff6181f1a59243e4c692cd65e23d66b390515682c662b282e`

主机原有 npm 默认 registry 为镜像站；E 在独立任务中向 primary npm registry 逐一核验 155 个 lock 条目的版本、SRI 和 tarball URL，全部一致后将 lock 的 resolved 规范为官方地址，使用官方 registry 干净 `npm ci` 通过；未修改用户共享 npm 配置。

本 AS 不广告没有实现的 authorize 路由或 response type。[RFC 8414 §2 / §3.2](https://www.rfc-editor.org/rfc/rfc8414.html)允许没有相应 grant 的 AS 省略 authorization endpoint，并规定空数组不输出。共享 CIMD 的 CC-only `response_types=[]` 是另一对象的发布契约，不应混同 AS metadata。

AS 冻结的显式 `client_id`、唯一有效 `kid`、60 秒断言和真实资源约束保持不变。后续若要支持这些上游 provider，须在单独消费端变更中明确处理官方实现缺项，或等待上游修复；不得将此次失败改称完整 OAuth 互通。静态 provider 的任何后续重取都必须生成新断言并建立新 provider，不复用静态 assertion。
