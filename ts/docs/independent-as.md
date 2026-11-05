# I02 独立 AS 产品组件：oidc-provider 9.13.3

本 lane 使用未修改的成熟 AS 产品库 `oidc-provider@9.13.3`。CIMD 获取与缓存、client authentication、ES256 JWT 校验与 replay、Client Credentials grant、Token 模型、内省和撤销均执行它的原生实现，不调用本仓 `oauth-as`、CIMD resolver、PostgreSQL store 或 Token handler，也不自写这些协议核心。

## 固定来源与产品代码边界

- Primary tarball：`https://registry.npmjs.org/oidc-provider/-/oidc-provider-9.13.3.tgz`。
- SRI：`sha512-WmNDX9dLeItBmIqGqspmX5u6Cc7VVMrKUw2InX2T16+bwUJ8m/N5rJ3Ed+YKxE5aZqLp4YqwEi6kMJx4Ui5ffw==`。
- 官方 tag `v9.13.3` 固定 commit：`7b21c6da77f61fb66adfec72e0d8247dda7248e6`。
- MIT；`LICENSE.md` SHA-256 为 `4cede26713cb397575e3dcf844b098ad3a879e6688899b1be0c26b205403e810`。
- 仅新增 dev/test dependency，不加入 AS/RS 运行时依赖；当前 lock SHA-256 为 `ccc0f1d143b76a4a68402a8091bc04346496f520f8860495e1bbb376d09e770d`。

固定 primary 源码关系：[`token.js`](https://github.com/panva/node-oidc-provider/blob/v9.13.3/lib/actions/token.js) 使用 [`shared/client_auth.js`](https://github.com/panva/node-oidc-provider/blob/v9.13.3/lib/shared/client_auth.js)；后者原生调用 `provider.Client.find`，在 [`models/client.js`](https://github.com/panva/node-oidc-provider/blob/v9.13.3/lib/models/client.js) 到达未知 HTTPS CIMD 分支。真正解析、验证与 client 创建位于 [`client_id_metadata_document.js`](https://github.com/panva/node-oidc-provider/blob/v9.13.3/lib/helpers/client_id_metadata_document.js)。CC 使用原生 [`client_credentials.js`](https://github.com/panva/node-oidc-provider/blob/v9.13.3/lib/actions/grants/client_credentials.js)，不是 authorize 前置、DCR 代理或本仓仿制 handler。

| 已安装原样文件                               | SHA-256                                                            |
| -------------------------------------------- | ------------------------------------------------------------------ |
| `lib/provider.js`                            | `94a64ce834032c4d04ece497664e201590a8bb871698d178af7e275f16f1796d` |
| `lib/models/client.js`                       | `37841c70b72be69297851e4c9a091261748f7045ed8ae9a32f6b6c3ad9c312cb` |
| `lib/shared/client_auth.js`                  | `2ef832c2ce4093cbbb0a3eaf80ef7295410f0e2180bcfe8b036ec5021dd55f15` |
| `lib/helpers/client_id_metadata_document.js` | `fedbca8bf02fbd8c4aec1965a640dc4c4e20b4a0c58305121b646259004824fe` |
| `lib/actions/grants/client_credentials.js`   | `eade620806012fa4000573d28cb71fabb79d4089e2801356deb387eb1c78262d` |
| `lib/actions/introspection.js`               | `9c51064bc58f06a872c703aaf398778e51df288a7d1e5bd2bd587b677bc06575` |
| `lib/models/formats/opaque.js`               | `116a242cbe98d59b50d2c25e6c9b1810b97bc9a3d505a6ac3f03c54d43e9cb15` |

## 标准部署配置与隔离夹具

`tests/independent-as/fixture.ts` 是薄部署配置和独立 RS 应用，职责如下：

1. 启用官方 `features.clientIdMetadataDocument`、`ack:'draft-02'`、`clientCredentials`、`introspection`、`revocation`；关闭 dev interactions 和 DCR。仅配置一个普通 operator RS 的 ES256 private_key_jwt 公钥凭据，不预建任何 Agent client。
2. 官方 `allowFetch` 按受控测试 origin/path 和总预算放行陌生 CIMD，`allowClient` 按提供方无关的 private_key_jwt/ES256/CC 条件准入。没有每个 Agent 的白名单或手动授权。
3. 官方 `resourceIndicators.getResourceServerInfo` 对精确 resource、两个机器 scope 和 可配置测试 TTL（owner 为 3 秒、最终 native 为 8 秒） 执行明确部署政策，越界请求返回标准 invalid_target/invalid_scope。选择原生 opaque 格式，使用真实受认证内省，避免把结构化 JWT 假装成可内省 opaque token。
4. 官方 `configuration.fetch` 仅注入真实 TLS 的测试传输：精确配置 origin、临时 CA/hostname 验证、固定实际 loopback socket、manual redirect、时间/字节上限。不修改 metadata、断言、表单或上游响应，也不替换其 CIMD resolver、JWT 或 CC 实现。线上默认 SSRF dispatcher 没有被改源码；测试例外只存在于这个隔离 hook。
5. AS 自己的 signing key 配置为 RS256，以满足该库即使面对 CC-only client 也会验证的默认 `id_token_signed_response_alg`。Agent 认证仍只允许 ES256，未给客户端添加 id-token 字段、改变曲线或更换 audience 规避错误。
6. 本 lane 使用官方自带 **development-only MemoryAdapter**，原生库会明确警告。它只证明隔离组件协议互通，不证明持久化、多实例、重启恢复或生产部署；没有自写 Map 冒充 AS 或包装本仓持久化实现。

## 内省与独立 RS 的信任事实

原生 Client Credentials Token 的模型 kind 由库的 constructor 绑定，不能由请求自行声明。官方 `extraTokenClaims` hook 仅在 `token.kind==='ClientCredentials'` 时产生 `grant_type='client_credentials'`，经原生 opaque token 保存并由原生内省返回。这是部署应用的标准扩展声明，来源是真正的 grant 模型；不注入 `subject_type`、`sub`、固定假主体或客户端私有字段。

内省只允许预配 RS 身份验证该 resource 的原生 ClientCredentials token。独立 RS application 不使用本仓 `TokenVerifier`：它使用未修改的 `oauth4webapi` 发送受认证内省并验证 active、issuer、audience、到期、实际 scope 和上述 AS grant-kind 声明。原生 CC 内省没有 account sub；RS 的 `identity_get.subject` 仅在应用层映射为已认证的 client_id，未伪装成 AS 返回的用户/机器 UUID。

RS 用官方 MCP SDK 完成真实 initialize/tools/list/tools/call；实际工具名和 scope 使用同一授权政策。catalog-only Token 看不到也不能调用 identity 工具。AS/RS 是不同真实 TLS origins/listeners，仍是本机组件夹具，不是正式多进程服务部署。

## 已执行的独立 AS owner 组件

```sh
npm run test:independent-as
```

2026-11-06 / Node 22.23.1：**4 子项与父项，TAP 5/5 通过**。

- 未知 HTTPS 自托管 CIMD 首次 Token 请求前 public reads 为 0、Agent 预登记为 0，仅配置 RS；原生 CIMD/ES256/CC 取得 Token，两项 MCP 工具通过，authorize/DCR/interaction 请求数为 0。
- 实际等待 3 秒 Token TTL 到期，原生内省 inactive、RS 拒绝；新的标准 CC 请求成功。
- 精确 resource、机器 scope 政策拒绝越界；非 RS 的已认证 client 不能获取内省结果；实际工具 scope 执行有效。
- 原生标准撤销后 Token inactive，RS 拒绝，没有浏览器/授权码/回调替代流程。

首次仅给 AS 配 ES256 signing key 时，库因默认 id-token alg 校验拒绝陌生 CIMD；改为标准 AS 自有 RSA signing 配置后通过，没有改客户端元数据或认证 profile。一次配置失败遗留的本任务临时 TLS listener/certificate 已精确清理，fixture 现在在构造失败时也会关闭所有 listener 并清除证书。

## 最终真实 C/A/B → Desktop D 组合结果

```sh
DSH_IDENTITY_USER_SERVICE_SOURCE=/absolute/path/to/user-service-source \
DSH_IDENTITY_PYTHON=/absolute/path/to/user-service/.venv/bin/python \
npm run test:independent-as-native -- /absolute/path/to/anp-identity-source /absolute/path/to/actual-D-source
```

本轮完整实际执行 **passed=true**。D root 与 MCP client 的实际 package version 都是 `0.1.5-rc.2`。执行基线为 parent `fb2c4b9e698e30edb738bca4cf0618587db7d203`，production 已由 D owner 冻结但尚未提交，所以输出 `dSourceDirty=true`，并在运行前后验证所有关键生产源摘要一致；没有用旧 family 结果代替实际 Desktop rc2。

| 输入                                       | 候选或 SHA-256                                                     |
| ------------------------------------------ | ------------------------------------------------------------------ |
| Identity/C 与真实 registered helper commit | `e0d0019f836df296ddcf9d9e64540cb3536d5b42`，clean                  |
| 真实 B 软件 source commit                  | `04fe2050dc6168e1978666948bfcf27490c8dece`                         |
| Registered helper                          | `1bbe3146c8062d60435447c3cb23e115f1984c0285864eb89cfdf11e0377fadb` |
| D machine-auth.ts                          | `8984939a08e85076558bbd3ea0de188a579ee01e5e3ef4f100462c9f9f8a9a04` |
| D machine-http.ts                          | `7f7704391d3244c361beddfd1ae6b772505774ee7d6bea85fe5179f39751f8dd` |
| D machine-store.ts                         | `5f29927da04cdb65ad3ae10100d306438e1d6e9de7751a746893cd64219703ea` |
| Native addon                               | `e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef` |
| 原始 B metadata bytes                      | `ac3e8d96fd0bccf08209e0c278fea280e2360aac066688fd267980eaf0b5a9a6` |
| 原始 B JWKS bytes                          | `385cffc45630607e2e4dec508bea10131e1c7d0d1f393657cf18c94a9e29bfc3` |

已通过链路为实际 C approval → A native identity → B production RegistrationCommand/SQL/JWT/Registry/enrollment/prepare-bind-activate-readback → C 真实受限 Context → D → 原样第三方 AS → 独立 RS 的实际 SDK 两工具。`publicMaterials` 来自真实 B 匿名 GET 原 bytes，E 只按返回的 client_id/jwks_uri exact pathname 提供 TLS，不改 client_id/kid/digest；native 公文档唯一 ANPCIMD URL/原 metadata digest 一致。

该 AS 没有预建 Agent client；仅预配普通 RS 凭据。同一一般性准入政策同时接受上述实际 AWiki 软件 publisher 和独立自托管 P-256/CIMD publisher。前者的私钥一直在 C/A native；后者私钥只由本地测试进程中的独立标准 client 使用，不交给 D/C 或 AS 配置；该组件夹具不宣称客户端与服务器的 OS 进程强隔离。两个来源均实际获得该第三方 AS 的 Token 并调用工具。

Native lane 配置 8 秒 TTL，真实等待到期后由 D 自行新签/新 CC，机器 subject（应用映射的已认证 client_id）连续。C policy 显式允许受控负向 scope probe，以保证真正到达 AS；AS 拒绝 `account.profile.read`，没有创建成功 Token。标准撤销在原生 AS 产生 latest ClientCredentials.destroyed，使用 digest 匹配最后实际发行的 native Token，不记录明文。D 的本地持久 disabled fence 生效。

**D aggregate remoteRevocation 为 remote_revocation_unconfirmed。** 这是其在多次发行/可能存在历史 Token 时的冻结保守语义；不能因为最新 Token 已销毁，就宣称全部历史发行已确认撤销。测试同时断言最新 native Token 真正销毁、另一 client Token 不受影响与本地断开有效，不改 D 或 AS 为凑 confirmed。authorize/DCR/browser/interaction/callback 请求数为 0。

运行中的必要纠正均有边界记录：首次真实 publisher helper 在 C policy reopen 漏配 consumer，被真实 caller guard 拒绝；B owner 按权限配置修复并提交，未绕过。独立 RS fixture 曾对已认证的可选 SSE GET 探测返回 401，引发 D 正当清除 cache；现对有效凭据认证后返回 405（JSON-only transport），未改 D。旧测试将 aggregate revocation 错要求 confirmed，以及按目录首文件选 fence 的不精确假设，均改为真实冻结语义与指定 connectionId 精确文件。失败窗口记录保留，不计通过。

最终原生证据位于本仓 `.artifacts/independent-as-native-desktop-rc2-registered-verified/`：`run.log`、`result.json`、`source-and-results.json`。result SHA-256 `9fa363cef64b69de4233951b31c0b5e7266e731ec3967e8ad2aab23837e2573f`；log SHA-256 `95323ef655af53a85723d00236d26bc74bf361375f5b0dc6ff1a39be4be94eda`。完整 C/D/B/core-library/source-face/lock 摘要在 JSON 中，运行前后相同。

这里证明的是实际 AWiki **软件** publisher 与独立 AS 的受控组件互通。注册管理走本机 ASGI/私有 MySQL 组件桥，公开 bytes 是真实 TLS；localhost 测试 origin 不是 awiki.info 部署，不能推断外部 DNS、远程控制面或实际 OS keyring 通过。旧 N2 publication acceptance fixture 证据保留为历史；本轮没有以它替代实际注册发布。官方 AS MemoryAdapter 仍只用于隔离协议组件，不是生产持久化、多实例或灾备验证。未执行 System Test、产品 E2E、共享服务操作或发布；b65 镜像及其旧 lock/source provenance 仍保持历史事实。

D owner 随后冻结最终 clean commit `3860cc3a2696cc2f81e62d501a5dc87d79aef226`（parent fb2 / family0.1.5-rc.2）。E 将该提交的 machine-auth/http/store 和 source-face git blobs 与实际执行摘要逐一核对相同，并同样核对 C e0d0019 的 helper/authority/host/publication 与 B04fe205 bridge 共9项。原始执行记录的 dirty 状态不改写；最终提交绑定保存在 `final-source-binding.json`，SHA-256 `5d00f9ff85d4ffa2f07cb50d78980634d569b4a461ebbccaa12398c844686d47`。该核对不读取或依赖旧 family 的 lib 构建制品，也没有因为仅commit/docs改变而重复运行相同生产源。
