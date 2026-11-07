# 私有运行制品

从精确源码构建后，`npm run pack:runtime -- <private-output-directory>` 只打入明确白名单中的 built service modules、SQL migration、独立 AS/RS 启动器、configure/admin 工具、公开 `.env.example` 和依赖许可清单。它不包含 `.artifacts/`、`.local/`、原生日志、真实 `.env`、源码测试、测试数据库或 native/source integration fixtures。源码由公开 Git 仓库交付；运行配置和执行证据仍按各自保密边界保存。

本项目代码采用 Apache-2.0，许可证随运行包提供。`private: true` 保留用于防止误发 npm，本次不发布包或镜像。`oauth4webapi`、`oidc-provider` 等独立互通库仅 dev/test，不是本 AS 的运行时依赖；生产依赖及各自 notice 随正常依赖安装保留，清单见 `dependency-licenses.json`。

制品带从已提交 package-lock 原样派生的 npm-shrinkwrap，安装应使用 npm ci --omit=dev --ignore-scripts，锁定完整运行依赖而不是重算浮动传递版本。临时派生只在pack期间存在，结束后删除，不改变源码依赖来源。

在受控目标目录安装运行时依赖（或由私有部署工具完成），通过保护环境/secret manager 配置真实 PostgreSQL、issuer/resource、RS 凭据、TLS 和显式准入政策后使用：

```sh
npm run migrate:built
npm run configure:built
npm run start:as:built
npm run start:mcp:built
npm run admin:built -- cleanup
```

AS 与 MCP/RS 在独立进程运行。migration/config/admin 使用受控管理数据库角色；AS 使用无 DDL 的应用角色；RS 只注入固定内省源及独立服务凭据，不需要 DATABASE_URL。不要把管理角色的完整环境复制给 RS。缺配置时入口立即拒绝，不因安装自动启用 open_basic、迁移或启动服务。

`:built` 命令对应 tarball 中实际存在的 JavaScript。开发用 `tsx`、原生 source fixtures、`npm test:*` 等命令只属于完整源码工作区；运行制品不携带或宣称可运行那些开发入口。服务镜像由源码的 Dockerfile 单独构建，不要求从此 runtime tarball 重建源码容器。

候选验证仅检查完整性、运行时导入/迁移资产、缺配置 fail-closed 和受限拥有者组件证据；不自动执行发布前全套测试、不发布 registry、不替代 System/产品 E2E 或实际部署验收。每个包和镜像的 source commit/lock/digest 由其对应 provenance 记录，旧 b65 镜像不会重标为新 source。

已认证的 `server/discover` 协议版本探测与 `initialize` 一样不要求业务工具 scope；兼容 handler 在旧 SDK 的 HTTP 版本头校验之前返回标准 MethodNotFound，允许新版客户端显式按协议回落到 initialize。未认证请求仍返回 401，未知非握手方法及 scope 不足的 tools/call 仍拒绝，绝不把 403 当成版本不支持。
