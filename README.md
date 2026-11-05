# CIMD 机器 OAuth 参考服务

本仓库为 private / 闭源实现，包含 CIMD `private_key_jwt` + `client_credentials` 授权服务器、PostgreSQL 存储、可独立运行的资源验证组件和两个只读工具的 MCP 应用。当前全部实现与工具链位于 [`ts/`](ts/)；Rust 留待后续阶段。

从 [`ts/docs/quickstart.md`](ts/docs/quickstart.md) 开始。协议契约、安全边界、依赖来源及本次实际验证见 [`docs/protocol.md`](docs/protocol.md)、[`docs/security.md`](docs/security.md)、[`docs/sources.md`](docs/sources.md) 和 [`ts/docs/verification.md`](ts/docs/verification.md)。

未知客户端只有通过运营者显式配置的有界 `open_basic` 政策后才能取得有限机器权限。公开 CIMD、签名正确与资源授权是独立步骤。首版不提供浏览器授权、用户账户、授权码、Refresh Token、DCR、PAP Session 或 Agent 私钥托管/代签。

源码、包与镜像不得发布至公开服务。
