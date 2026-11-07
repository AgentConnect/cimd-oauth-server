# Service Agent

本仓库已更名为 `AgentConnect/service-agent`。新增 ANP 身份认证模块与 ANP、MCP、PAP 三协议组合入口，复用一份版本文档读取和留言业务。ANP 服务端不需要自己的 DID；接入、配置与验证见 [三协议服务说明](ts/docs/service-agent.md)。原有 CIMD 机器 OAuth 和 PAP 示例继续保留。

本仓库以 [Apache-2.0](LICENSE) 开源，包含 CIMD `private_key_jwt` + `client_credentials` 授权服务器、PostgreSQL 存储、可独立运行的资源验证组件和两个只读工具的 MCP 应用。当前全部实现与工具链位于 [`ts/`](ts/)；Rust 留待后续阶段。

另提供 [PAP 0.3 无人交互 hello demo](ts/docs/pap-demo.md)：通过公共身份验证 PAP Session 后调用 OpenAPI，无需浏览器或账户授权。

从 [`ts/docs/quickstart.md`](ts/docs/quickstart.md) 开始。协议契约、安全边界、依赖来源及本次实际验证见 [`docs/protocol.md`](docs/protocol.md)、[`docs/security.md`](docs/security.md)、[`docs/sources.md`](docs/sources.md) 和 [`ts/docs/verification.md`](ts/docs/verification.md)。

MCP 机器模式下，未知客户端只有通过运营者显式配置的有界 `open_basic` 政策后才能取得有限机器权限。公开 CIMD、签名正确与资源授权是独立步骤。独立 PAP demo 只提供 signed-out Session；本仓库不提供浏览器授权、用户账户、授权码、Refresh Token、DCR 或 Agent 私钥托管/代签。

源码公开；npm 包和镜像发布另行安排，当前不执行制品发布。
