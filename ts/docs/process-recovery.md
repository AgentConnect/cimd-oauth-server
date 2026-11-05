# 独立 AS/RS 进程与真实备份恢复组件

入口：`npm run test:process-recovery`。owner runner 为每次执行新建私有 `/tmp/cimd-pg.*` PostgreSQL/Unix socket，执行迁移；脚本另外创建精确 named 的 owned 恢复数据库，实际 `pg_dump`/restore 后清理。它不是 System/产品 E2E 或共享数据库演练。

最终71秒完整窗口执行 exit0，总约81.104秒。3个AS、3个RS不同fresh Node PID和不同TLS origin；RS配置/env无DATABASE_URL，没有导入构造PG Pool或直读AS库，实际用独立凭据进行HTTP内省。两工具、AS/RS重启后的Token/replay/ban保持、AS SIGKILL后RS503 fail-closed均通过。

恢复顺序为AS物理offline、RS仍监听但全部资源鉴权503；真实dump恢复到另一owned DB，先invalidate所有政策/代次并重建可信operator ban。未知安全事实的resource保持disabled。等待完整最坏窗口后才重开已收敛的政策；旧未到期Token因恢复代次失效，fresh请求恢复，不能靠旧快照解禁。

默认规则允许future iat5秒、lifetime60秒和expiration tolerance5秒，因此最坏接受窗口70秒，组件保守等待71秒。真实向量最初已由AS接受：iat=t0+5、exp=t0+65。65,070ms时生产Authenticator经真实TLS/JWKS仍接受，尚余4,305ms；只做认证不mint、不消费replay。71,050ms后同断言被生产认证及真实TokenHTTP拒绝，fresh控制成功。旧65.059秒运行保留为较窄向量的历史事实，不能当完整恢复门槛。

最终script SHA `8cd4c567c0b9dbbadf889bde83727a655f20955fd4793e518de19fe2bb87d27a`，worker SHA `9fd16765fddc8b635b375872e1b0997d7ca14dfd13ee01365ebc5bd1a98812bd`；执行前后source一致，并绑定kid修正后的Authenticator `73909f9dd915ff7d5581f2b9d8ace859f3d397f695c8dbcbf6d989a3213aa284`。原生artifact为本仓 `.artifacts/process-recovery-full-window-64uq8gi1/`，result SHA `fae5f980701e5ce64a07b34230ff778b8fdc13587846c72ad94034975430eadf`、log SHA `4c4fe3d0b6bdfd7cb38ed324b7e86058d0da5c1a2f51350f43d07d73d7930222`。

所有6个worker PID实际核对已消失，stdout/stderr均0字节且known-secret扫描false；精确恢复DB、taskroot及runner cluster已清理，没有动别的owner目录。worker仅在NODE_ENV=test运行真实TLS模块factories，不是假称production entrypoint部署；DB角色为隔离测试owner，不代表生产least-privilege验证。可信operator事实仍必需，没有自动恶意DBA回滚检测、独立durable security witness或OS keyring证明。
