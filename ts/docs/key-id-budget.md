# 完整 DID key ID 的有界兼容修复

真实 C/A/B OAuth key 旋转暴露了 E 的兼容缺陷：初始 key ID 长 121，旋转后同一 DID 下的完整 key ID 长 **132**，两次 native assertion 都能用实际 B 当期 JWKS 独立验签，但 E 曾因本地 `kid <=128` 预算返回 invalid_client。没有缩短、改写或重新命名真实材料来消除错误。

`ClientAuthenticator` 现在在 JWKS 与 JWT header 使用同一有界政策：非空且非全空白、最多 **1024** 个 JS 字符单元（与 C PublicJwk max1024 一致）、拒绝 Unicode Cc 控制字符。标识保持原字符串、精确比较，不规范化、不截断。总文档64KiB、最多8keys、JWT16KiB、唯一kid、公开P256/ES256、私钥字段拒绝与所有iss/sub/aud/time/replay规则均保留。这不是放宽认证或自动增加资源权限。

新增 owning `tests/kid-budget.test.ts` 经过真实 TLS metadata/JWKS 与真实 ES256 签名：132完整DID形态、1024边界正向；empty/blank/ASCII与C1控制/1025分别在JWT header与JWKS拒绝；无效header在远端获取前失败，duplicate kid与private material仍拒绝。与既有network tests定向执行为 **4/4**，typecheck通过。

真实回归由 D 运行原 `rotation-native-component.ts`，原132 key材料不改，实际PG/TLS/SDK完整通过：

- 真实C管理与B enrollment/prepare/bind/activate/read-back旋转，client_id不变。
- 旧C lease/旧D session在物理send前拒绝，AS Token/RS调用数不增，旧本地partition文件不变。
- 新显式许可、新key、新Token成功，两工具可调用；同一machine subject、不同本地partition。
- 删除/更换key不自动撤销旧Access Token，旧Bearer实际RS与内省仍有效。
- 真正注销C native provider registration后，新签名/请求报provider_unavailable，Token/RS/交互端点请求均0；它不是OS keyring lock，未宣称GNOME自动锁。

原失败证据保留于 `ts/.artifacts/rotation-native-component/rotation-kid-budget-failure.log`。成功原生日志为同目录 `run-after-kid-budget-fix.log`、`result.json`；结果SHA-256 `1c2f5d59d81104d0b4a295c0f44bf601763e36a8a2a32f6b167132f97069ba49`。执行script SHA `cf1ec10022e56c6e2431dff57bcb5c9f9a85fd17e236ccff04cb590a1acc66c8`，E authenticator新SHA `73909f9dd915ff7d5581f2b9d8ace859f3d397f695c8dbcbf6d989a3213aa284`，worker运行前后关键源相同。C/helper95c5与B bridge test增量dirty均在原记录里，没有伪称clean。

这项修复没有改变E生产cache时间、PostgreSQL结构或Token代次。此前真实60秒cache传播和71秒恢复证据各自保留对应源窗口，未扩成所有AS即时撤销。旧b65镜像及其旧锁/provenance仅作历史记录，不冒称包含此生产修复。
