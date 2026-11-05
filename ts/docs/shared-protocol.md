# P01/P28 同一 native DID/CIMD 的 PAP 与 MCP 状态分离

入口：`npm run test:shared-protocol -- <identityRoot> <harnessRoot> <papRoot>`，使用显式source face和每次独立的PG/TLS/state。执行者G实际exit0，脚本SHA以实际文件为准为 `f4cfe6c72b4964d736aca35b3b1f179abad42b22899214fdcd0dfcdac0943c81`，C test helper SHA `d193031633ccd233953783ba18f373bbff6c014bee0168a23a4aa811adf3a867`。

同一真实C/A native身份与CIMD只发布一次（明确publication acceptance fixture，MCP+PAP signed-out、papAccount=false、无callback）；两个不同installed Context及policy分别属于F/PAP与D/MCP。实际顺序：F真实engine→NoAS HTTPS服务，实际从CIMD/JWKS验证Delegation和Session，Token请求0、MCP/AS principal未建立；然后只关闭PAP engine/lease/Context/server，保留共享身份；再由独立D Context首次CC取得机器权限、SDK两工具、实际8秒TTL到期/SQL旧Token过期后新CC两工具成功。

Host PAP scope ceiling为显式pap.read以满足当前C管理配置合同，实际PAP wire requestedScopes=[]，不发OAuth scope、不取得Token。首轮用空Host ceiling触真实C拒绝，后仅修测试配置，没有放宽C production。早期spy构造Request后又转发原body的问题也只修编排，不改D/F。

执行绑定F `7325b80a2b5c4b4b5e5e80d1ff1304921c9d1bb7`、D `af6f299a8a6361e028711789480faaab52f80f0a`、native `e2c4b86a…52663ef`。C执行HEAD fddc8a3，helper随后test-only提交b137a1d6ed4f6e87692287d854b90487475fa516，字节不变；完整source hashes前后一致。两个Token全是client_credentials，无authorize/callback/refresh；latest revoke与本地disabled fence通过，多次发行aggregate保持unconfirmed。

原生stdout结构化归档在 `ts/.local/verification/shared-protocol-final-20261106.json`，SHA `fcd4f93190bf787a1e7e93caf4455b0bc3b71f99b2c6a64cce74fa3fc2392ea9`，清楚标记来自完成的owner stdout及post-guard复核，不为归档重跑。精确PG目录 `/tmp/cimd-pg.rvezGbFr` 退出后不存在，TLS/native/pap/machine状态及pool均清理；初次失败的两个exact orphan root也由owner按时间归属核验清理，没有泛删。

本case不读取/导出Agent私钥，不代表真实B发布、真实keyring或产品UI；I01实际C/A/B注册发布另见independent-as.md。它是共享身份/独立消费者与状态的模块证据，不是System/产品E2E或默认账户权限。
