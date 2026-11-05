# S09：实际 JWKS 缓存传播窗口

`npm run test:cache-window` 使用本仓原样 `ClientAuthenticator` 和 **默认 60 秒缓存 TTL**、真实 TLS publisher/AS、独立 PostgreSQL。没有修改生产 TTL，没有 fake timers/Date，没有以过期 assertion 代替 key 失效证据。新 owning case 位于 `tests/cache-window.component.ts`。

2026-11-06 最终完整执行 **1/1 通过**，总 TAP 时长约 60.09 秒。初始缓存同时含 old/new 两把 ES256 公钥；publisher 在初次成功取得机器 Token 后移除 old，只保留 new。

| 阶段                               | 实测相对起点 | CIMD/JWKS GET 各计数 | 结果                                                            |
| ---------------------------------- | -----------: | -------------------: | --------------------------------------------------------------- |
| Publisher 移除 old key             |        43 ms |                    1 | 原始 snapshot 已缓存 old/new                                    |
| 使用新 iat/exp/jti、old key 新签   |     1,052 ms |                    1 | 窗口内接受                                                      |
| 使用 new key 新签                  | 同一初始窗口 |                    1 | 接受且主体相同；因为原缓存已含 new，不触发未知 kid 刷新         |
| 接近 cache 到期，再用 old key 新签 |    57,640 ms |                    1 | 仍在记录有效期内，接受                                          |
| cache TTL 后再用 old key 新签      |    59,770 ms |                    3 | 401 invalid_client；该断言仍剩 **60 秒**，不是过期 JWT 导致失败 |
| TTL 后用 new key 新签              |         随后 |                    3 | 接受，唯一机器 subject 连续                                     |
| 原始 300 秒 Access Token 内省      |         随后 |                    3 | 仍 active，不把删 key 当作该 Token 自动撤销                     |

默认实现将 cache 到期时间向下取到秒；本轮从网络开始到记录到期为 **59,497 ms**，验证函数返回时实际剩余 **59,478 ms**，所以并不要求观测为整整 60,000 ms。测试把上界锚定在 TLS/JWK 加载后，避免初始网络耗时跨秒造成误判。assertion 的固定 5 秒 clock tolerance 不延长 metadata/JWKS cache，到期后的拒绝也没有借助 assertion 过期。

GET 从各 1 变为各 3 的原因是：到期后先获取一次当前 snapshot；随后 old kid 在新 snapshot 不存在，按现有政策再允许 **一次**有界强刷，仍不存在即拒绝。新 key 后续使用缓存，不再增加 GET。这里没有推断所有对端、所有副本或全网都即时发现删除，也没有把 JWKS 变化与已签发 Token 的撤销/政策代次混为一谈。

最终原生记录在本仓忽略目录 `.artifacts/s09-cache-window-final/`：`run.tap`、`result.json`、`source-and-results.json`。首次完整源也通过并保留于 `.artifacts/s09-cache-window-20261105T1920Z/`；调整测试秒边界锚点期间一次旧源重复启动已中止，保留于 `.artifacts/s09-cache-window-stable-boundary/`，不计为通过。中止的临时数据库/证书已精确清理；最终源重新从头实际等待并通过。没有发现需要修改生产 cache 政策的行为缺陷。

该入口只运行这一项 owning component，结束后停止/清理私有 PostgreSQL、TLS 和临时材料，没有连接共享数据库、部署服务或顺带运行其他 owner suites。
