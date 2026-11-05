# N5：确定输入的私有候选镜像验证

执行时间：2026-11-05 UTC / 2026-11-06 Asia/Shanghai。镜像源代码固定为 **`b65e5b30e3f3d13b38f43ad7cf35ec680fae577e`**，构建前工作树干净；本记录在构建后以独立文档提交保存，不能把文档提交误称为镜像的代码 revision。

## 环境与授权范围

本机 Docker Engine / CLI 29.1.3，`default` context 使用 `unix:///var/run/docker.sock`，Linux/amd64；Podman 可执行文件未安装。只使用已有 daemon，没有启动或重启 daemon、安装系统包或变更 Docker 配置。起始可用约 23 GiB，构建后仍约 23 GiB，没有执行缓存或镜像清理。

构建前有 4 个既有容器（2 个运行、2 个停止）及 12 个镜像 tag。构建/检查后逐一比较既有容器 ID/name/image/running 与镜像 tag→ID，均保持一致；本任务的检查容器残留为 0。没有连接共享数据库、映射主机目录、发布端口、启动生产服务或执行 System Test/产品 E2E。

## 固定构建与标识

唯一候选 tag：`cimd-oauth-server:dsh-identity-b65e5b3-candidate`。构建前该 tag 不存在，没有覆盖其他 tag，没有 push。

| 输入或产物                    | 标识                                                                                                 |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- |
| 源代码 commit                 | `b65e5b30e3f3d13b38f43ad7cf35ec680fae577e`                                                           |
| Dockerfile SHA-256            | `34b33e50ad7e289ef0525bc890b595d9fd7a812b0d20ab2de41f68984800eaba`                                   |
| Registry lock SHA-256         | `f7a5fc3c2382f0dd711c7d44c638091aa545ed8fd61deb4c79f630b752236f23`                                   |
| Migration SHA-256             | `4b466871a3259dbc6b2f2cf377f8cacf09530c3517c181b8360b5402845bf552`                                   |
| 固定 base image               | `node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` |
| 本地 image/index ID           | `sha256:80d385259333ecb882e3a17b2110157268275a77a6bb66cf5862cf1b705b9703`                            |
| 导出的 Linux manifest         | `sha256:69f5c671fc9a57deee154949c0bd3f7789983c0d25aac5c9b766353cf1ceac37`                            |
| 导出的 config                 | `sha256:2edd064ffaacae226a46555d17589b8904fba5586d03f2161542abcf35fa5567`                            |
| BuildKit attestation manifest | `sha256:00b6fa765097fbd5625f7a5bc7c67245b1125b658e8e1d1607441b5e5b22aa3b`                            |
| 本地镜像大小                  | 83,550,547 bytes                                                                                     |

当前 Docker 的 `RepoDigests` 列出本地 `cimd-oauth-server@sha256:80d385…9703`。这是本机 metadata，**不代表已经发布到任何 registry**。此项验证固定 source/base/lock 并记录实际输出，不宣称已完成第二次构建的逐字节复现。

从 `ts/` 执行的准确构建命令：

```sh
docker build --progress=plain \
  --iidfile ../.artifacts/n5-b65e5b3-20261105T180440Z/image-id.txt \
  --label org.opencontainers.image.revision=b65e5b30e3f3d13b38f43ad7cf35ec680fae577e \
  --label org.opencontainers.image.source=https://github.com/AgentConnect/cimd-oauth-server \
  --label org.opencontainers.image.licenses=LicenseRef-Proprietary \
  --label org.agentconnect.cimd.lock-sha256=f7a5fc3c2382f0dd711c7d44c638091aa545ed8fd61deb4c79f630b752236f23 \
  --tag cimd-oauth-server:dsh-identity-b65e5b3-candidate \
  --file Dockerfile .
```

Dockerfile 实际完成固定 base 拉取、`npm ci --ignore-scripts --no-audit --no-fund`、TypeScript build、migration asset copy 和 `npm prune --omit=dev --ignore-scripts`。没有触发测试或发布 lifecycle。构建不向镜像注入真实环境、密钥或凭据；`.dockerignore` 排除 `.env*`、本地状态、缓存、日志与制品目录。

## 五项禁网检查

所有检查均使用：

```sh
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --name <本任务唯一检查名> \
  cimd-oauth-server:dsh-identity-b65e5b3-candidate <下面对应命令>
```

| 检查                        | 实际命令主体                                      | 退出码 / 结果                                                                                              |
| --------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Runtime imports             | `node --input-type=module --eval <imports check>` | 0；实际导入 oauth-as、oauth-rs、store-postgres、MCP app；Node 22.23.1 / UID 1000；`tsx` 未包含在运行时依赖 |
| Migration 与 license assets | `node --input-type=module --eval <assets check>`  | 0；SQL 内容 SHA-256 与源码一致，六个直接运行依赖的实际 license 文件存在并计算摘要                          |
| AS 缺配置                   | 使用镜像默认 CMD                                  | 1；`missing_configuration`，没有 listening                                                                 |
| RS 缺配置                   | `node dist/examples/minimal-mcp-server/main.js`   | 1；`missing_configuration`，没有 listening                                                                 |
| Migration 缺 DB             | `node dist/scripts/migrate.js`                    | 1；`missing_configuration`，没有创建 Pool/应用 migration                                                   |

完整 eval 内容、argv 数组、stdout/stderr 摘要均保存在下列私有证据中，未用探针启动 AS/RS listener，也没有执行任何数据库 migration。入口失败是预期的 fail-closed 检查通过，不能改称配置完整的服务部署通过。没有在容器中重跑 MCP/PG 功能链或 System/产品测试。

## 许可与私有证据

产品为 private / closed-source，镜像 label 标记 `LicenseRef-Proprietary`。实际检查运行时 `@modelcontextprotocol/sdk@1.29.0`、`jose@6.2.15`、`pg@8.23.1`、`express@5.3.0`、`ipaddr.js@2.5.0`、`zod@4.6.7` 均保留 MIT 声明及对应 license 文件；每份 notice 的 SHA-256 记录在结果中。完整锁定依赖清单仍见 `dependency-licenses.json`。此次没有修改生产代码、Dockerfile、正式 lock 或 migration。

本仓忽略目录 `.artifacts/n5-b65e5b3-20261105T180440Z/` 保留：

- `build.log`、`image-id.txt`、`image.json`：原生构建输出及选定 image metadata；build log SHA-256 `637266c18275e70a119c5375972ccdcfd4c0fabf4ba4b61b59cfc1394dc46219`。
- `check-image.py`、`commands.txt`：本次实际验证入口和完整准确命令。
- `result.json` 与逐项 stdout/stderr：五项实际结果；result SHA-256 `78f32c30b3f24364228331cacf7acdc098b81812ab766f5fe78b8fc62b97eaa3`。
- `environment-before.json`、`environment-after-check.json`：既有容器/镜像保留及检查容器自动清理事实。
- `provenance.json`：源 commit/tree/clean、构建参数、固定 base、source/lock/assets/license 摘要、实际镜像与检查、发布/部署边界；SHA-256 `11865c193d315d159e6d347b80b1035f2e24066e50341f21501795e1ec3d82f5`。

镜像和以上证据仅保留于当前私有主机；没有导出到公开位置，没有 public/private registry 发布，也没有为验证调整任何共享运行实例。
