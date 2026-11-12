# 播放协议对齐记录

对照源：`NeteaseCloudMusicApiEnhanced/api-enhanced`，提交
`4a7d557326d16d2f1e5172ee69c9471eb3a50173`（2026-11-06）。Rust 基线：
`dddqmmx/ncm-api-rs@133b65bfe482e41ebccf018870d3fce07bf58eb3`。

SDK 独立维护于 `git@github.com:dddqmmx/ncm-api-rs.git`，API 修改直接写入 `src/` 并在本仓库中提交；桌面客户端通过 Cargo path 依赖使用本地源码。

上游 `d0935f6`（2026-05-30）把 `song_url_v1` 改为 XEAPI；
`bd407ce`（2026-10-03）将 XEAPI 的 B/S/R 改为 C/S/R。客户端原来安装的
Node 4.36.1 包仍使用 B/S/R，不能用它作为当前协议的对照基线。

2026-11-12 的只读探针复现了匿名旧 EAPI 的拒绝：HTTP 200，业务码 **-460**，
`message` 为“检测到您的网络环境存在风险，请稍后再试”。旧 SDK 把业务码折算成 400，
只读取 `msg` 而忽略 `message`，最终显示 Unknown error。同条件下 XEAPI 返回业务码 200；
测试曲目的匿名音源条目为 404，仍受歌曲权限限制。已有登录会话的同歌曲 EAPI、XEAPI
均返回 200，XEAPI 提供完整音源。因此不能把每次拒绝都解释为 EAPI 完全失效。

此次对齐内容：

| 部分 | 对齐行为 |
| --- | --- |
| 公钥 | `/api/bsr/sk/get`，Android 9.5.61，响应 HMAC-SHA256 验签，AES-256-ECB 公钥解密 |
| XEAPI | `interface3.music.163.com`，C 使用 base64url 无填充，S/R 使用 base64 |
| C | UTF-8 表单 `content`、`e_r=true`，静态 AES-256-ECB、随机掩码及字节旋转、动态 AES-ECB |
| S | X25519、HMAC-SHA256 密钥派生、AES-128-GCM；拒绝无贡献的公钥 |
| R | 公钥版本和会话 ID，经静态 AES-256-ECB 加密 |
| 输出响应 | AES-128-ECB，支持 gzip，解压上限 16 MiB，解密失败提供明确阶段说明 |
| 请求头 | Android OS/版本/设备、`X-Client-Enc-State`、`x-aeapi`、当前请求的 MUSIC_U |
| 缓存 | 首次请求自动获取公钥；按客户端、域名、设备与账号隔离，会话不会在不同账号间复用 |
| 业务错误 | 保留原始 HTTP 状态、业务 code、message/msg、body 与 cookie，不把 -460 改为 400 |
| EAPI | 按上游当前配置改用 `interfacepc.music.163.com` |
| 播放 | v1 使用 XEAPI，保留 `level`，支持 sky 的 immerseType 与 vivid 参数，不自动降级到旧 bitrate 接口 |
| 相关已有接口 | 下载 vivid 参数、302 下载对象/数组响应、匿名注册、评论删除/回复、分享、云贝签到，以及实时 checkToken v3 |

对齐范围是播放、共享请求层与已经存在的相关接口。上游新增的 NEAPI 和广告、推荐分类等独立接口
未在此次修改中移植；不会将它们标记为已兼容。

固定输入测试向量由上游 Node 的 `util/crypto.js` 生成，位于
`tests/fixtures/xeapi-node.json`。它包含合成密钥，不含真实登录信息。Rust 测试逐字节比较
C/S/R 与签名，并验证普通/gzip 响应和公钥解密。运行这些回归不需要 Node 或网络：

```sh
cargo test --locked --lib --test error --test query
```

重新生成向量时使用 `scripts/xeapi-node-fixtures.cjs`；需提供上述固定提交的 Node 加密文件
与能解析其依赖的 package.json 绝对路径。真实网络探针位于桌面仓库的 Slint API 测试中，
以 ignored 测试显式运行，不打印 cookie 或音源 URL。
