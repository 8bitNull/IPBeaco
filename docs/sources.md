# 来源准入与时间复核

核查日期：**2026-10-04 UTC**。本记录沿用当日 11:47–11:50 的官方页面/数据
审计，并于 **14:16 UTC** 实际运行四项只读 CLI 诊断；14:16:23 再读取 Feodo
官方许可、格式和 FAQ。只保存许可摘录和诊断摘要，不在公共文档或产物镜像原始
来源数据。下载成功、代码许可、署名或本记录本身都不能替代数据再分发授权。

## 当前准入结论

| 配置来源 | 独立家族 / 方向 | 启用 / public_approved | 当前有效覆盖及原因 |
| --- | --- | --- | --- |
| `blocklist-de-apache` | `blocklist-de` / Web 入站来源 IP | 否 / 否 | 无；公共再分发依据、Apache 分类和时间语义仍待明确 |
| `spamhaus-drop-v4` | `spamhaus` / 网络层 IPv4 CIDR | 否 / 否 | 无；公开镜像/加工输出的许可与格式义务仍待明确 |
| `spamhaus-drop-v6` | `spamhaus` / 网络层 IPv6 CIDR | 否 / 否 | 无；与 v4 同家族，许可及较短上游到期示例仍待明确 |
| `feodo-recommended` | `abuse-ch-feodo` / 出站 C2 目的 IP | 是 / 是 | 无；CC0 准入，但推荐快照的 3 月生成时间已陈旧，运行时拒绝 |
| `cins-army` | `cins` / IPv4 信誉观察 | 是 / 是 | 2026-10-05 复核 15,000 个公网 IPv4；仅观察，时间未知 |
| 可选 AbuseIPDB | 未接入 / 不贡献公开证据 | 否 / 未准入 | 仅禁用配置；不实现 API 拉取或公开数据 |

**CINS 提供 IPv4 观察候选；Web 封禁、网段和 C2 暂无当前有效覆盖。** blocklist.de/Spamhaus 未通过公共输出准入，
Feodo 已通过许可准入但未通过时效检查。不能为完成上线而启用存疑来源；以后
官方许可或数据变化时，需重新记录依据、更新配置并运行真实诊断。各端点不自动
成为独立家族，Spamhaus v4/v6 也不是两份独立 Web 证据。

## CINS Army

核查时间：**2026-10-05 02:28:48 UTC**。官方[说明与使用授权](https://cinsscore.com/)
及[TXT 数据](https://cinsscore.com/list/ci-badguys.txt)均返回 HTTP 200。针对该列表的原文：

> The CINS Army list is here and at Emerging Threats as part of their Open Source Community.
> The link below is provided as a simple text file, with which you can parse and use in any way you see fit.
> We assume Network Administrators will use the IP addresses from this file in their firewall blacklists
> and possibly in custom IDS and IPS signatures.

本项目依据这一数据专属使用授权批准公开加工输出，自愿署名 CINS Army、CINSscore.com；
不将代码许可套用于数据。此次下载包含 15,000 个唯一公网 IPv4，无注释、IPv6 或非公网地址，
SHA-256 为 `7b91a02d0cc4f86a43c114d7fc5d8f7774326d1a3c43d580127eb8edb5686e02`。

这是广泛信誉列表，没有逐 IP 攻击时间或可靠 Web 专属分类。固定使用独立适配器
`cins_army`、家族 `cins`、`time_mode=unknown`、`category=unknown`、
`max_tier=observe`、`independent=false`、`trusted_single=false`、IPv4 only。
仅进入观察列表，不能贡献 Web 封禁、网段或出站 C2。HTTP Last-Modified 不作攻击时间。
首次出现起最多 7 天，重复下载不续期；只有成功确认消失后再出现才启动新观察期。
格式错误或下载失败不能确认消失。条数与状态以每次实际产物为准。

## blocklist.de Apache

官方[导出说明](https://www.blocklist.de/en/export.html)、
[条款](https://www.blocklist.de/en/terms.html)、
[Apache 下载](https://lists.blocklist.de/lists/apache.txt)。官方说明每 30 分钟
生成，列出过去 48 小时被报告攻击相应服务的 IP；Apache 分类包括 Apache、
Apache-DDOS 和 RFI。输出为每行一 IP，分类端点都归同一 `blocklist-de` 家族。

已检查的官方页面介绍下载、展示和报告处理，没有找到明确允许下游公共镜像或
加工再分发的条款；因此 `public_approved=false`，不把免费可下载等同镜像许可。
尚未建立适用于本项目的署名条款，不能据此声称无署名义务；启用前一并明确。

初次审计中 Apache 与 all 各 112,480 字节，SHA-256 完全相同：
`20916136d63b5fd89a685dc5d10f35e62c35842c27377ad8240daea0ba8fda00`。
这不能证明分类错误，也不能建立可靠的 Web 专属分类。bots 返回零字节，并非
可用来补足分类证据。CLI 本次 Apache 仍返回同一摘要，报告 7,967 行。

正文没有逐 IP 观测时间或带日期的生成头；HTTP Last-Modified 只是文件修改时间，
不能当作攻击时间。网页只有时刻的更新标签不足以确定观测日期。配置使用
`time_mode=unknown`、`max_tier=observe`、`independent=false`，保持禁用；只读
诊断的 accepted_count 表示解析/规范化结果，不表示生产准入或当前有效观测。

## Spamhaus DROP v4/v6

官方[DROP 说明](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)、
[公平使用条款](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)、
[数据中的条款链接](https://www.spamhaus.org/drop/terms/)、
[v4 下载](https://www.spamhaus.org/drop/drop_v4.json)、
[v6 下载](https://www.spamhaus.org/drop/drop_v6.json)。这是网络层 DROP CIDR，
不是 Web 攻击来源 IP；项目不接收 ASN-DROP。

官方页面说明免费使用，并要求产品使用时署名 Spamhaus Project、保留日期和 ©
信息。条款 §3.1 同时声明数据受版权及数据库权利保护，且条款不授予相关知识
产权许可；§3.2 限制营销/商业宣传中的名称或数据引用，§3.3 允许撤销使用。
在已检查文本中，公共镜像/加工再分发未明确，不能把署名义务当成充分授权。
两项维持 `enabled=false/public_approved=false`；不是 CC0，也不套用代码许可。

`.json` 实际是 **NDJSON**：每行 CIDR 对象，末行 `type: metadata` 带 Unix
生成时间、条数、版权和条款链接。metadata 的 `size` 不包含完整 HTTP 正文中的
元数据行长度，不能直接与完整下载字节数比较。采用正文元数据的生成时间作为
快照时间，HTTP 修改时间另存，不将二者视作逐地址攻击时间。两项均属 `spamhaus`
家族，若未来准入，需保留日期、原版权和署名；network 输出有 `#` 注释承载这些
信息，设备必须兼容或依法保留旁存记录。

官方自动抓取要求至少间隔一小时，页面/FAQ 的每日建议可由现有每日调度满足。
官方 JSON 转 TXT 示例的 Expires 为生成时间 + **93,600 秒（26 小时）**；它是
转换示例而非已明确的通用有效期条款，启用前需明确适用范围，并优先采用较短
上游期限。本项目当前禁用配置的只读诊断使用设计的 48 小时上限：两项显示
current **不意味着获准生产使用**。v6 在核查时已超过 26 小时示例期限，不能
隐藏这个差异。

## Feodo recommended

官方[格式说明及 CC0](https://feodotracker.abuse.ch/blocklist/)、
[推荐 TXT](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt)、
[FAQ](https://feodotracker.abuse.ch/faq/)。数据是 botnet C2 **目的 IP**；推荐列表
说明仅包含活动或过去数小时活动的 C&C 服务器，不可导入 Web 来源封禁档。
独立家族为 `abuse-ch-feodo`，与 Web 或网络用途的证据不互换。

14:16:23 UTC 再次读取官方说明，HTTP 200，仍明确写道：

> All datasets offered by Feodo Tracker can be used for both, commercial and
> non-commercial purpose without any limitations (CC0).

该明确 CC0 依据支持本项目公开镜像和加工输出，无强制署名条件；项目自愿注明
“Feodo Tracker, abuse.ch; upstream data published under CC0.”。保留
`enabled=true/public_approved=true`，将 `reviewed_at` 记录为本次官方核查时间，
无禁用理由。**许可批准不豁免运行时的时效和格式检查。**

推荐 TXT 是注释头、DstIP 数据行、END 条数声明；使用正文 `Last updated` 的 UTC
生成时间作为快照时间。初次审计返回的头是 **2026-03-04 14:28:39 UTC**；HTTP
Last-Modified 为 2026-06-30 04:53:05 UTC，不能替换 3 月生成时间。本次真实
CLI 再取该推荐端点报 `stale_snapshot`，不接受其中历史记录。JSON/CSV 的历史
记录日期与生成日期语义不同，不切换端点绕过 TXT 的陈旧检查，也不用 30 天 IoC
或 aggressive 历史表替代推荐活动列表。

官方说明每 5 分钟生成，建议至少每 15 分钟、最好每 5 分钟更新；项目每日
00:17 UTC 采集明显更慢，不能承诺同等实时防护。FAQ 当前写数据因执法打击而
为空，与下载历史快照不一致；HTML 公告不能变成一份新鲜零条目的 feed。只有
后来返回**结构有效、生成时间当前**的空快照才能标 `empty`。当前旧快照首次
运行应标 `stale`，C2 列表没有未来截止时间，不能称为健康空列表。

## 四项真实只读诊断

宿主机 `NO_PROXY` 的 IPv6 排除格式导致 HTTPX 初始化失败。本次仅对诊断进程
清空大小写两个 NO_PROXY 值，保留其余代理设置、HTTPS 和默认 TLS 校验；没有
修改生产 HTTP 客户端或全局环境。运行时间为 2026-10-04 14:16 UTC：

```bash
NO_PROXY= no_proxy= .venv/bin/ipbeaco inspect-source --config config --source blocklist-de-apache
NO_PROXY= no_proxy= .venv/bin/ipbeaco inspect-source --config config --source spamhaus-drop-v4
NO_PROXY= no_proxy= .venv/bin/ipbeaco inspect-source --config config --source spamhaus-drop-v6
NO_PROXY= no_proxy= .venv/bin/ipbeaco inspect-source --config config --source feodo-recommended
```

| 来源 | 退出码 | 实际结果 |
| --- | --- | --- |
| blocklist-de-apache | 0 | record_count=7967，accepted_count=7967；freshness=unknown，generated_at/valid_until=null，public_admitted=false |
| spamhaus-drop-v4 | 0 | record_count=1692，accepted_count=1691；生成 2026-10-03 19:14:02 UTC，48h 诊断截止 2026-10-05 19:14:02 UTC，current，public_admitted=false |
| spamhaus-drop-v6 | 0 | record_count=91，accepted_count=91；生成 2026-10-03 06:14:02 UTC，48h 诊断截止 2026-10-05 06:14:02 UTC，current，public_admitted=false |
| feodo-recommended | 1 | `Run error: stale_snapshot`，没有接受为当前公共证据 |

v4 的 accepted_count 是公网地址规范化后的数量，不与原始记录数强行等同。
两项 Spamhaus 摘要分别为
`98b57930b9da98a0c270677256d4ec17eaa87f4c8fdbd7a3bd5ba11ccb45654f` 和
`d0aa31ac5a5f23479691bbe29f060e8d2639e9c5d218c2b753c137b2028987e8`。
命令对禁用来源也可进行解析和时间诊断，不写状态、不启用来源，不上传数据。

## 维护边界

内置适配器的用途和时间模式由配置校验固定约束，禁用来源也必须符合：

| adapter | purpose | time_mode |
| --- | --- | --- |
| `blocklist_de` | `web` | `observed`、`rolling`、`unknown` |
| `spamhaus_drop` | `network` | `snapshot` |
| `feodo` | `c2` | `snapshot` |
| `cins_army` | `web`（仅 IPv4 observe） | `unknown` |

Web 的 `unknown` 仅允许 `max_tier=observe`，`rolling` 必须提供 1–72 小时的
`window_hours`；家族、独立性和可信单来源批准仍由维护者配置。新增适配器需明确
用途和时间语义并扩展校验，不能通过改写现有适配器的 purpose 绕过方向或时效。

新增/启用来源必须记录官方许可链接、核查日期、用途方向、家族、时间依据和
署名要求，明确公共再分发及输出格式允许后再设置 public_approved、reviewed_at
和启用状态。许可撤回时立即撤销准入，其历史证据不能继续进入公开产物。网络、
C2 最长 48 小时；Web block 最长 72 小时，observe 最长 7 天；更短上游期限
优先，未来超过 5 分钟的上游时间不接受。采集时间不为旧证据续期。

许可不明时保持禁用，明确报告覆盖不足；不自动联系来源维护者，不通过别处镜像
绕过准入。固定测试样本只用于离线测试，不能加入生产 config 或上线 artifact。
