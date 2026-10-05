# 订阅与客户端同步

当前站点为 https://8bitnull.github.io/IPBeaco/ ，下表是实际下载地址。
2026-10-04 首次发布时八份列表均为 0 条：Web/网段为 unavailable，C2 为 stale，
不能作为健康空名单导入。新增 CINS Army 后，IPv4 观察列表可获得信誉候选，
仅用于观察、验证或限速；重复下载不会续期。请读取 status 判断当时的可用性。

这些文件由工作流生成到 `site/lists/` 后发布到 Pages，不保存在 main 分支。
Fork 的主示例为 `https://<owner>.github.io/IPBeaco/lists/block-ipv4.txt`，
`<owner>` 替换为自己的 GitHub 用户名或组织名；更改仓库名或域名时也需调整基址。

| 下载地址 | 用途 |
| --- | --- |
| [block-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/block-ipv4.txt) | 入站 Web 来源 IPv4 封禁 |
| [block-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/block-ipv6.txt) | 入站 Web 来源 IPv6 封禁 |
| [observe-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/observe-ipv4.txt) | 入站 Web 来源 IPv4 观察、验证、限速 |
| [observe-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/observe-ipv6.txt) | 入站 Web 来源 IPv6 观察、验证、限速 |
| [network-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/network-ipv4.txt) | 网络层 IPv4 CIDR |
| [network-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/network-ipv6.txt) | 网络层 IPv6 CIDR |
| [c2-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/c2-ipv4.txt) | 出站 C2 目的 IPv4 |
| [c2-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/c2-ipv6.txt) | 出站 C2 目的 IPv6 |

辅助文件为 [status.json](https://8bitnull.github.io/IPBeaco/lists/status.json) 和
[metadata.json](https://8bitnull.github.io/IPBeaco/lists/metadata.json)。站点首页显示当次构建版本、
各列表条数、状态及截止时间；实时判断以状态和证据为准，不能只看首页更新时间。

## 同步协议

TXT 不包含到期机制。直接订阅 TXT 且无限保留地址的客户端无法落实项目有效期，
应先增加下面的同步和本地到期处理，再导入设备。使用可信 UTC 时钟，通过 HTTPS
读取，每次下载写入临时文件；整个过程不导入实际防火墙，直到所有检查完成。

1. 读取 `lists/status.json`，保存 `schema_version`、`build_id`、`generated_at` 及
   所需列表的 `path/status/count/sha256/valid_until`；检查版本和预期路径。以当前
   时间核对 `valid_until`，构建或下载时间不能延长证据期限。
2. 按下表判断列表可用性。`unavailable`、`stale`、截止时间为 `null` 或已到期都
   不是健康同步；不能将它们的空 TXT 作为“没有威胁”的证据。
3. 读取 metadata，按 status 中 `metadata.sha256` 校验其**原始字节**的 SHA-256，
   确认 metadata 与 status 的 `schema_version/build_id/generated_at` 一致。检查
   所选 `entries` 的用途、地址、证据、来源准入及 `valid_until`；需要来源说明的
   设备保留相关署名/版权。默认使用列表最早的截止时间管理整个集合；若按条目
   管理，也不得越过列表宣告的有效期。
4. 下载所需 TXT，先对完整原始文件（包含注释和最终 LF）计算 SHA-256，再解析。
   核对 IP 版本、IP/CIDR 语法、数值排序及去重；只数数据行，核对 status 的
   `count` 和 metadata 的目标集合。Web/C2 是纯 IP；network 排除 `#` 注释后数
   CIDR，因此 `count=0` 的有效 network 文件仍可含有版权和来源注释。
5. 再读 status，确认 `build_id` 以及所用列表路径、摘要、条数、状态、截止时间和
   metadata 摘要与第一份完全一致；在替换前再次检查当前时间和有效期。如果
   不同，丢弃临时文件并重新开始，不能拼接不同构建的数据。
6. 通过设备容量及语法检查后，原子替换本地集合，同时保存 `build_id` 和截止
   时间。多份相关列表一起导入时使用同一构建并统一替换。提前安排本地到期
   清理，在网络失败、上游失败或任务全停时仍能移除到期规则。

摘要用于检出损坏或跨构建混合，不是数字签名。健康空列表也必须完成一致性校验；
不能见到空文件立即清空本地规则。获取失败时已有规则只保留到其**上次有效截止**，
随后到期移除，不因重试或下载缓存而续期。

| 列表 status | 含义与客户端处理 |
| --- | --- |
| `ok` | 当前有条目且相关来源健康；校验一致性、摘要和未来截止时间后可替换 |
| `empty` | 相关来源有有效的当前快照，但该列表无条目；有未来截止时间并完成全部校验后可原子替换为空集合 |
| `degraded` 且有条目、未来截止时间 | 部分来源异常，仍有未到期的获准证据；消费者明确允许降级同步时可经完整校验使用这些条目，不能称为全面健康 |
| `degraded` 且 `valid_until=null` | 失败且没有有效覆盖；停止该次同步，不把空输出视作健康空快照 |
| `stale` / `unavailable` | 陈旧或缺少获准的相关来源；停止该次同步，本地旧规则按原截止时间清理 |

source 状态与 list 状态是两层概念。例如 Feodo 首次返回陈旧快照，source 和 C2
列表为 `stale`；若请求失败且没有存活证据，source 为 `error`，C2 列表可为
`degraded` 且截止时间为 `null`。某源失败但其他来源或上次证据仍有效时，非空列表
可以是 `degraded` 且有未来截止时间。不能一律把 degraded 视为有效或无效。

## 格式与设备适配

文件采用 UTF-8、LF；非空文件末尾有 LF，零条目纯 IP 文件为零字节。Web 封禁和
观察互斥；observe 仅用于观察、验证或限速，不能直接升级为永久封禁。C2 是目的
地址，适用于出站防护；network 是 CIDR 网段，作用范围大，应由网络策略决定
应用方向。相同目标可出现在不同用途的列表中，不能跨用途去重丢掉规则。

确认设备分别支持 IPv4/IPv6、CIDR、注释、条目容量和原子替换。若只能接受纯
CIDR，在验证原始摘要后再本地转换，并在旁存的许可记录中保留原日期、版权及
署名；转换合规需服从具体来源许可。超容量、部分上传或转换失败应拒绝替换，
不能静默截断。厂商 API 自动推送不属于本阶段。

私有白名单应在消费者本地导入时应用，不提交组织资产或内部规则。项目公开
白名单只用于共同适用、可公开说明的误报排除；任何地址重叠会使整个对应网段
被保守排除。反馈方式见[运维文档](operations.md)。
