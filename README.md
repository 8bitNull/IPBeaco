# IPBeaco

IPBeaco 将通过公开再分发准入的威胁来源加工为八个静态 IPv4/IPv6 列表，并公开
来源、用途、状态、有效期和摘要。默认无需 API 密钥；每天 UTC 00:17（北京时间
08:17）由 GitHub Actions 更新，持久状态保存在独立 `data` 分支，站点由 Pages 发布。

**项目仓库：[8bitNull/IPBeaco](https://github.com/8bitNull/IPBeaco)。
[订阅站点](https://8bitnull.github.io/IPBeaco/)已上线，
[当前列表状态](https://8bitnull.github.io/IPBeaco/lists/status.json)可直接查询。**
2026-10-04 首次线上运行已完成；当次八份列表均为 0 条，无有效防护覆盖。来源复核时，
blocklist.de 与 Spamhaus DROP 的公共再分发依据未明确，保持禁用；Feodo 的 CC0
依据明确，已启用采集，但返回的推荐快照生成于 2026-03-04，诊断拒绝其陈旧数据。
目前 Web、网段、C2 均无当前有效覆盖。文件存在、条数为零或构建成功不代表来源健康。
首次采集该快照时，Web/网段列表为 `unavailable`，C2 为 `stale`，有效期均为 `null`；
若后来网络失败，C2 也可能显示 `degraded` 且无有效期，以当次状态为准。

## 列表与用途

| 路径 | 方向与用途 | 格式 |
| --- | --- | --- |
| [lists/block-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/block-ipv4.txt) | Web 入站请求的来源 IPv4，达到封禁证据门槛 | 每行一个 IP |
| [lists/block-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/block-ipv6.txt) | Web 入站请求的来源 IPv6，达到封禁证据门槛 | 每行一个 IP |
| [lists/observe-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/observe-ipv4.txt) | Web 入站来源 IPv4，仅观察、验证或限速 | 每行一个 IP |
| [lists/observe-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/observe-ipv6.txt) | Web 入站来源 IPv6，仅观察、验证或限速 | 每行一个 IP |
| [lists/network-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/network-ipv4.txt) | 网络层 DROP IPv4 网段，按设备和网络策略使用 | CIDR 与 `#` 来源/版权注释 |
| [lists/network-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/network-ipv6.txt) | 网络层 DROP IPv6 网段，按设备和网络策略使用 | CIDR 与 `#` 来源/版权注释 |
| [lists/c2-ipv4.txt](https://8bitnull.github.io/IPBeaco/lists/c2-ipv4.txt) | 出站连接的 C2 **目的** IPv4 | 每行一个 IP |
| [lists/c2-ipv6.txt](https://8bitnull.github.io/IPBeaco/lists/c2-ipv6.txt) | 出站连接的 C2 **目的** IPv6 | 每行一个 IP |

Web 封禁需要两个独立家族的有效证据，或配置中明确认可的强单源；观察与封禁档
互斥。同一家族的多个端点不算独立证据。网段、C2 不参与 Web 档位合并，不能将
C2 目的地址作为攻击者来源导入入站 WAF。项目不聚合 IP 成大网段、不展开 CIDR，
也不接收 ASN-DROP。

列表在更新工作流中生成到 `site/lists/` 并部署至 Pages，**不会提交到 main 代码分支**；
上表链接可直接下载，`data` 分支仅保存持久状态。Fork 后的 URL 模板为
`https://<owner>.github.io/IPBeaco/lists/block-ipv4.txt`，将 `<owner>` 替换为自己的账号。
全部 URL、摘要及一致性同步步骤见[订阅文档](docs/subscriptions.md)。
**TXT 本身没有失效逻辑**，必须配合 `lists/status.json` 和 `lists/metadata.json`。

导入前核对 WAF/防火墙的条目容量、IPv6 支持、IP/CIDR 语法、注释处理和原子替换
能力。纯 IP 列表不等同厂商规则语法；网段列表可能只有注释而没有 CIDR，不能按
字节数判断是否为空。超容量时应停止该次导入，不能静默截断。厂商 API 适配或自动
推送另开任务；本项目不调用设备 API。

## 本地运行

使用 Python **3.12**，在项目目录安装已锁定的运行依赖与项目：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-index --no-build-isolation --no-deps -e .
ipbeaco --help
ipbeaco inspect-source --config config --source feodo-recommended
```

`inspect-source` 是只读诊断，不修改状态、不启用来源，也不证明公共再分发已获准。
Feodo 此次预期报 `Run error: stale_snapshot` 并返回 1。该宿主机的 `NO_PROXY`
IPv6 排除语法不被 HTTPX 接受；本次诊断只对命令进程使用
`NO_PROXY= no_proxy= ipbeaco inspect-source ...`，保留代理设置和 TLS 校验。
正常环境无需这个调整。

纯本地首次生成示例（目录名是本地路径，不是线上部署）：

```bash
ipbeaco run --config config --state local-state --out local-site \
  --build-id local-first --bootstrap
ipbeaco validate --site local-site
```

仅在 `local-state` 确实没有状态对时 bootstrap，之后读取原状态并每次使用新的
输出目录。清理过期数据不会因全部来源失败而暂停。validate 校验产物一致性和时间，
允许明确标注不可用的空列表；通过 validate 不代表当前有威胁情报覆盖。

## 部署、来源与反馈

Fork 后需启用 Actions，并将 Settings → Pages → Source 设为 **GitHub Actions**。
在获准发布的仓库中首次手动触发更新，仅在远端没有 `data` 分支时开启
`bootstrap_state`；后续每天自动更新。完整设置、状态保护与恢复见
[运维文档](docs/operations.md)，许可、时间语义与本次四项诊断见
[来源准入记录](docs/sources.md)。每日调度可能延迟，且慢于 Feodo 建议的更新频率。

误报通过仓库的 **误报反馈** Issue 模板由用户手动提交，注明 IP/CIDR、列表名、
`build_id`、理由和期望处理，避免附私有日志或密钥。项目白名单
`config/allowlist.txt` 随仓库公开并影响所有订阅者；仅本地例外应保存在消费者的
私有白名单中。任何白名单与网段重叠时，项目保守排除整个网段。

公开数据许可逐来源判断，代码不授予上游数据许可。AbuseIPDB 只保留默认关闭的
扩展配置，不实现拉取或公开输出。测试样本仅供离线测试，不属于生产来源。
