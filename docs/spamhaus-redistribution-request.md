# Spamhaus DROP 公共输出确认文案

状态：**待上游确认，本文不是授权记录**。IPv4/IPv6 DROP 仍未启用公共输出。
本项目已具备公共 network 导出功能；本地 DROP 命令与公共准入分离。

## 需要确认的范围

- IPBeaco 从官方 IPv4/IPv6 JSON 端点每天采集，将公网 CIDR 去重、排序并按白名单排除部分网段。
- CIDR 不展开、不聚合、不转为 ASN，也不混入 Web 攻击来源或 C2 列表。
- 在公开 GitHub Pages 提供可下载的 TXT 和包含来源/有效期的 JSON；下游包括防火墙与 WAF 用户。
- 在 TXT 注释及元数据保留上游生成日期、原始版权、条款链接及 The Spamhaus Project 署名。
- 希望确认该公共加工再分发方式，以及必须遵守的更新间隔、失败重试、有效期和下游义务。

## 可发送的英文文案

Subject: Permission clarification for public redistribution of processed Spamhaus DROP CIDRs

Hello Spamhaus team,

I maintain IPBeaco, an open-source project at https://github.com/8bitNull/IPBeaco.
We would like to fetch the official IPv4 and IPv6 DROP JSON datasets and make
processed CIDR lists publicly downloadable through GitHub Pages for firewall
and WAF users.

The processing would preserve the original CIDR boundaries, deduplicate and
sort entries, filter non-public networks, and omit entries that overlap a
project allowlist. We would not expand CIDRs into individual addresses,
aggregate ranges, or include ASN-DROP. Each TXT file and its accompanying
JSON metadata would preserve the upstream generation date, original copyright
notice, source and terms URLs, and credit to The Spamhaus Project.

Your DROP FAQ permits free download and use in products with attribution and
retention of the date and copyright text. Section 3.1 of the linked DROP Terms
of Use reserves intellectual property rights. Could you please confirm
whether the public redistribution described above is permitted, and identify
any additional conditions?

In particular, please clarify the permitted polling and failure-retry intervals,
the maximum retention period after the upstream generation timestamp, and any
conditions applying to downstream commercial or non-commercial consumers.
The FAQ contains both once-per-day and at-least-one-hour-apart wording; its
JSON-to-TXT example uses a 26-hour expiry. We would like to apply the correct
requirements to this public output.

We have not enabled public redistribution of DROP in this project pending
clarification. Thank you for your guidance.

## 当前参考依据

- https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/
- https://www.spamhaus.org/blocklists/do-not-route-or-peer/
- https://www.spamhaus.org/blocklists/drop-fair-use-policy/
- https://www.spamhaus.org/drop/terms/

确认后需记录回复出处、日期及适用条件，再更新来源准入、频率/时效处理、回归测试，
运行真实采集和发布验证。上游响应有可能只批准本地使用或要求额外条件，不能预设结果。
