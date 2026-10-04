# 运行与发布

主分支 `main` 保存代码、配置、规则、文档和测试；独立 `data` 分支只保存
`state.json` 与 `state.sha256`。Actions 缓存和 Pages artifact 都不能替代持久状态。

## 首次启用

首次线上运行属于发布检查阶段，需要已授权的 GitHub 仓库和远端账号。在仓库
Settings → Pages 中将 Source 设为 **GitHub Actions**，确认 Actions 可使用下表权限，
以及 `github-pages` 环境允许 `main` 部署。当前本地工作区尚无已连接的远端，
未执行真实 GitHub 更新或 Pages 部署，也没有在线站点链接。

将工作流发布到默认分支 `main` 后，手动运行 **Update IP intelligence**，选择
`main`，仅在远端确实没有 `data` 分支的首次运行勾选 `bootstrap_state`。后续运行
保持关闭。状态不存在、损坏或远端不可达时先排查原因；不能通过删除状态再启动
来恢复。更新工作流只接受定时与手动事件，并在非 `main` 分支跳过任务。

| 工作流 | 权限 | 用途 |
| --- | --- | --- |
| CI | `contents: read` | 主分支 push、以 main 为目标的 pull request，只读检出与离线检查 |
| Update | `contents: write` | 检出代码、读取与普通推送 data 状态 |
| Update | `pages: write` | 读取 Pages 配置并创建 Pages 部署 |
| Update | `id-token: write` | 获取部署所需的 OIDC 身份令牌 |

更新使用自动提供的 `GITHUB_TOKEN`，无需来源密钥或另行配置个人 token。
`configure-pages` 不自动启用 Pages；首次设置在仓库界面完成。CI 不运行带写权限的
更新步骤，也不使用 `pull_request_target`。Actions 中状态提交使用已知的
`github-actions[bot]` 身份，仅作用于该次 Git 调用；本地使用操作者已配置的身份。

## 调度、串行和失败

每日 UTC **00:17**（北京时间 **08:17**）调度，定时任务可能延迟，不承诺准点。
手动与定时更新共享 `ipbeaco-publish` 并发组，`cancel-in-progress: false`，避免中途
取消状态保存或部署。将来增加任何写状态或发布工作流，也必须使用同一并发组。
GitHub 的并发排队不保证每个待运行事件都执行，不能把它当作消息队列。

固定顺序为：拉取已校验状态 → 重新采集、清理并生成新站点 → 提交状态 → 按实际
当前时间校验 → 上传站点 → 再按实际当前时间校验 → 部署。任何步骤失败均停止后续
步骤；不使用 `continue-on-error` 或 `always()` 绕过失败。公开 `status.json` 中的
`build_id` 是该产物版本，`data` 分支最新状态不一定已经上线。

必须禁止删除 `data` 分支和强推、回退其历史（配置保护规则或 ruleset，并确保
Actions 的正常前进推送仍被允许）。状态写入先核对精确父版本，再进行普通非强制
push；这可拒绝同时向前写入的旧候选，但不保护管理员强制回退或删除造成的竞态。
遇到远端版本冲突，应重新拉取、重新运行，不能直接 rebase 或强推旧候选状态。

部署失败时已经提交的状态应保留。**重新运行整个更新任务**，或从 `main` 重新手动
触发；不要仅重试部署步骤或重新发布上次的 Pages artifact。整个更新 job 重跑会
拉取最新状态，产生新的 `${run_id}-${run_attempt}` 构建，并重新计算证据有效期。
旧 artifact 的时间戳与内容不会因为下载或重试部署而变新。

Web 封禁证据最长 72 小时、观察证据最长 7 天；网段和 C2 快照最长 48 小时，
更短的上游期限优先。过期证据即使来源不可用也要正常删除。等待期间到期的旧产物
必须被 `validate` 拒绝；已经上线的静态文件不会自动消失，消费者还需检查
`status.json` 的有效期及文件摘要。

在有已授权远端和已配置本地 Git 身份的干净检出中，完整重建的命令为：

```bash
ipbeaco state pull --remote origin --dir state --revision-file state-base.txt
ipbeaco run --config config --state state --out site --build-id "manual-$(date -u +%Y%m%dT%H%M%SZ)"
ipbeaco state push --remote origin --dir state --revision-file state-base.txt
ipbeaco validate --site site
# 上传 site 前执行上面的校验；真正部署前再次执行：
ipbeaco validate --site site
```

`site` 必须是新目录，`run` 不覆盖旧产物。首次创建远端状态时仅在第一条命令加
`--bootstrap`；`state pull` 已创建有效初始状态后，`run` 不需要 bootstrap。
本地命令只生成并提交候选，Pages 上传与部署由授权的更新工作流执行。

## 依赖与 Actions 版本

Python 固定 **3.12**。CI 从 `requirements-dev.lock`、更新从 `requirements.lock`
使用 `pip install --require-hashes` 安装。运行锁包含 editable 构建所需的
setuptools；随后 `pip install --no-index --no-build-isolation --no-deps -e .`
使用已锁定的后端，不另行获取未锁定的构建依赖。运行锁可由已安装开发锁的
Python 3.12 环境重建（保留开发锁中的已有版本约束）：

```bash
pip-compile --build-deps-for editable --no-build-isolation --allow-unsafe \
  --generate-hashes --strip-extras --constraint requirements-dev.lock \
  --output-file requirements.lock pyproject.toml
```

2026-10-04 核对官方 README、版本 tag 的 `action.yml` 和官方 Pages starter 后采用：

| Action | 版本 | 运行时与官方依据 |
| --- | --- | --- |
| checkout | `v7` | Node 24；[README](https://github.com/actions/checkout/blob/main/README.md)、[版本元数据](https://github.com/actions/checkout/blob/v7/action.yml) |
| setup-python | `v7` | Node 24；[README](https://github.com/actions/setup-python/blob/main/README.md)、[版本元数据](https://github.com/actions/setup-python/blob/v7/action.yml) |
| configure-pages | `v5` | Node 20；[版本元数据](https://github.com/actions/configure-pages/blob/v5/action.yml)、[Pages starter](https://github.com/actions/starter-workflows/blob/main/pages/static.yml) |
| upload-pages-artifact | `v3` | composite，内部 upload-artifact v4；[README](https://github.com/actions/upload-pages-artifact/blob/main/README.md)、[版本元数据](https://github.com/actions/upload-pages-artifact/blob/v3/action.yml) |
| deploy-pages | `v5` | Node 24；[版本元数据](https://github.com/actions/deploy-pages/blob/v5/action.yml)、[Pages starter](https://github.com/actions/starter-workflows/blob/main/pages/static.yml) |

deploy-pages 的 README 示例仍引用 v4，当前官方静态 Pages starter 已使用 v5；
v5 tag 元数据与 main 一致，因此这里采用 v5。部署权限依据
[deploy-pages 官方安全要求](https://github.com/actions/deploy-pages/blob/main/README.md#security-considerations)。
Node 24 action 要求 Actions Runner 至少 v2.327.1；checkout 的凭据分离机制在容器
action 中使用认证 Git 时还要求至少 v2.329.0。本工作流使用 GitHub 托管
`ubuntu-latest`，没有容器 action；将来迁移自托管 runner 前应重新核对版本。

## 本地验证

安装开发锁后运行：

```bash
ruff check .
ruff format --check .
python -m pytest -q
actionlint .github/workflows/ci.yml .github/workflows/update.yml
python -m pytest tests/test_cli.py::test_failed_deployment_retry_rejects_expired_artifact_and_rebuilds_committed_state -q
```

上述延迟重试测试使用本地 bare Git 远端、合成来源与可控时钟，模拟状态已提交但
未能部署。时钟推进 8 天后旧产物被拒绝；从远端恢复状态并在上游不可用时全量
重跑，八个列表均清空、状态正常前进且防复活标记保留。PR 测试不连接真实来源，
不会因动态上游状态失败。首次实际 GitHub/Pages 部署仍需在发布阶段验证。

## Fork、停止运行与当前覆盖

Fork 后在 Actions 页面明确启用工作流，并允许仓库所需的读写权限；同时设置
Pages 的 GitHub Actions 来源、`github-pages` 环境和 `main` 部署约束。先保护
`data` 不被删除或强制回退，再首次手动 bootstrap，确认生成的 status、状态提交
和 Pages 部署对应同一构建，随后使用每日调度。不能因 fork 后 `data` 存在就再次
bootstrap，也不能把缓存当作初始状态。

GitHub 定时事件只在默认分支执行，可能因队列负载延迟甚至丢失；公共仓库在
连续 60 天无活动后，定时工作流可能被自动禁用，需检查并重新启用。参见
[官方 schedule 说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。
检查 Actions 的最近运行、data 的普通前进提交及公开 status，不能只依靠 cron。
项目每天采集一次，比 Feodo 建议的每 5–15 分钟慢，不承诺实时 C2 防护。

2026-10-04 来源复核详见[来源记录](sources.md)：Web 和网络来源未获公共准入，
Feodo 获 CC0 准入但推荐快照陈旧，因此三类均无当前有效覆盖。构建或部署成功
只证明生成/发布流程完成，不表示有健康来源。全部任务停止后，Pages 上的静态
TXT 仍可被下载；客户端必须按上次有效截止时间自行移除规则，不能无限保留。
同步故障、健康空快照与部分降级的处理见[订阅协议](subscriptions.md)。

## 损坏状态的恢复与历史增长

读取时缺失一份文件、摘要不匹配或 schema/时间字段错误都会拒绝状态。先停止写
状态的工作流，保留故障提交、原文件对和运行记录供排查；远端访问失败先处理
访问，不将它误判为首次运行。**禁止删除 data、强推、reset 后推回旧历史，或用
bootstrap 清空恢复。** 分支保护需覆盖维护者及管理操作，恢复也遵守它。

若只是本地候选损坏，保存故障候选后从远端重新 `state pull`，完整重跑。若远端
最新提交损坏，在已获准操作的干净检出中恢复如下：

1. 停止所有写入者并记录当前远端 data 的完整 commit ID。检查历史，找到最近
   **完整且可验证**的提交，将该提交的 `state.json` 与 `state.sha256` 一起导出
   到新的本地恢复目录，不能混用不同提交的两份文件。
2. 使用 `ipbeaco.state.load_state` 验证恢复目录的摘要、schema 和时间；检查
   故障提交前后的来源和运行记录，确认恢复保留最新可信的快照标记、反复活
   标记及准入撤销信息。不能任意选更旧状态覆盖这些标记；若后续可信变化未在
   恢复对中，需先恢复/重放它们。无法证明完整性时继续停止发布，让消费者按
   原截止时间失效，不能用丢失标记的旧状态强行运行。
3. 将记录的**当前远端 tip**（即故障 tip，不是历史恢复提交）写入单独的
   revision 文件，以它为 expected parent，通过普通 `ipbeaco state push`
   提交恢复对。这样创建故障 tip 的新子提交，保留完整历史；不移动分支回旧
   提交。先检查最新远端 tip 仍未变；遇到版本冲突重新排查，不能强推。
4. 恢复成功后重新拉取并完整运行采集、到期清理、校验和部署。使用新的输出
   目录和 build_id，重新计算实际有效期，不重发历史 artifact。重新启用调度，
   检查公开 status 和状态分支；保存故障原因及恢复依据。

验证已导出的恢复对（只读）的示例，`recovery-state` 是新建的本地恢复目录：

```bash
python -c 'from pathlib import Path; from ipbeaco.state import load_state; load_state(Path("recovery-state")); print("state pair verified")'
```

`state push` 会校验候选和当前父版本；它不能判断操作者选用的历史状态是否丢失
了后续防复活信息，第二步的完整性审查不可省略。若没有可验证的完整历史提交，
不能自动建空状态恢复，需恢复可信备份并完成相同审查。

每次更新都会为 data 增加一份完整状态提交，Git 历史会持续增长。状态正文仅
保留最近 30 天运行明细，防复活标记继续保留；这不清理 Git 的旧提交。定期监测
仓库体积，并保留可信备份；不通过删分支、强推压缩历史或回退历史来节省空间。
若未来需要归档/迁移，应单独设计保留完整性和反复活信息的方案，不在当前运维
中绕过状态保护。

## 误报与白名单

用户在仓库 Issues 中选择“误报反馈”模板，手动提供 IP/CIDR、八列表之一的名称、
订阅时的 build_id、可公开的理由和希望的处理。不自动创建 Issue 或联系来源方；
不要提交私有日志、内部资产、凭证、密钥或 token。反馈不自动移除规则，需结合
metadata 的来源、原因和时间复核。

`config/allowlist.txt` 是随主分支公开的项目白名单，每行一 IP 或 CIDR，允许
空行及 `#` 注释，影响所有订阅者。只有共同适用、可以公开说明的排除才加入；
公开 metadata 会记录白名单排除的目标、来源和原因。仅本地所需例外放在消费者
私有白名单，不上传组织资产。网段与任一白名单地址重叠时保守排除整个网段，
不会拆成残余网段；因此需评估影响范围。

## 获准远端后的实际发布验收

当前没有远端或本地作者身份，只交付本地结果，未 push、未修改 Pages 设置、
未部署，也未生成真实在线 URL。以后在已确定且获准发布的仓库中：发布 main
代码，按上述设置 Actions/Pages 和 data 保护，首次手动 bootstrap，检查 data
状态提交和 deploy 成功，再只读 GET 八个 TXT、status、metadata。按订阅协议
核对同一 build_id、原始摘要、条数、方向、证据期限和当时的来源状态，记录真实
URL。下载验收不向实际防火墙导入规则；没有完成该步骤不能称为项目已经上线。
