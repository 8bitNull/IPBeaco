# IPBeaco Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立每天更新、可追溯且会过期的多源 IP 情报流水线，将 Web 两档、恶意网段和出站 C2 列表统一发布到 GitHub Pages 的 `lists/` 目录。

**Architecture:** Python 将各来源转换为统一快照，再计算证据有效期、白名单和用途分组，生成一次构建的全部静态产物。GitHub Actions 串行运行，先保存 `data` 分支状态，再部署 Pages；故障来源不能刷新旧证据寿命。三类列表共享流水线，因此本计划保持一个项目，分别实现和测试来源适配器及用途规则。

**Tech Stack:** Python 3.12、标准库 `dataclasses/ipaddress/tomllib/json/hashlib`、HTTPX 0.28.x、pytest 8.x、Ruff 0.x、GitHub Actions、GitHub Pages。Python 和依赖版本为本计划的实现选择；开发时生成锁定的依赖文件。

**Spec:** `docs/superpowers/specs/2026-10-04-ipbeaco-design.md`（已确认，包含后续确认的 `lists/` 路径）。

## Global Constraints

- GitHub Actions 每天 UTC 00:17（北京时间 08:17）调度，支持手动触发。定时执行可能延迟，不承诺准点。
- 主分支保存代码、来源配置、规则、文档和测试；独立 `data` 分支保存持久状态。
- 所有更新和部署任务使用同一并发组，串行执行；不在中途取消正在保存状态或部署的任务。
- Actions 缓存仅用于加速，不能作为唯一状态存储。
- Web 封禁证据最长有效 72 小时；观察证据最长有效 7 天，自观测时间计算。
- 网段和 C2 快照最长有效 48 小时；更短上游有效期优先。
- 上游时间超过当前时间 5 分钟时，不作为有效证据。
- Web 两档互斥，不跨用途去重掉网段或 C2 记录。
- 不把单 IP 自动聚合成更大的网段，不展开 CIDR 成海量 IP，不接收 ASN-DROP。
- 网段与白名单有任何地址重叠时，首版保守移除整个网段并记录原因。
- 默认无密钥；AbuseIPDB 仅保留禁用的扩展配置，不实现 API 拉取或公开其数据。
- 不调用防火墙 API，不主动扫描，不发送消息，不提供数据库、后台或查询服务。
- 公共状态和元数据只包含允许再分发的内容；代码许可不能替代数据许可。
- 来源失败、陈旧、不可用与合法空快照必须区分。未通过准入的来源不能贡献公共证据。
- 非首次有效快照的新增条目达到 1,000 且总量超过上一有效快照的 3 倍时，隔离该快照；正常到期删除继续执行。
- 运行明细保留最近 30 天；防止旧证据复活所需的标记不随明细清理。

---

## 执行起点、完成边界与任务顺序

当前仓库只有设计文档，本计划未创建任何业务代码。Git 已初始化在 `main`，尚无首次提交，作者姓名和邮箱未配置。执行前读取现有工作区指令和用户改动；只提交本任务文件。使用用户配置的作者身份，不能编造用户姓名或修改全局 Git 配置。身份缺失只阻止提交，不阻止本地实现和测试。

依赖顺序：1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12。任务 4 的三个适配器可以分别审查，但共享接口必须先完成。执行计划时再按所选技能准备隔离工作区；不要在编写计划阶段创建实现分支或启动子代理。

每项代码任务先写下列行为测试并确认因缺少目标行为失败，再实现、运行指定测试并提交。代码片段固定接口和关键算法，不是可直接部署的完整程序；各步明确列出的错误处理和验收同样必须实现。测试中的 `8.8.8.8` 等地址只作为离线格式样本，不能上传到实际威胁列表。

技术完成：离线全流程、规则、输出、持久化和部署控制均通过测试。生产完成：真实来源通过准入、成功提交状态并部署，URL 可用且至少一类确有有效覆盖。其他类别明确标记不可用，不能将八个文件存在等同于八类实际覆盖。

## 文件结构与职责

```text
pyproject.toml                          包、命令入口、测试与 lint 配置
requirements.lock                      运行依赖精确版本及哈希
requirements-dev.lock                  pytest、Ruff、构建工具依赖锁
.gitignore                             排除 .venv、缓存、state/、site/、临时下载
src/ipbeaco/
  __init__.py
  models.py                            不可变数据契约与异常
  config.py                            TOML 来源/策略配置、准入校验
  addresses.py                         IP/CIDR 规范化、公网与白名单判定
  fetch.py                             有界 HTTPS 获取及重试
  adapters/__init__.py                  明确的适配器注册表
  adapters/blocklist_de.py              分类 TXT 解析
  adapters/spamhaus.py                  DROP NDJSON 及尾部元数据解析
  adapters/feodo.py                     C2 推荐列表及时间/数量头解析
  state.py                             schema、校验和、原子本地保存
  temporal.py                          证据更新、过期、出现/消失标记
  policy.py                            Web 分档、网段/C2 选择、白名单
  export.py                            site/lists/ 与清单生成及校验
  pipeline.py                          从上次状态到新状态和产物的编排
  cli.py                               run、validate、inspect-source 命令
  git_store.py                         data 分支初始化、读取、提交与推送
config/sources.toml                     已核查的来源配置与禁用原因
config/policy.toml                      TTL、异常阈值、请求限制
config/allowlist.txt                    每行 IP/CIDR，支持 # 注释
tests/                                 按模块分文件的离线行为测试
tests/fixtures/                        合成快照、坏响应、来源配置
tests/factories.py                      明确的测试工厂
.github/workflows/ci.yml                PR 与主分支离线测试
.github/workflows/update.yml            定时采集、状态提交、Pages 部署
.github/ISSUE_TEMPLATE/false-positive.yml 误报反馈入口
docs/sources.md                         准入依据、当前限制和更新时间
docs/operations.md                      部署、故障恢复及状态分支说明
docs/subscriptions.md                   八个 URL、设备兼容与失效处理
README.md                              项目入口、运行与订阅说明
```

运行产物：`site/lists/{block,observe,network,c2}-ipv{4,6}.txt`、`site/lists/status.json`、`site/lists/metadata.json`、`site/index.html`、`site/.nojekyll`。`site/` 不提交主分支。独立状态分支只保存 `state.json` 和 `state.sha256`，历史运行清单存于 state 内。

## Task 1：建立可验证的数据契约和来源配置

**Files:** Create `pyproject.toml`、锁文件、`.gitignore`、`src/ipbeaco/{__init__,models,config}.py`、`config/{sources,policy}.toml`、`config/allowlist.txt`、`tests/{__init__,factories,test_config}.py`。

**Interfaces:** 后续模块统一使用下列类型。时间使用带时区的 `datetime`，禁止 naive datetime。序列化时间为 UTC ISO 8601，字典键是来源 ID；身份字段不接受任意额外键。

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Purpose = Literal['web', 'network', 'c2']
TimeMode = Literal['observed', 'rolling', 'unknown', 'snapshot']
Tier = Literal['block', 'observe']

@dataclass(frozen=True)
class SourceSpec:
    id: str
    family: str
    purpose: Purpose
    adapter: str
    url: str
    enabled: bool
    public_approved: bool
    license_url: str
    reviewed_at: datetime | None
    time_mode: TimeMode
    max_tier: Tier = 'observe'
    trusted_single: bool = False
    independent: bool = False
    category: str = 'unknown'
    window_hours: int | None = None
    attribution: str = ''
    disabled_reason: str = ''
    ip_versions: tuple[int, ...] = (4, 6)

@dataclass(frozen=True)
class InputRecord:
    target: str
    category: str
    observed_at: datetime | None = None

@dataclass(frozen=True)
class Snapshot:
    source_id: str
    fetched_at: datetime
    generated_at: datetime | None
    records: tuple[InputRecord, ...]
    sha256: str
    upstream_expires_at: datetime | None = None
    notices: tuple[str, ...] = ()

@dataclass(frozen=True)
class Outcome:
    source_id: str
    attempted_at: datetime
    snapshot: Snapshot | None = None
    error: str | None = None

@dataclass(frozen=True)
class Evidence:
    source_id: str
    target: str
    category: str
    first_seen_at: datetime
    observed_at: datetime | None
    snapshot_at: datetime | None
    time_basis: TimeMode
    block_until: datetime | None
    observe_until: datetime | None
    expires_at: datetime

@dataclass(frozen=True)
class Presence:
    first_seen_at: datetime
    present: bool

@dataclass(frozen=True)
class SourceState:
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    status: str = 'unavailable'
    generated_at: datetime | None = None
    valid_until: datetime | None = None
    accepted_count: int = 0
    sha256: str | None = None
    notices: tuple[str, ...] = ()
    error: str | None = None

@dataclass(frozen=True)
class RunRecord:
    build_id: str
    generated_at: datetime

@dataclass(frozen=True)
class State:
    schema_version: int = 1
    evidence: tuple[Evidence, ...] = ()
    presence: dict[str, dict[str, Presence]] = field(default_factory=dict)
    sources: dict[str, SourceState] = field(default_factory=dict)
    history: tuple[RunRecord, ...] = ()

@dataclass(frozen=True)
class Settings:
    block_hours: int = 72
    observe_hours: int = 168
    snapshot_hours: int = 48
    future_skew_seconds: int = 300
    anomaly_new: int = 1000
    anomaly_ratio: int = 3
    max_bytes: int = 10_485_760
    timeout_seconds: int = 20
    attempts: int = 3

@dataclass(frozen=True)
class Config:
    sources: tuple[SourceSpec, ...]
    settings: Settings
    allowlist: tuple[str, ...]

class ConfigError(ValueError):
    pass

class SourceError(ValueError):
    pass

class StateError(ValueError):
    pass
```

`config.py` 提供 `load_config(root: Path) -> Config`、`validate_source(spec: SourceSpec) -> None`。`tests/factories.py` 使用下面的实际工厂；它只供离线测试使用，不能进入生产配置。

```python
import hashlib
from dataclasses import replace
from datetime import datetime, timezone
from ipbeaco.models import InputRecord, Snapshot, SourceSpec

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)

def source(**changes) -> SourceSpec:
    base = SourceSpec(
        id='test-web', family='test-family', purpose='web',
        adapter='blocklist_de', url='https://example.invalid/feed.txt',
        enabled=True, public_approved=True,
        license_url='https://example.invalid/license', reviewed_at=NOW,
        time_mode='observed', max_tier='block', independent=True,
        category='web_attack',
    )
    return replace(base, **changes)

def snapshot(*targets: str, **changes) -> Snapshot:
    raw = ''.join(target + '\n' for target in targets).encode()
    base = Snapshot(
        source_id='test-web', fetched_at=NOW, generated_at=NOW,
        records=tuple(InputRecord(target, 'web_attack', NOW) for target in targets),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    return replace(base, **changes)
```

- [ ] **1. 写配置行为测试与工厂。** 禁用源允许未批准，启用源必须授权并有 reviewed_at、license_url；禁止重复 ID、非 HTTPS、未知 adapter、空 family。`snapshot` 模式只能用于 network/c2；`rolling` 必须有 0 < window_hours ≤ 72。unknown 不得直接封禁。启用 AbuseIPDB 返回明确配置错误。

```python
import pytest
from ipbeaco.config import validate_source
from ipbeaco.models import ConfigError
from tests.factories import source

def test_unapproved_source_cannot_be_enabled():
    with pytest.raises(ConfigError, match='public_approved'):
        validate_source(source(public_approved=False))
```

- [ ] **2. 建开发环境并运行失败测试。** `python3.12 -m venv .venv`，激活后安装 `pytest>=8,<9`、`httpx>=0.28,<0.29`、`ruff>=0.11,<1`、`pip-tools>=7,<8`；`python -m pytest tests/test_config.py -q` 必须因尚无配置校验失败。
- [ ] **3. 实现模型和 TOML 校验。** 根据上面 dataclass 定义实现；错误包括来源 ID 和字段名，不输出配置全文。`pyproject.toml` 指定 `requires-python = '>=3.12,<3.13'`、src 布局和 `ipbeaco = 'ipbeaco.cli:main'`。将上面 Settings 数值写入 `policy.toml`。blocklist.de/apache、DROP v4/v6 配置默认 disabled，记录设计中的未通过原因；Feodo 的 CC0 可记录为已批准，但陈旧数据必须被后续时间校验拒绝。AbuseIPDB 仅以单独 `[optional.abuseipdb] enabled=false` 保存，不构造可运行 SourceSpec。

生产配置为 `[[sources]]` 数组，字段与 SourceSpec 同名，省略可空时间由 loader 转为 None，`ip_versions` 转为 tuple。固定四个 ID、地址与时间模式如下：

| ID | URL | purpose / time_mode / 地址族 |
| --- | --- | --- |
| `blocklist-de-apache` | `https://lists.blocklist.de/lists/apache.txt` | web / unknown / 4,6 |
| `spamhaus-drop-v4` | `https://www.spamhaus.org/drop/drop_v4.json` | network / snapshot / 4 |
| `spamhaus-drop-v6` | `https://www.spamhaus.org/drop/drop_v6.json` | network / snapshot / 6 |
| `feodo-recommended` | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` | c2 / snapshot / 4,6 |

同一提供方设置相同 family。blocklist 未经分类和时间审核只能 max_tier=observe；禁止根据文件名默认 trusted_single=true。IPsum 仅在来源文档列为未启用候选，不建立运行配置。`policy.toml` 使用 `[policy]` 表，键与 Settings 同名。
- [ ] **4. 测试并锁定依赖。** `python -m pip install -e .`；运行 `python -m pytest tests/test_config.py -q`。使用 `pip-compile --generate-hashes --output-file requirements.lock pyproject.toml` 和 `pip-compile --extra dev --generate-hashes --output-file requirements-dev.lock pyproject.toml`；CI 按锁文件安装，不在每次更新时升级依赖。
- [ ] **5. 提交。** `git add pyproject.toml requirements.lock requirements-dev.lock .gitignore src/ipbeaco config tests`；`git commit -m 'feat: define source configuration and evidence contracts'`。

## Task 2：公网地址标准化和白名单

**Files:** Create `src/ipbeaco/addresses.py`、`tests/test_addresses.py`。

**Interfaces:** `normalize_target(text: str, purpose: Purpose) -> str` 非法时抛 SourceError；`is_allowed(target: str, allowlist: tuple[str, ...]) -> bool` 返回是否命中白名单；`sort_key(target: str) -> tuple[int, int, int]` 按地址族、数值地址、前缀排序。

- [ ] **1. 写离线边界测试。** 覆盖 IPv6 压缩、前后空白、私网/回环/链路本地/多播/文档地址、IPv4 映射 IPv6、整段跨越特殊用途空间、含主机位 CIDR 拒绝、web/c2 拒绝 CIDR、network 要求 CIDR。

```python
from ipbeaco.addresses import is_allowed, normalize_target

def test_allowlist_ip_exempts_whole_overlapping_network():
    assert is_allowed('8.8.8.0/24', ('8.8.8.8',))
    assert not is_allowed('8.8.4.0/24', ('8.8.8.8',))

def test_ipv6_is_canonical():
    assert normalize_target('2606:4700:4700:0:0:0:0:1111', 'web') == '2606:4700:4700::1111'
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_addresses.py -q`。
- [ ] **3. 实现。** 使用 `ipaddress.ip_address` / `ip_network(strict=True)`；白名单先转成 /32 或 /128 网络，再用同族 `.overlaps()`。公网判断不仅检查两个端点：用 Python 3.12 对应的固定特殊用途网段清单逐项检查相交，拒绝含非公网地址的整个 CIDR。清单和 Python 小版本升级需要运行固定回归样本；显式拒绝 multicast、unspecified 和 IPv4-mapped IPv6，避免标准库 `is_global` 的特殊语义漏网。

```python
def is_allowed(target, allowlist):
    from ipaddress import ip_network
    candidate = ip_network(target)
    return any(candidate.version == rule.version and candidate.overlaps(rule)
               for rule in map(ip_network, allowlist))
```

- [ ] **4. 运行测试。** `python -m pytest tests/test_addresses.py tests/test_config.py -q`。
- [ ] **5. 提交。** `git add src/ipbeaco/addresses.py tests/test_addresses.py`；`git commit -m 'feat: normalize public addresses and apply allowlists'`。

## Task 3：有界、可测试的下载器

**Files:** Create `src/ipbeaco/fetch.py`、`tests/test_fetch.py`。

**Interfaces:** `download(url: str, settings: Settings, client: httpx.Client) -> bytes`。调用者传入 client；线上 client 启用 TLS 校验、`follow_redirects=False`，按 `timeout_seconds` 设置连接和读取超时。错误抛 SourceError，只有错误代码和 HTTP 状态，不含响应正文或完整查询串。

- [ ] **1. 写 MockTransport 测试。** 测试 200、3xx 不跟随、403 不重试、429/5xx/超时最多 attempts 次、分块响应超限、解压后体积超限、HTML 响应拒绝。

```python
import httpx
import pytest
from ipbeaco.fetch import download
from ipbeaco.models import Settings, SourceError

def test_oversized_body_rejected():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b'12345'))
    with httpx.Client(transport=transport) as client:
        with pytest.raises(SourceError, match='response_too_large'):
            download('https://example.invalid/list', Settings(max_bytes=4), client)
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_fetch.py -q`。
- [ ] **3. 实现流式读取和有限重试。** 累计 `iter_bytes()` 解压后长度，超过上限立即停止；重试等待 1 秒、2 秒，测试 monkeypatch 模块的 `time.sleep`。不缓存原始响应到 Git；不支持从任意 URL 读取本地文件。Content-Type 为 HTML 或正文以 HTML 文档起始时返回 `unexpected_html`。

```python
parts, size = [], 0
for chunk in response.iter_bytes():
    size += len(chunk)
    if size > settings.max_bytes:
        raise SourceError('response_too_large')
    parts.append(chunk)
```

- [ ] **4. 运行测试。** `python -m pytest tests/test_fetch.py -q`，确认重试测试不真实等待、不连接互联网。
- [ ] **5. 提交。** `git add src/ipbeaco/fetch.py tests/test_fetch.py`；`git commit -m 'feat: add bounded threat feed downloader'`。

## Task 4：实现三类来源适配器

**Files:** Create `src/ipbeaco/adapters/{__init__,blocklist_de,spamhaus,feodo}.py`、`tests/test_adapters.py`、`tests/fixtures/{blocklist,drop,feodo}/` 合成样本。

**Interfaces:** 各文件暴露 `parse(raw: bytes, spec: SourceSpec, fetched_at: datetime) -> Snapshot`；注册表 `PARSERS` 键为 `blocklist_de`、`spamhaus_drop`、`feodo`。parser 只提取数据和时间，不决定最终封禁。未知行、时间格式错误、数量声明不符抛 SourceError，不静默从任意文本搜 IP。

- [ ] **1. 写三个格式的行为测试。** blocklist 分类 TXT 无可靠时间时生成时间必须为空；DROP 是每行 JSON，尾部 timestamp/copyright 元数据与 cidr/sblid 条目区分；Feodo 提取 `Last updated`、`DstIP`、`END N entries`，已验证合法空文件可解析为空。

```python
from dataclasses import replace
from ipbeaco.adapters import feodo, spamhaus
from tests.factories import NOW, source

def test_feodo_keeps_upstream_time_not_download_time():
    raw = (b'# Last updated: 2026-03-04 14:28:39 UTC\n'
           b'# DstIP\n8.8.8.8\n# END 1 entries\n')
    spec = source(purpose='c2', adapter='feodo', time_mode='snapshot')
    parsed = feodo.parse(raw, spec, NOW)
    assert parsed.generated_at.month == 3
    assert parsed.fetched_at == NOW

def test_drop_retains_copyright():
    raw = (b'{"cidr":"8.8.8.0/24","sblid":"SBL-TEST"}\n'
           b'{"type":"metadata","timestamp":1791072000,"copyright":"TEST NOTICE"}\n')
    spec = source(purpose='network', adapter='spamhaus_drop', time_mode='snapshot')
    parsed = spamhaus.parse(raw, spec, NOW)
    assert parsed.records[0].target == '8.8.8.0/24'
    assert 'TEST NOTICE' in parsed.notices
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_adapters.py -q`。
- [ ] **3. 实现解析和样本。** blocklist 的 category 取配置，默认只适用于候选 Web 分类；无时间的纯 TXT 使用 unknown 策略，不能拿 HTTP Date 当观测时间。DROP 校验所有行、元数据唯一且时间有效，保留版权、来源、SBL 关联到解析审计信息（目标证据中采用 category=`network_drop`，SBL 关联保存在 notices 或后续扩展的公开来源详情，不作为时间依据）。Feodo 只读取推荐列表，category=`botnet_c2`。三者使用原始字节 SHA-256、UTC、`InputRecord`，在 temporal 阶段拒绝陈旧快照。

```python
PARSERS = {
    'blocklist_de': blocklist_de.parse,
    'spamhaus_drop': spamhaus.parse,
    'feodo': feodo.parse,
}
```

- [ ] **4. 运行测试。** `python -m pytest tests/test_adapters.py tests/test_addresses.py -q`。增加 IPv6 DROP、空合法快照、HTML、截断 NDJSON、重复/缺失元数据、Feodo 数量不匹配和错误时间样本。
- [ ] **5. 提交。** `git add src/ipbeaco/adapters tests/test_adapters.py tests/fixtures`；`git commit -m 'feat: parse web network and C2 feeds'`。

## Task 5：校验和保护的持久状态

**Files:** Create `src/ipbeaco/state.py`、`tests/test_state.py`。

**Interfaces:** `encode_state(state: State) -> bytes`、`decode_state(raw: bytes) -> State`、`load_state(directory: Path, *, bootstrap: bool = False) -> State`、`save_state(state: State, directory: Path) -> None`。目录固定包含 `state.json` 和 `state.sha256`。

- [ ] **1. 写状态往返和损坏测试。** 测试证据、时间、presence 标记和来源状态完整往返；未知 schema、缺少文件、错误摘要、截断 JSON、无时区时间、额外字段均拒绝。只有显式 bootstrap 且两个文件都不存在时返回 State()。

```python
import pytest
from ipbeaco.models import State, StateError
from ipbeaco.state import load_state, save_state

def test_corruption_never_becomes_empty_state(tmp_path):
    save_state(State(), tmp_path)
    (tmp_path / 'state.json').write_text('{broken', encoding='utf-8')
    with pytest.raises(StateError):
        load_state(tmp_path, bootstrap=True)

def test_missing_state_requires_explicit_bootstrap(tmp_path):
    with pytest.raises(StateError):
        load_state(tmp_path)
    assert load_state(tmp_path, bootstrap=True) == State()
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_state.py -q`。
- [ ] **3. 实现 schema v1 和持久化。** 稳定 JSON 用 `sort_keys=True, separators=(',', ':'), ensure_ascii=False` 并加换行；每个模型显式解码，不用不受控的 `**json`。同目录临时文件写入、flush/fsync、`os.replace`；写数据后写摘要。两文件不能作为一对原子替换，断电产生不匹配时必须拒绝，下次从上次完整 Git 提交恢复，不能自动忽略摘要。

```python
raw = encode_state(state)
checksum = hashlib.sha256(raw).hexdigest() + '\n'
# 分别通过同目录临时文件 + os.replace 写入 state.json 与 state.sha256。
# 两者都成功后才允许后续 Git 提交和部署。
```

- [ ] **4. 运行测试。** `python -m pytest tests/test_state.py -q`；使用 monkeypatch 模拟第二次 replace 失败，确认 loader 拒绝不一致状态；保存时不截断 presence 标记。
- [ ] **5. 提交。** `git add src/ipbeaco/state.py tests/test_state.py`；`git commit -m 'feat: persist validated evidence state'`。

## Task 6：证据更新、失效与来源隔离

**Files:** Create `src/ipbeaco/temporal.py`、`tests/test_temporal.py`。

**Interfaces:** `advance(previous: State, config: Config, outcomes: tuple[Outcome, ...], now: datetime, build_id: str) -> State`。纯函数，不能网络访问、写文件或修改 previous。时间依据只读 SourceSpec，不信任输入记录自报的可信等级。

- [ ] **1. 写时间边界测试。** 首先证明无时间记录连续出现不会续期，以及两次下载的旧时间不变。使用实际模块接口构造场景：

```python
from dataclasses import replace
from datetime import timedelta
from ipbeaco.models import Config, Outcome, Settings, State
from ipbeaco.temporal import advance
from tests.factories import NOW, snapshot, source

def test_unknown_time_does_not_renew_on_download():
    spec = source(time_mode='unknown', max_tier='observe')
    cfg = Config((spec,), Settings(), ())
    snap = snapshot('8.8.8.8', generated_at=None)
    snap = replace(snap, records=tuple(replace(r, observed_at=None) for r in snap.records))
    first = advance(State(), cfg, (Outcome(spec.id, NOW, snap),), NOW, 'run-1')
    later = NOW + timedelta(days=8)
    second = advance(first, cfg,
                     (Outcome(spec.id, later, replace(snap, fetched_at=later)),),
                     later, 'run-2')
    assert second.evidence == ()
    assert second.presence[spec.id]['8.8.8.8'].first_seen_at == NOW
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_temporal.py -q`。
- [ ] **3. 实现时间计算和证据状态机。** 按下面公式计算；所有过期判断使用 `now >= expires_at`。观察时限和封禁时限分别保存，不因为封禁到期删掉仍有效观察证据。

```python
# observed：每条记录必须有可靠 observed_at；输入时间未来超限则拒绝快照。
block_until = observed_at + timedelta(hours=settings.block_hours)
observe_until = observed_at + timedelta(hours=settings.observe_hours)
# rolling：window_hours 由已审核配置给出。
block_until = generated_at + timedelta(hours=settings.block_hours - spec.window_hours)
observe_until = generated_at + timedelta(hours=settings.observe_hours - spec.window_hours)
# unknown：从 presence 中保留的本次连续出现周期的 first_seen_at 起算。
block_until = None
observe_until = first_seen_at + timedelta(hours=settings.observe_hours)
# network/c2 snapshot：存在上游有效期时取更短者。
snapshot_until = generated_at + timedelta(hours=settings.snapshot_hours)
```

Web `Evidence.expires_at` 为有效观察截止（没有观察资格时为封禁截止）；network/c2 为快照截止。rolling 源中的记录若在有效新快照中消失，移除该源对应记录，避免将“最近窗口”解释为继续活动。observed/unknown 的历史 Web 证据可保留至原有效期，但 disappearance 标记只由完整成功快照更新。

规范化在合并前执行：无效语法拒绝快照；非公网记录丢弃并计入拒绝原因；同源同目标取最新可靠观测时间，首次发现时间保持不变。源级 count/sha256 保留上一接受快照，不用失败样本更新异常比较基线。

每次先撤销配置中已禁用、移除或失去 public_approved 的来源证据、presence 和可能含该源数据的审计字段；不能仅阻止新抓取而继续公开旧数据。准入撤销错误只保留来源 ID 和原因。来源错误保留先前有效证据至其原截止时间；新鲜度不因 `attempted_at` 变化。

- [ ] **4. 加入有效快照、空快照和异常增长分支。** 每个 Outcome 要满足 snapshot/error 恰有一个；重复 outcome ID 拒绝运行。generated_at 回退的快照拒绝，避免旧数据覆盖已删除条目。相同快照可确认获取成功，但不能续期；unknown 源也不能靠重复快照更新 presence 起点。完整成功的空快照可标记所有条目 absent；失败、异常增长、陈旧快照不得标记 absent。

```python
is_anomaly = (
    had_previous_accepted_snapshot
    and len(current_targets - previous_targets) >= settings.anomaly_new
    and len(current_targets) > previous_count * settings.anomaly_ratio
)
```

为准确计算新增数量，使用 previous.presence 中该来源 `present=True` 的目标集合；network/c2 也维护 presence。0 条的上一合法快照算有效基线。异常快照设 error=`anomalous_growth`，不更新 accepted_count、摘要或 presence，但仍执行全局过期清理。SourceState.status 只取 ok、empty、error、stale、disabled、unavailable；last_success_at 仅在通过格式、时间和异常检查后更新。

SourceState.valid_until 的 snapshot 模式按上游生成时间 + 最长 48 小时计算，合法空快照也一样，不能按下载时间续期。rolling 模式按已审核窗口规则计算。observed/unknown 非空源取其证据的最早 expires_at；没有任何证据仍有效时为 stale。没有上游生成时间的合法空响应，仅把“本次空检查”的状态寿命设为接受时间 + 24 小时，不给任何 IP 续期。所有条目归属地址族必须在 spec.ip_versions 内，否则拒绝快照。

- [ ] **5. 运行完整 temporal 行为矩阵。** `python -m pytest tests/test_temporal.py -q`。逐项加入：72h/7d/48h 边界、未来 301 秒拒绝、窗口 48h 的快照 24h 后不得用于封禁、同源旧观测不覆盖新观测、消失后重现、失败后重现不重置、回退快照、上游更短有效期、合法空、全部来源失败仍过期、来源授权撤销、异常增长、30 天 history 清理且 tombstone 保留。
- [ ] **6. 提交。** `git add src/ipbeaco/temporal.py tests/test_temporal.py`；`git commit -m 'feat: enforce evidence expiry and source isolation'`。

## Task 7：按用途选取列表和 Web 两档

**Files:** Create `src/ipbeaco/policy.py`、`tests/test_policy.py`。

**Interfaces:** 在 policy.py 定义下列输出类型；`select(state: State, config: Config, now: datetime) -> Selection`。keys 固定为 `block-ipv4`、`block-ipv6`、`observe-ipv4`、`observe-ipv6`、`network-ipv4`、`network-ipv6`、`c2-ipv4`、`c2-ipv6`，即使没有记录也存在。

```python
@dataclass(frozen=True)
class Entry:
    target: str
    valid_until: datetime
    source_ids: tuple[str, ...]
    reason: str

@dataclass(frozen=True)
class Selection:
    lists: dict[str, tuple[Entry, ...]]
    exclusions: tuple[dict[str, str], ...]
```

exclusions 字典固定包含 `target`、`source_id`、`reason`，只记录当前允许公开的来源。白名单命中返回 reason=`allowlisted`，过期不重新导出原始地址的无限历史。

- [ ] **1. 写独立来源与用途隔离测试。** 同一家族两个 ID 不够封禁；两个独立 family 可以；高可信单源可以；过期后重新评估。

```python
from ipbeaco.models import Config, Outcome, Settings, State
from ipbeaco.temporal import advance
from ipbeaco.policy import select
from tests.factories import NOW, snapshot, source

def test_same_family_does_not_count_twice():
    a = source(id='a', family='shared')
    b = source(id='b', family='shared')
    cfg = Config((a, b), Settings(), ())
    outcomes = tuple(Outcome(s.id, NOW, snapshot('8.8.8.8', source_id=s.id)) for s in (a, b))
    state = advance(State(), cfg, outcomes, NOW, 'run')
    result = select(state, cfg, NOW)
    assert result.lists['block-ipv4'] == ()
    assert [e.target for e in result.lists['observe-ipv4']] == ['8.8.8.8']
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_policy.py -q`。
- [ ] **3. 实现 Web 判定。** 仅 category=`web_attack` 或经配置明确允许的 `web_exploit`、`web_bruteforce` 可贡献封禁资格；`scan`/`unknown` 不贡献。`max_tier='observe'` 不得参与凑足封禁阈值，`independent=False` 不贡献独立家族数。

```python
qualifying = [e for e in evidence
              if e.block_until is not None and now < e.block_until
              and specs[e.source_id].max_tier == 'block'
              and e.category in {'web_attack', 'web_exploit', 'web_bruteforce'}]
families = {specs[e.source_id].family for e in qualifying
            if specs[e.source_id].independent}
blocked = any(specs[e.source_id].trusted_single for e in qualifying) or len(families) >= 2
```

已进入 block 的目标从 observe 移除。Entry.valid_until 保守取支撑当前判断证据的最早截止；因此任一依赖证据到期都要求客户端重新同步，不把另一个来源较晚到期当作全部证据延期。

- [ ] **4. 实现 network/c2 及白名单。** 只选对应 purpose 的有效证据；相同目标合并 source_ids，但不改变网段边界。精确重复 CIDR 去重、重叠而不相同的 CIDR 保留；CIDR 白名单命中整段排除。三类独立计算，不把 C2 地址升级为 Web block。
- [ ] **5. 运行测试矩阵。** `python -m pytest tests/test_policy.py tests/test_temporal.py -q`。覆盖白名单优先、单双源、观察档来源不得参与封禁、IPv6、同 IP 跨用途出现、C2 不进入 Web、CIDR 不展开、expiry 后降级和所有结果稳定排序。
- [ ] **6. 提交。** `git add src/ipbeaco/policy.py tests/test_policy.py`；`git commit -m 'feat: select separate web network and C2 lists'`。

## Task 8：生成统一 lists 目录和可验证状态

**Files:** Create `src/ipbeaco/export.py`、`tests/test_export.py`。

**Interfaces:** `write_site(selection: Selection, state: State, config: Config, now: datetime, build_id: str, output: Path) -> None`、`validate_site(output: Path, now: datetime) -> None`，校验失败抛 ValueError。`output` 是新的临时构建目录，调用者不得覆盖正在使用的公共目录。

- [ ] **1. 写八文件契约和元数据测试。** 全部为空时也要有八个文件，各自状态不可冒充健康；有地址时验证排序、LF、末尾换行、地址族；network 版权头随文件保留。

```python
import json
from ipbeaco.models import Config, Settings, State
from ipbeaco.policy import select
from ipbeaco.export import write_site
from tests.factories import NOW

def test_unavailable_lists_exist_but_are_not_healthy(tmp_path):
    cfg = Config((), Settings(), ())
    write_site(select(State(), cfg, NOW), State(), cfg, NOW, 'run-1', tmp_path)
    names = {f'{kind}-ipv{v}.txt' for kind in ('block', 'observe', 'network', 'c2') for v in (4, 6)}
    assert {p.name for p in (tmp_path / 'lists').glob('*.txt')} == names
    status = json.loads((tmp_path / 'lists/status.json').read_text())
    assert status['lists']['block-ipv4']['status'] == 'unavailable'
    assert status['lists']['block-ipv4']['valid_until'] is None
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_export.py -q`。
- [ ] **3. 实现导出与清单。** TXT 使用 `sort_key` 排序，纯 IP 文件无头。network 文件每个相关来源保留规范的 `# source`、`# generated_at`、版权/署名行；保留来源要求的原始文字，对换行逐行添加注释前缀，不允许版权头注入 IP 行。真实授权若要求不同格式，先修改对应来源输出契约及测试，再启用。空文件为零字节；有数据以 LF 结束。

`status.json` 固定结构：

```json
{
  "schema_version": 1,
  "build_id": "run-1",
  "generated_at": "2026-10-04T00:00:00+00:00",
  "sources": {},
  "lists": {
    "block-ipv4": {
      "path": "lists/block-ipv4.txt",
      "status": "unavailable",
      "count": 0,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "valid_until": null
    }
  }
}
```

上例只展示一个列表结构，实际必须产生全部八项。清单不包含自身 SHA，避免循环依赖。metadata 固定含 `schema_version/build_id/generated_at/entries/exclusions/source_licenses`；entries 按列表 key 关联 Entry 与允许公开的 Evidence，保留时间依据和原因；source_licenses 只包含已批准公开的来源。生成 metadata 后添加真实摘要：

```python
metadata_bytes = (output / 'lists/metadata.json').read_bytes()
manifest['metadata'] = {
    'path': 'lists/metadata.json',
    'sha256': hashlib.sha256(metadata_bytes).hexdigest(),
}
```

- [ ] **4. 实现状态汇总及有效期。** 对每个用途/地址族独立判定，按 SourceSpec.ip_versions 判断来源能力。没有已准入来源为 unavailable；有有效记录且所需来源正常为 ok，有失败/陈旧来源为 degraded；有来源本次成功确认无符合条目且其他来源正常为 empty；仅有过期来源数据为 stale，不能标记 empty。全部源失败导致无有效记录时为 degraded、valid_until=null。有效记录取最早 Entry.valid_until；合法空结果取相关健康 SourceState.valid_until 的最早值。
- [ ] **5. 实现文件验证和页面。** 验证八份文件、count、IP 族、CIDR、公网、两档互斥、摘要、metadata build_id 一致、所有当前有效条目在 now 之后；检查未批准来源 ID 不出现在 evidence/metadata。用 `html.escape` 生成简单中文 index，链接使用相对 `lists/` 路径，显示三类用途和更新时间，不做交互后台。
- [ ] **6. 运行测试。** `python -m pytest tests/test_export.py -q`；篡改文件一字节必须失败；更新某来源 fetched_at 不得虚增有效期；空 IPv6 列表不能被错误归为来源故障；恶意版权 HTML 在页面必须转义。
- [ ] **7. 提交。** `git add src/ipbeaco/export.py tests/test_export.py`；`git commit -m 'feat: publish lists with provenance and freshness manifests'`。

## Task 9：贯通流水线与本地命令

**Files:** Create `src/ipbeaco/{pipeline,cli}.py`、`tests/{test_pipeline,test_cli}.py`、`tests/fixtures/integration/`。

**Interfaces:** `collect(config: Config, now: datetime, client: httpx.Client) -> tuple[Outcome, ...]`；`run_once(config: Config, state_dir: Path, output: Path, client: httpx.Client, now: datetime, build_id: str, *, bootstrap: bool = False) -> State`；`cli.main(argv: list[str] | None = None) -> int`。CLI 时钟由内部 `utc_now() -> datetime` 提供，测试 monkeypatch，不向生产命令开放“忽略当前时间”的选项。

- [ ] **1. 写 HTTPX MockTransport 全流程测试。** 使用临时 TOML 中三个已批准的合成来源，不修改生产默认配置；合成 Web unknown、network snapshot、C2 snapshot 响应。首次调用生成八文件和状态，时间推进三天后所有来源失败，network/c2 过期但 Web 观察仍存在，状态降级；八天后 Web 也移除，presence 仍在。

```python
import httpx
from ipbeaco.models import Config, Settings
from ipbeaco.pipeline import run_once
from ipbeaco.state import load_state
from tests.factories import NOW, source

def test_offline_pipeline_persists_only_after_output_validation(tmp_path):
    spec = source(adapter='blocklist_de', time_mode='unknown', max_tier='observe')
    cfg = Config((spec,), Settings(), ())
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b'8.8.8.8\n'))
    with httpx.Client(transport=transport) as client:
        state = run_once(cfg, tmp_path / 'state', tmp_path / 'site', client,
                         NOW, 'test-build', bootstrap=True)
    assert (tmp_path / 'site/lists/observe-ipv4.txt').read_text() == '8.8.8.8\n'
    assert load_state(tmp_path / 'state') == state
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_pipeline.py tests/test_cli.py -q`。
- [ ] **3. 实现编排。** 严格顺序是 config 校验 → load_state → collect → advance → select → write_site → validate_site → save_state。拒绝输出目录已存在，避免覆盖上一成功本地产物；失败的临时目录可保留排障，但下一次使用新目录。下载和解析 SourceError 转为该来源 Outcome.error；配置、状态、输出校验失败则终止整次运行。禁用来源不发网络请求。

```python
outcomes = collect(config, now, client)
candidate = advance(previous, config, outcomes, now, build_id)
selected = select(candidate, config, now)
write_site(selected, candidate, config, now, build_id, output)
validate_site(output, now)
save_state(candidate, state_dir)
return candidate
```

- [ ] **4. 实现命令与退出码。** 使用 argparse，支持：

```bash
ipbeaco run --config config --state state --out site --build-id local-001 --bootstrap
ipbeaco validate --site site
ipbeaco inspect-source --config config --source feodo-recommended
```

`run` 后续运行省略 bootstrap，使用新的 out 目录。0 表示生成并校验成功（可能 degraded/unavailable，必须在摘要打印）；2 表示参数/配置错误；1 表示状态/文件/运行错误。`inspect-source` 是只读诊断：可对禁用候选执行格式和新鲜度核查，仅打印条数、时间、摘要和准入结果，不修改启用状态、不写公开产物、不输出 IP 全集；异常返回 1。`validate` 使用实际当前时间，能拒绝过期的非空文件或过期的健康 empty 声明，但允许明确 degraded/unavailable/stale 的诊断空产物。
- [ ] **5. 运行测试。** `python -m pytest tests/test_pipeline.py tests/test_cli.py -q`；注入输出校验失败后状态文件字节不变，注入 state 保存失败后命令非零，确认没有任何 deploy 动作；所有测试离线。
- [ ] **6. 提交。** `git add src/ipbeaco/pipeline.py src/ipbeaco/cli.py tests/test_pipeline.py tests/test_cli.py tests/fixtures/integration`；`git commit -m 'feat: run complete feed generation pipeline locally'`。

## Task 10：独立 data 分支的事务性保存

**Files:** Create `src/ipbeaco/git_store.py`、`tests/test_git_store.py`；Modify `src/ipbeaco/cli.py`、`tests/test_cli.py`。

**Interfaces:** `pull_state(remote: str, directory: Path, *, bootstrap: bool = False) -> str | None` 返回所读取的 data 提交 ID；`push_state(remote: str, directory: Path, expected_parent: str | None) -> str` 返回新提交 ID。内部使用 `subprocess.run` 的参数数组，禁止拼接 shell 字符串或 force push。

- [ ] **1. 写本地 bare Git 集成测试。** 用 tmp_path 建立 bare remote 和工作副本，配置仅测试仓库的测试身份。覆盖已有 data 正常往返、首次显式创建、分支缺失且未授权 bootstrap、网络/remote 错误、先读后另一写入者更新、校验和错误以及上传文件白名单。

```python
import subprocess
import pytest
from ipbeaco.git_store import pull_state
from ipbeaco.models import StateError

def test_absent_branch_requires_bootstrap(tmp_path):
    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
    with pytest.raises(StateError, match='bootstrap'):
        pull_state(str(remote), tmp_path / 'state')
    assert pull_state(str(remote), tmp_path / 'fresh', bootstrap=True) is None
```

- [ ] **2. 运行失败测试。** `python -m pytest tests/test_git_store.py -q`。
- [ ] **3. 实现读取与首次创建。** 使用 `git ls-remote --exit-code remote refs/heads/data` 区分分支不存在（退出 2）、远端不可达（其他非零）和存在。只有手动 bootstrap 且确认分支不存在时可新建空 State 并保存；保存时不包含主分支代码。读取成功后 fetch 精确 data 提交，通过 `git show` 导出两个状态文件并校验。所有 Git 输出错误需要清理可能含凭据的 URL。
- [ ] **4. 实现无强推提交。** 先校验目录，临时仓库建立只含 state.json/state.sha256 的 tree。父提交使用 expected_parent，提交后用普通 push 更新 `refs/heads/data`；若远端已变化，非快进失败必须退出，不强推、不在旧候选上直接 rebase。第一次创建前后若有并发远端建立了 data，也拒绝覆盖。GitHub Actions 提交身份使用已知的 `github-actions[bot]` 和 `41898282+github-actions[bot]@users.noreply.github.com`，只作用于该次 Git 调用；本地遵循用户身份。

```python
subprocess.run(['git', '-C', str(workdir), 'push', remote,
                f'{commit_id}:refs/heads/data'], check=True, capture_output=True)
```

- [ ] **5. 增加 CLI 状态子命令。** 任务 9 的 argparse 继续支持：

```bash
ipbeaco state pull --remote origin --dir state --revision-file state-base.txt --bootstrap
ipbeaco state push --remote origin --dir state --revision-file state-base.txt
```

revision-file 保存上次提交 ID，首次为 `null`；push 解析并校验 ID，不能把任意文本作为 Git 参数。origin 先从当前 checkout 解析为真实远端 URL，再给临时仓库使用；临时仓库继承 runner 的 Git HTTPS 认证配置，但不能输出认证头或把它写入 data 分支。pull 写入有效空状态后，run 不再需要 bootstrap。测试目录的额外文件（如 token.txt）不得被提交。
- [ ] **6. 运行测试。** `python -m pytest tests/test_git_store.py tests/test_cli.py -q`。网络被测试桩禁止，所有 Git 交互针对临时 bare remote；确认并发错误不改写远端提交。
- [ ] **7. 提交。** `git add src/ipbeaco/git_store.py src/ipbeaco/cli.py tests/test_git_store.py tests/test_cli.py`；`git commit -m 'feat: persist feed state on an isolated data branch'`。

## Task 11：CI、每日更新和 Pages 部署

**Files:** Create `.github/workflows/{ci,update}.yml`；Modify `docs/operations.md`（在此任务创建初稿，任务 12 完善）。

**Interfaces:** CI 调用测试套件；更新 workflow 依次调用任务 9/10 的 CLI。失败不允许跳过状态提交去部署；全量重跑会重新计算过期时间，不能只重用上次的 Pages artifact。

- [ ] **1. 建立更新配置并核对控制流。** 计划中的关键 YAML 如下，执行时补齐已明确的命令步骤，不能使用 continue-on-error 或 always() 部署：

```yaml
name: Update IP intelligence
on:
  schedule:
    - cron: '17 0 * * *'
  workflow_dispatch:
    inputs:
      bootstrap_state:
        description: '仅首次创建 data 分支时开启'
        type: boolean
        default: false
permissions:
  contents: write
  pages: write
  id-token: write
concurrency:
  group: ipbeaco-publish
  cancel-in-progress: false
jobs:
  update:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install
        run: |
          python -m pip install --require-hashes -r requirements.lock
          python -m pip install --no-deps -e .
      - name: Read state
        env:
          BOOTSTRAP_STATE: ${{ inputs.bootstrap_state || false }}
        run: |
          args=()
          if [ "$BOOTSTRAP_STATE" = "true" ]; then args+=(--bootstrap); fi
          ipbeaco state pull --remote origin --dir state --revision-file state-base.txt "${args[@]}"
      - name: Build
        env:
          BUILD_ID: ${{ github.run_id }}-${{ github.run_attempt }}
        run: ipbeaco run --config config --state state --out site --build-id "$BUILD_ID"
      - name: Commit state
        run: ipbeaco state push --remote origin --dir state --revision-file state-base.txt
      - name: Check freshness before uploading
        run: ipbeaco validate --site site
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: site
      - name: Check freshness before deployment
        run: ipbeaco validate --site site
      - name: Deploy
        id: deployment
        uses: actions/deploy-pages@v4
```

启用前用当前官方 action 文档核对版本及所需 permissions，若调整版本同步文档。工作流不绑定未知用户名。不要在 PR 中执行带写权限的更新 workflow；CI 工作流使用 `contents: read`，只监听主分支 push 和 pull_request，锁文件安装开发依赖后执行下面检查。

- [ ] **2. 完成 CI 步骤。** Python 3.12、`pip install --require-hashes -r requirements-dev.lock`、`pip install --no-deps -e .`、`ruff check .`、`ruff format --check .`、`python -m pytest -q`。不把动态上游网络状态作为 PR 测试是否通过的条件。
- [ ] **3. 验证 workflow 语义。** 使用 `actionlint` 检查两个文件；核对 cron、同一 concurrency、cancel-in-progress=false、首次 bootstrap 显式、state push 在 upload/deploy 前、两个实际时间 validate、无失败后部署。此项无需编写只复述 YAML 的单元测试。
- [ ] **4. 验证延迟重试行为。** 本地测试用任务 9/10 的模块和可控时钟模拟状态已提交但部署失败，推进至 evidence 到期后再次 validate 必须失败；重新 run 产生已清理的列表。将命令写入 operations：仅“重试部署步骤”不能更新旧产物，应重新运行整个更新任务。
- [ ] **5. GitHub 首次实际运行留到发布检查阶段。** 要有已授权的远端账号/仓库和 GitHub Pages（Source=GitHub Actions）。若当前没有远端连接，先完成 workflow、本地验证和操作说明，明确实际部署未执行；不伪造在线链接或索取密钥。
- [ ] **6. 提交。** `git add .github/workflows docs/operations.md`；`git commit -m 'ci: schedule validated list publication to GitHub Pages'`。

## Task 12：接入文档、来源复核与交付验收

**Files:** Create `README.md`、`docs/{sources,subscriptions}.md`、`.github/ISSUE_TEMPLATE/false-positive.yml`；Modify `docs/operations.md`、`config/sources.toml`（仅在证据充分时调整启用状态）。

**Interfaces:** 文档使用与 export 完全一致的八条 `lists/` 路径。静态网页和 README 明确列表方向、用途、最新状态及 WAF 容量/格式兼容性。用户需要具体厂商 API 适配时另开任务，不能在此阶段偷偷扩大到厂商自动推送。

- [ ] **1. 写来源准入记录。** sources.md 对每个来源记录核查日期、官方链接、数据方向、时间语义、独立家族、许可依据、署名要求、是否启用和具体原因。沿用设计核查结果为起点；blocklist.de/apache 分类和 all 相同的现象不能掩盖，Feodo 旧时间不能改写为获取时间。逐项运行以下只读命令并记录结果：

```bash
ipbeaco inspect-source --config config --source blocklist-de-apache
ipbeaco inspect-source --config config --source spamhaus-drop-v4
ipbeaco inspect-source --config config --source spamhaus-drop-v6
ipbeaco inspect-source --config config --source feodo-recommended
```
- [ ] **2. 完成公共数据上线核查。** 对将启用的来源读取最新官方许可和格式说明，确认本项目公开镜像/加工输出被允许；取得明确依据后更新 public_approved、reviewed_at 和 disabled_reason，再运行真实只读诊断。若依据不足，保持禁用，并报告该用途无有效覆盖；不得为了“完成”启用存疑来源。研究结果不能替代他人授权，不自动给来源维护者发消息。
- [ ] **3. 写订阅文档。** 列出八个 URL，主示例为 `https://<owner>.github.io/IPBeaco/lists/block-ipv4.txt`，说明 owner 是用户部署时替换的 URL 参数。明确 TXT 不具备失效逻辑，客户端应先读取 status、核对 valid_until/count/SHA，再拉取文件并再次确认 build_id；一致后原子替换本地集合。unavailable/stale 或 valid_until=null 不作为健康同步；本地已有规则按其上次有效期到期移除，不能无限保留，也不能见空文件立即清空。observe 仅用于观察、验证或限速，C2 是目的地址，network 是 CIDR 且带注释。
- [ ] **4. 写运维与误报反馈说明。** 覆盖首次手动 bootstrap、后续自动运行、损坏状态从上次完整提交恢复、data 分支历史增长、任务全停时客户端失效、GitHub Actions 定时限制、fork 后需启用 Actions/Pages。误报模板要求 IP/CIDR、列表名、build_id、理由和希望的处理，提示不要附带私有日志或密钥；不自动提交 Issue。项目级白名单与私有白名单的适用范围分别说明。
- [ ] **5. 执行本地交付检查。** 以下命令必须真实运行并保存结果摘要：

```bash
python -m pytest -q
ruff check .
ruff format --check .
actionlint .github/workflows/ci.yml .github/workflows/update.yml
git diff --check
```

只有发生新改动、失败或未解决疑点才重复扩大测试。文档链接、文件名与导出目录人工核对；测试固定样本不得进入生产 config 或 artifact。
- [ ] **6. 执行已授权远端的发布验证。** 在用户已经确定仓库与允许发布后执行：push 代码 → 配置 Pages 使用 Actions → 手动 bootstrap 更新 → 查看状态提交及 deploy 成功 → GET 八文件和 status/metadata → 验证摘要、用途、时间和当前来源状态。下载验证只读且不导入任何实际防火墙。缺少远端信息时交付本地实现并明确尚未部署，不能称为项目全部上线。
- [ ] **7. 提交并交付。** `git add README.md docs/sources.md docs/subscriptions.md docs/operations.md .github/ISSUE_TEMPLATE config/sources.toml`；`git commit -m 'docs: document source admission subscriptions and operations'`。交付实际测试结果、有效来源/不可用来源清单、已发布 URL（如果确实部署）及实际限制。

## 设计覆盖检查

| 设计要求 | 对应任务 |
| --- | --- |
| 默认无需密钥、许可准入、AbuseIPDB 关闭 | 1、6、12 |
| 三种来源格式、版权信息、空与坏数据 | 3、4、8 |
| 公网校验、IPv6、CIDR、白名单 | 2、7 |
| TTL、滚动窗口、旧数据不续期、独立证据 | 6、7 |
| 全部来源失败也清理到期记录、异常源隔离 | 6、9 |
| 八个列表统一放入 lists/ | 8、12 |
| 元数据、原因、来源状态、有效期和摘要 | 5、8 |
| data 持久化、损坏拒绝、并发非强推 | 5、10 |
| 每日 00:17 UTC、串行、先状态再部署 | 11 |
| 部署重试检查实际时间、客户端陈旧检测 | 8、11、12 |
| 状态保留与运行历史清理 | 5、6、12 |
| 正常空、不可用、陈旧的区别 | 6、8、9 |
| 离线行为测试与上线前真实只读核查 | 1–10、12 |
| 误报入口、设备兼容、Fork 与发布说明 | 12 |

## 执行交接

计划已准备为逐任务执行的清单。执行方式可选择子代理逐任务实现并审查，或在当前会话按 executing-plans 分批执行并汇报检查点。编写本计划不代表已经运行实现测试、获得新增来源许可或发布 GitHub Pages。
