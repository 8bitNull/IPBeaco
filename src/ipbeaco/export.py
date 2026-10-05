"""Build and validate one frozen, public static publication artifact."""

import hashlib
import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ipbeaco.addresses import normalize_target, sort_key
from ipbeaco.models import Config, SourceState, State
from ipbeaco.policy import Selection, select

_KEYS = tuple(
    f"{kind}-ipv{version}" for kind in ("block", "observe", "network", "c2") for version in (4, 6)
)
_SOURCE_STATUSES = {"ok", "empty", "error", "stale", "disabled", "unavailable"}
_LIST_STATUSES = {"ok", "empty", "degraded", "stale", "unavailable"}


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError("Publication timestamps must include a timezone")
    return parsed


def _check_now(now: datetime) -> None:
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")


def _json_value(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _json_bytes(value) -> bytes:
    return (
        json.dumps(_json_value(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _relevant(spec: dict, key: str) -> bool:
    kind, version = key.split("-ipv")
    if int(version) not in spec["ip_versions"]:
        return False
    if kind in ("block", "observe"):
        if spec["purpose"] != "web":
            return False
        return kind == "observe" or (
            spec["max_tier"] == "block"
            and spec["time_mode"] in ("observed", "rolling")
            and (spec["independent"] or spec["trusted_single"])
        )
    return spec["purpose"] == kind


def _healthy(health: dict, now: datetime) -> bool:
    return (
        health["status"] in ("ok", "empty")
        and health["valid_until"] is not None
        and now < _time(health["valid_until"])
        and health["last_success_at"] is not None
    )


def _list_health(entries: list, related: list[dict], now: datetime) -> tuple[str, str | None]:
    if not related:
        return "unavailable", None
    if entries:
        status = "ok" if all(_healthy(health, now) for health in related) else "degraded"
        return status, min((entry["valid_until"] for entry in entries), key=_time)
    if all(_healthy(health, now) for health in related):
        return "empty", min((health["valid_until"] for health in related), key=_time)
    if any(health["status"] in ("error", "unavailable", "disabled") for health in related):
        return "degraded", None
    return "stale", None


def _comment(text: str) -> list[str]:
    # splitlines also handles CR and Unicode line separators: every logical line
    # stays a comment, even if the original attribution contains an IP/CIDR.
    return ["# " + line for line in text.splitlines()]


def _network_header(
    key: str, entries: list, licenses: dict, sources: dict, now: datetime
) -> list[str]:
    supporting = {sid for entry in entries for sid in entry["source_ids"]}
    contributors = sorted(
        sid
        for sid, spec in licenses.items()
        if _relevant(spec, key)
        and (
            sid in supporting
            or (
                sources[sid]["last_success_at"] is not None
                and sources[sid]["valid_until"] is not None
                and now < _time(sources[sid]["valid_until"])
            )
        )
    )
    lines = []
    for sid in contributors:
        spec, health = licenses[sid], sources[sid]
        if health["generated_at"] is None or health["last_success_at"] is None:
            raise ValueError("Network publication needs an accepted snapshot generation date")
        lines.extend(_comment(f"source: {sid}"))
        lines.extend(_comment(f"generated_at: {health['generated_at']}"))
        lines.extend(_comment(spec["attribution"]))
        for notice in spec["notices"]:
            lines.extend(_comment(notice))
    return lines


def _page(manifest: dict, licenses: dict) -> bytes:
    escape = html.escape
    lines = [
        '<!doctype html><html lang="zh-CN"><meta charset="utf-8">',
        "<title>IPBeaco 公共威胁列表</title><h1>IPBeaco 公共威胁列表</h1>",
        f"<p>更新时间：{escape(manifest['generated_at'])}</p>",
        f"<p>构建版本：{escape(manifest['build_id'])}</p>",
        "<p>Web block 用于入站请求的来源 IP 封禁；observe 仅用于观察、验证或限速。"
        "C2 是出站连接的目的 IP；network 是网络层 CIDR，文件含 # 来源与版权注释。</p>",
        "<p>CINS Army 为广泛 IPv4 信誉来源，仅进入 observe；没有逐 IP 攻击时间，"
        "不代表确认的 Web 攻击。首次出现后最多观察 7 天，重复下载不续期。</p>",
        "<p>导入前核对 WAF/防火墙的条目容量、IPv6、CIDR、注释和原子替换能力；"
        "超容量时停止导入，不静默截断。厂商 API 适配需另行实现。</p>",
        "<p>TXT 不会自动失效。同步前后核对状态、build_id、有效期、条数和 SHA-256；"
        "unavailable、stale 或无有效期不能作为健康同步。degraded 仅在仍有有效条目且"
        "客户端接受降级时使用；本地规则到期应移除，不能见空文件立即清空。</p>",
    ]
    for title, kinds in (
        ("Web 封禁与观察", ("block", "observe")),
        ("网段", ("network",)),
        ("C2", ("c2",)),
    ):
        lines.append(f"<h2>{title}</h2><ul>")
        for kind in kinds:
            for version in (4, 6):
                key = f"{kind}-ipv{version}"
                row = manifest["lists"][key]
                deadline = row["valid_until"] or "无当前有效期"
                lines.append(
                    f'<li><a href="{escape(row["path"], quote=True)}">{key}.txt</a> '
                    f"— {escape(row['status'])}，{row['count']} 条，有效截止：{escape(deadline)}</li>"
                )
        lines.append("</ul>")
    lines.append(
        '<p><a href="lists/status.json">状态清单</a> · <a href="lists/metadata.json">证据与许可</a></p>'
    )
    lines.append("<h2>来源署名与版权</h2>")
    for sid, spec in licenses.items():
        lines.append(f"<h3>{escape(sid)}</h3><pre>")
        lines.extend(escape(text) for text in (spec["attribution"], *spec["notices"]))
        lines.append("</pre>")
    lines.append("</html>")
    return ("\n".join(lines) + "\n").encode()


def write_site(
    selection: Selection, state: State, config: Config, now: datetime, build_id: str, output: Path
) -> None:
    """Write into a new build directory; callers must never use the live site.

    Selection must match this frozen state and current admission rules. This
    prevents an earlier selection from disclosing data after approval revocation.
    """
    _check_now(now)
    if not isinstance(build_id, str) or not build_id:
        raise ValueError("build_id must be a nonempty string")
    if set(selection.lists) != set(_KEYS):
        raise ValueError("Selection must include all eight lists")
    ordered = Selection(
        {
            key: tuple(sorted(entries, key=lambda item: sort_key(item.target)))
            for key, entries in selection.lists.items()
        },
        tuple(
            sorted(
                selection.exclusions, key=lambda item: (sort_key(item["target"]), item["source_id"])
            )
        ),
    )
    if ordered != select(state, config, now):
        raise ValueError("Selection does not match the current state, policy, and time")
    licenses, sources = {}, {}
    for spec in sorted(config.sources, key=lambda item: item.id):
        admitted = spec.enabled and spec.public_approved
        health = (
            state.sources.get(spec.id, SourceState())
            if admitted
            else SourceState(status="disabled")
        )
        if health.status not in _SOURCE_STATUSES:
            raise ValueError("Invalid source status")
        row = _json_value(asdict(health))
        # Raw errors are collection diagnostics, not public provenance. Notices
        # are published only through the admitted source's license association.
        del row["notices"], row["error"]
        if row["status"] in ("ok", "empty") and not _healthy(row, now):
            row["status"] = "stale"
        sources[spec.id] = row
        if admitted:
            licenses[spec.id] = _json_value(
                {
                    **{
                        name: getattr(spec, name)
                        for name in (
                            "enabled",
                            "public_approved",
                            "purpose",
                            "ip_versions",
                            "family",
                            "independent",
                            "trusted_single",
                            "max_tier",
                            "category",
                            "time_mode",
                            "license_url",
                            "reviewed_at",
                            "url",
                            "attribution",
                        )
                    },
                    "notices": health.notices,
                }
            )

    evidence = {(item.source_id, item.target): item for item in state.evidence}
    entries = {}
    for key in _KEYS:
        rows = []
        for entry in sorted(selection.lists[key], key=lambda item: sort_key(item.target)):
            supporting = []
            for sid in entry.source_ids:
                if sid not in licenses or not _relevant(licenses[sid], key):
                    raise ValueError("Entry references a source without publication capability")
                item = evidence[(sid, entry.target)]
                supporting.append(_json_value(asdict(item)))
            rows.append({**_json_value(asdict(entry)), "evidence": supporting})
        entries[key] = rows
    metadata = {
        "schema_version": 1,
        "build_id": build_id,
        "generated_at": now,
        "entries": entries,
        "exclusions": selection.exclusions,
        "source_licenses": licenses,
    }
    manifest = {
        "schema_version": 1,
        "build_id": build_id,
        "generated_at": _json_value(now),
        "sources": sources,
        "lists": {},
    }
    lists = output / "lists"
    lists.mkdir(parents=True, exist_ok=True)
    for key, rows in entries.items():
        lines = (
            _network_header(key, rows, licenses, sources, now) if key.startswith("network-") else []
        )
        lines.extend(entry["target"] for entry in rows)
        raw = ("\n".join(lines) + "\n").encode() if lines else b""
        path = f"lists/{key}.txt"
        (output / path).write_bytes(raw)
        related = [sources[sid] for sid, spec in licenses.items() if _relevant(spec, key)]
        status, deadline = _list_health(rows, related, now)
        manifest["lists"][key] = {
            "path": path,
            "status": status,
            "count": len(rows),
            "sha256": _digest(raw),
            "valid_until": deadline,
        }
    metadata_raw = _json_bytes(metadata)
    (lists / "metadata.json").write_bytes(metadata_raw)
    manifest["metadata"] = {"path": "lists/metadata.json", "sha256": _digest(metadata_raw)}
    (lists / "status.json").write_bytes(_json_bytes(manifest))
    (output / "index.html").write_bytes(_page(manifest, licenses))
    (output / ".nojekyll").write_bytes(b"")


def _object(value, fields: str | None = None) -> dict:
    if type(value) is not dict or (fields is not None and set(value) != set(fields.split())):
        raise ValueError("Missing or unexpected publication fields")
    return value


def _array(value) -> list:
    if type(value) is not list:
        raise ValueError("Expected a publication array")
    return value


def _load_json(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate publication field")
            value[key] = item
        return value

    return _object(json.loads(raw.decode("utf-8"), object_pairs_hook=unique))


def _validate_entry(entry: dict, key: str, licenses: dict, now: datetime) -> None:
    _object(entry, "target valid_until source_ids reason evidence")
    kind = key.split("-ipv")[0]
    deadline = _time(entry["valid_until"])
    if deadline <= now:
        raise ValueError("Expired publication entry")
    ids = _array(entry["source_ids"])
    if not ids or ids != sorted(set(ids)):
        raise ValueError("Entry source IDs must be unique and sorted")
    supporting = _array(entry["evidence"])
    if [item["source_id"] for item in supporting] != ids:
        raise ValueError("Evidence does not match entry source IDs")
    deadlines = []
    for item in supporting:
        _object(
            item,
            "source_id target category first_seen_at observed_at snapshot_at time_basis block_until observe_until expires_at",
        )
        sid = item["source_id"]
        if sid not in licenses or not _relevant(licenses[sid], key):
            raise ValueError("Unapproved or incapable evidence source")
        if item["target"] != entry["target"] or item["time_basis"] != licenses[sid]["time_mode"]:
            raise ValueError("Evidence target or time basis differs from entry")
        if kind == "block" and not (
            item["category"] == "web_attack"
            or (
                item["category"] in ("web_exploit", "web_bruteforce")
                and item["category"] == licenses[sid]["category"]
            )
        ):
            raise ValueError("Evidence category cannot support web blocking")
        for field in (
            "first_seen_at",
            "observed_at",
            "snapshot_at",
            "block_until",
            "observe_until",
            "expires_at",
        ):
            if item[field] is not None:
                _time(item[field])
        expires = _time(item["expires_at"])
        tier_deadline = (
            item["block_until"]
            if kind == "block"
            else item["observe_until"]
            if kind == "observe"
            else item["expires_at"]
        )
        if tier_deadline is None or min(expires, _time(tier_deadline)) <= now:
            raise ValueError("Evidence cannot support a current entry")
        deadlines.append(min(expires, _time(tier_deadline)))
    if deadline != min(deadlines):
        raise ValueError("Entry expiry differs from supporting evidence")
    reason = "snapshot"
    if kind == "observe":
        reason = "observation"
    elif kind == "block":
        trusted = any(licenses[sid]["trusted_single"] for sid in ids)
        families = {licenses[sid]["family"] for sid in ids if licenses[sid]["independent"]}
        if not trusted and len(families) < 2:
            raise ValueError("Block evidence lacks trusted or independent support")
        reason = "trusted_single" if trusted else "independent_families"
    if entry["reason"] != reason:
        raise ValueError("Entry reason differs from evidence support")


def validate_site(output: Path, now: datetime) -> None:
    """Reject inconsistent, malformed, expired, or unapproved publication data.

    Admission is carried in the artifact's approved license registry. Checksums
    provide consistency, not authenticity of an artifact supplied by an attacker.
    """
    _check_now(now)
    try:
        _validate_site(output, now)
    except (OSError, KeyError, TypeError, AttributeError, UnicodeError, OverflowError) as exc:
        raise ValueError("Invalid or incomplete publication artifact") from exc


def _validate_site(output: Path, now: datetime) -> None:
    manifest = _load_json((output / "lists/status.json").read_bytes())
    _object(manifest, "schema_version build_id generated_at sources lists metadata")
    metadata_ref = _object(manifest["metadata"], "path sha256")
    if metadata_ref["path"] != "lists/metadata.json":
        raise ValueError("Unexpected metadata path")
    metadata_raw = (output / "lists/metadata.json").read_bytes()
    if _digest(metadata_raw) != metadata_ref["sha256"]:
        raise ValueError("Metadata checksum mismatch")
    metadata = _load_json(metadata_raw)
    _object(metadata, "schema_version build_id generated_at entries exclusions source_licenses")
    for field in ("schema_version", "build_id", "generated_at"):
        if manifest[field] != metadata[field]:
            raise ValueError("Publication build identity mismatch")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("Unsupported publication schema")
    if not isinstance(manifest["build_id"], str) or not manifest["build_id"]:
        raise ValueError("Invalid publication build ID")
    built_at = _time(manifest["generated_at"])
    if built_at > now:
        raise ValueError("Publication build time is in the future")
    sources = _object(manifest["sources"])
    licenses = _object(metadata["source_licenses"])
    for sid, spec in licenses.items():
        _object(
            spec,
            "enabled public_approved purpose ip_versions family independent trusted_single max_tier category time_mode license_url reviewed_at url attribution notices",
        )
        if spec["public_approved"] is not True or spec["enabled"] is not True or sid not in sources:
            raise ValueError("Unapproved source in public license registry")
        if spec["purpose"] not in ("web", "network", "c2") or spec["time_mode"] not in (
            "observed",
            "rolling",
            "unknown",
            "snapshot",
        ):
            raise ValueError("Invalid publication source capability")
        if not _array(spec["ip_versions"]) or any(
            type(v) is not int or v not in (4, 6) for v in spec["ip_versions"]
        ):
            raise ValueError("Invalid publication source address families")
        if spec["max_tier"] not in ("block", "observe") or any(
            type(spec[field]) is not bool for field in ("independent", "trusted_single")
        ):
            raise ValueError("Invalid publication source tier capability")
        for field in ("family", "category", "license_url", "url", "attribution"):
            if not isinstance(spec[field], str):
                raise ValueError("Invalid publication license text")
        if spec["reviewed_at"] is not None:
            _time(spec["reviewed_at"])
        if any(not isinstance(notice, str) for notice in _array(spec["notices"])):
            raise ValueError("Invalid publication notice")
    for sid, health in sources.items():
        _object(
            health,
            "last_attempt_at last_success_at status generated_at valid_until accepted_count sha256",
        )
        if health["status"] not in _SOURCE_STATUSES:
            raise ValueError("Invalid source health status")
        if sid not in licenses and health != _json_value(
            {
                name: value
                for name, value in asdict(SourceState(status="disabled")).items()
                if name not in ("notices", "error")
            }
        ):
            raise ValueError("Unapproved raw source state in public status")
        for field in ("last_attempt_at", "last_success_at", "generated_at", "valid_until"):
            if health[field] is not None:
                _time(health[field])
        if type(health["accepted_count"]) is not int or health["accepted_count"] < 0:
            raise ValueError("Invalid accepted source count")
    for item in _array(metadata["exclusions"]):
        _object(item, "target source_id reason")
        if item["source_id"] not in licenses or item["reason"] != "allowlisted":
            raise ValueError("Unapproved or invalid exclusion provenance")
        purpose = licenses[item["source_id"]]["purpose"]
        if normalize_target(item["target"], purpose) != item["target"]:
            raise ValueError("Noncanonical exclusion target")

    list_rows = _object(manifest["lists"])
    entries = _object(metadata["entries"])
    if set(list_rows) != set(_KEYS) or set(entries) != set(_KEYS):
        raise ValueError("Publication must contain all eight lists")
    targets = {}
    for key in _KEYS:
        kind, version = key.split("-ipv")
        row = _object(list_rows[key], "path status count sha256 valid_until")
        if row["path"] != f"lists/{key}.txt" or row["status"] not in _LIST_STATUSES:
            raise ValueError("Invalid list path or status")
        raw = (output / row["path"]).read_bytes()
        if _digest(raw) != row["sha256"]:
            raise ValueError("List checksum mismatch")
        if b"\r" in raw or (raw and not raw.endswith(b"\n")):
            raise ValueError("Lists require LF and a final newline")
        lines = raw.decode("utf-8").split("\n")[:-1] if raw else []
        addresses = [line for line in lines if not line.startswith("#")]
        if kind != "network" and lines != addresses:
            raise ValueError("Pure IP lists cannot contain comments")
        purpose = "web" if kind in ("block", "observe") else kind
        for target in addresses:
            if normalize_target(target, purpose) != target or sort_key(target)[0] != int(version):
                raise ValueError("Invalid list target or address family")
        if addresses != sorted(set(addresses), key=sort_key):
            raise ValueError("List targets must be unique and numerically sorted")
        if type(row["count"]) is not int or row["count"] != len(addresses):
            raise ValueError("List count mismatch")
        current = _array(entries[key])
        if [entry["target"] for entry in current] != addresses:
            raise ValueError("List and metadata targets differ")
        for entry in current:
            _validate_entry(entry, key, licenses, now)
        related = [sources[sid] for sid, spec in licenses.items() if _relevant(spec, key)]
        # Status was decided at build time; consumer-time checks still reject
        # expired effective list deadlines and evidence without rewriting it.
        status, deadline = _list_health(current, related, built_at)
        if row["status"] != status or row["valid_until"] != deadline:
            raise ValueError("List health or effective expiry mismatch")
        if row["valid_until"] is not None and _time(row["valid_until"]) <= now:
            raise ValueError("Expired publication list")
        if kind == "network":
            expected = _network_header(key, current, licenses, sources, built_at) + addresses
            if lines != expected:
                raise ValueError("Network attribution comments differ from source metadata")
        targets[key] = set(addresses)
    if any(targets[f"block-ipv{v}"] & targets[f"observe-ipv{v}"] for v in (4, 6)):
        raise ValueError("Web block and observe tiers must be disjoint")
    if not (output / "index.html").is_file() or not (output / ".nojekyll").is_file():
        raise ValueError("Publication page or Pages marker is missing")
