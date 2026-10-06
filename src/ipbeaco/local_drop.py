"""Explicit local-only DROP batches with durable daily request limits.

State is deliberately incompatible with public State. POSIX flock holds across
state reads, requests, validation, and publication; failed requests consume the
same daily allowance as successful requests.
"""

import hashlib
import json
import re
import tempfile
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import httpx

from ipbeaco.adapters import PARSERS
from ipbeaco.addresses import is_allowed, normalize_target, sort_key
from ipbeaco.config import validate_config
from ipbeaco.export import _check_now, _comment, _json_bytes
from ipbeaco.fetch import download
from ipbeaco.models import Config, SourceError, StateError
from ipbeaco.state import _atomic_write, _invalid_constant, _unique_object
from ipbeaco.temporal import _deadline, _normalized_records

_PROTOCOL = "ipbeaco-drop-local-v1"
_ENDPOINTS = {
    "spamhaus-drop-v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "spamhaus-drop-v6": "https://www.spamhaus.org/drop/drop_v6.json",
}
_FILES = {f"network-ipv{version}" for version in (4, 6)}


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_json(path):
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (OSError, ValueError) as error:
        raise StateError(f"Cannot read local JSON: {path.name}") from error


def _exact(row, fields):
    if type(row) is not dict or set(row) != set(fields.split()):
        raise StateError("Missing or unexpected local protocol fields")


def _time(value):
    if type(value) is not str:
        raise StateError("Invalid local timestamp")
    result = datetime.fromisoformat(value)
    if result.utcoffset() is None:
        raise StateError("Local timestamps must include a timezone")
    return result


def _hash(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise StateError("Invalid local checksum")


def _strings(value):
    if type(value) is not list or any(type(item) is not str for item in value):
        raise StateError("Invalid local string array")


def _targets(value, version):
    _strings(value)
    if value != sorted(set(value), key=sort_key):
        raise StateError("Local CIDRs must be unique and numerically sorted")
    for target in value:
        if normalize_target(target, "network") != target or sort_key(target)[0] != version:
            raise StateError("Invalid local target family or canonical CIDR")


def _marker(row):
    if row["protocol"] != _PROTOCOL or row["local_only"] is not True:
        raise StateError("Expected the local-only DROP protocol")


def _specs(config):
    validate_config(config)
    result = []
    for sid, url in _ENDPOINTS.items():
        version = int(sid[-1])
        spec = next((item for item in config.sources if item.id == sid), None)
        if spec is None or (
            spec.url != url
            or spec.adapter != "spamhaus_drop"
            or spec.purpose != "network"
            or spec.time_mode != "snapshot"
            or spec.ip_versions != (version,)
        ):
            raise SourceError(f"invalid_local_drop_source: {sid}")
        result.append(spec)
    return result


@contextmanager
def _locked(directory):
    try:
        import fcntl
    except ImportError:
        raise StateError("Local DROP requires POSIX flock support") from None
    if directory.exists() and any(
        entry.name not in {"local-state.json", "local.lock"} for entry in directory.iterdir()
    ):
        raise StateError("Local state directory must be separate from public state/config")
    if directory.is_symlink() or any(
        (directory / name).is_symlink() for name in ("local-state.json", "local.lock")
    ):
        raise StateError("Local state paths must not be symlinks")
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "local.lock").open("a+b") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateError("Another local DROP run holds the state lock") from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _load_state(directory, now, *, initial):
    path = directory / "local-state.json"
    if not path.exists():
        if not initial:
            raise StateError("Local state is missing; do not reset the daily request history")
        return {"protocol": _PROTOCOL, "local_only": True, "sources": {}}
    envelope = _read_json(path)
    _exact(envelope, "data sha256")
    if envelope["sha256"] != _digest(_json_bytes(envelope["data"])):
        raise StateError("Local state checksum mismatch")
    data = envelope["data"]
    _exact(data, "protocol local_only sources")
    _marker(data)
    if type(data["sources"]) is not dict or set(data["sources"]) - set(_ENDPOINTS):
        raise StateError("Invalid local state sources")
    for sid, row in data["sources"].items():
        _exact(row, "last_attempt_at accepted error")
        attempted = _time(row["last_attempt_at"])
        if attempted > now:
            raise StateError("Local request history is in the future")
        if row["error"] is not None and type(row["error"]) is not str:
            raise StateError("Invalid local error")
        accepted = row["accepted"]
        if accepted is not None:
            _exact(accepted, "generated_at valid_until fetched_at targets sha256")
            generated, fetched, until = map(
                _time, (accepted["generated_at"], accepted["fetched_at"], accepted["valid_until"])
            )
            if fetched > attempted or generated > fetched + timedelta(minutes=5):
                raise StateError("Invalid accepted local timestamps")
            if not generated < until <= generated + timedelta(hours=48):
                raise StateError("Invalid accepted local expiry")
            _targets(accepted["targets"], int(sid[-1]))
            _hash(accepted["sha256"])
    return data


def _save_state(data, directory):
    _atomic_write(
        directory / "local-state.json",
        _json_bytes({"data": data, "sha256": _digest(_json_bytes(data))}),
    )


def _network_bytes(source):
    comments = [
        "IPBeaco local-only DROP; not a public publication",
        source["attribution"],
        source["url"],
        source["license_url"],
        f"Generated by upstream: {source['generated_at']}",
        f"Valid until: {source['valid_until']}",
        *source["notices"],
    ]
    lines = [line for text in comments for line in _comment(text)]
    return ("\n".join(lines + source["targets"]) + "\n").encode("utf-8")


def validate_local_drop(directory: Path, now: datetime) -> None:
    """Validate both families, comments, provenance, hashes, and current expiry."""
    _check_now(now)
    names = {"status.json", "metadata.json", *(key + ".txt" for key in _FILES)}
    if {path.name for path in directory.iterdir()} != names or any(
        not path.is_file() or path.is_symlink() for path in directory.iterdir()
    ):
        raise StateError("Local batch must contain exactly four regular files")
    status, metadata = (
        _read_json(directory / "status.json"),
        _read_json(directory / "metadata.json"),
    )
    _exact(status, "protocol local_only build_id generated_at metadata_sha256 lists")
    _exact(metadata, "protocol local_only build_id generated_at sources")
    _marker(status)
    _marker(metadata)
    if type(status["build_id"]) is not str or not status["build_id"].strip():
        raise StateError("Invalid local build ID")
    if (
        metadata["build_id"] != status["build_id"]
        or metadata["generated_at"] != status["generated_at"]
    ):
        raise StateError("Local batch identity mismatch")
    built = _time(status["generated_at"])
    if built > now + timedelta(minutes=5):
        raise StateError("Future local build timestamp")
    if status["metadata_sha256"] != _digest((directory / "metadata.json").read_bytes()):
        raise StateError("Local metadata checksum mismatch")
    if type(status["lists"]) is not dict or set(status["lists"]) != _FILES:
        raise StateError("Local batch requires both IP families")
    if type(metadata["sources"]) is not dict or set(metadata["sources"]) != set(_ENDPOINTS):
        raise StateError("Local batch source mismatch")
    for sid, url in _ENDPOINTS.items():
        source = metadata["sources"][sid]
        _exact(
            source,
            "url license_url attribution enabled public_approved generated_at fetched_at "
            "valid_until upstream_expires_at snapshot_hours sha256 notices targets "
            "excluded_allowlist accepted_count",
        )
        if source["url"] != url or any(
            type(source[field]) is not bool for field in ("enabled", "public_approved")
        ):
            raise StateError("Invalid local source provenance")
        if any(
            type(source[field]) is not str or not source[field].strip()
            for field in ("attribution", "license_url")
        ):
            raise StateError("Missing local source attribution")
        generated, fetched, until = map(
            _time, (source["generated_at"], source["fetched_at"], source["valid_until"])
        )
        if fetched > built or generated > min(now, fetched) + timedelta(minutes=5):
            raise StateError("Invalid local source timestamps")
        hours = source["snapshot_hours"]
        if type(hours) is not int or not 1 <= hours <= 48:
            raise StateError("Invalid local snapshot window")
        deadline = generated + timedelta(hours=hours)
        if source["upstream_expires_at"] is not None:
            deadline = min(deadline, _time(source["upstream_expires_at"]))
        if until > deadline or until <= now or until <= generated:
            raise StateError("Expired or invalid local deadline")
        _hash(source["sha256"])
        _strings(source["notices"])
        if not source["notices"] or url not in source["notices"]:
            raise StateError("Missing local upstream notices")
        version = int(sid[-1])
        targets = source["targets"]
        _targets(targets, version)
        _targets(source["excluded_allowlist"], version)
        if set(targets) & set(source["excluded_allowlist"]):
            raise StateError("Excluded local targets are present")
        if type(source["accepted_count"]) is not int or source["accepted_count"] != (
            len(targets) + len(source["excluded_allowlist"])
        ):
            raise StateError("Local accepted count mismatch")
        key = f"network-ipv{version}"
        row = status["lists"][key]
        _exact(row, "status count sha256 valid_until source_id")
        raw = (directory / (key + ".txt")).read_bytes()
        if raw != _network_bytes(source) or row["sha256"] != _digest(raw):
            raise StateError("Local network file integrity mismatch")
        if (
            row["source_id"] != sid
            or row["valid_until"] != source["valid_until"]
            or type(row["count"]) is not int
            or row["count"] != len(targets)
            or row["status"] != ("ok" if targets else "empty")
        ):
            raise StateError("Local list status mismatch")


def run_local_drop(
    config: Config,
    state_dir: Path,
    output: Path,
    client: httpx.Client,
    now: datetime,
    build_id: str,
    *,
    clock: Callable[[], datetime] | None = None,
) -> None:
    """Download once per source/day and publish only a complete validated batch."""
    _check_now(now)
    specs = _specs(config)
    if type(build_id) is not str or not build_id.strip():
        raise ValueError("Local build ID must be nonempty")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Output already exists: {output}")
    state_path, output_path = state_dir.resolve(), output.resolve()
    if state_path.is_relative_to(output_path) or output_path.is_relative_to(state_path):
        raise StateError("Local state and output directories must not overlap")
    initial = not (state_dir / "local.lock").exists()
    with _locked(state_dir):
        state = _load_state(state_dir, now, initial=initial)
        for spec in specs:
            previous = state["sources"].get(spec.id)
            if previous and now < _time(previous["last_attempt_at"]) + timedelta(hours=24):
                raise SourceError(f"local_cooldown: {spec.id}; wait at least 24 hours")
        sources, accepted = {}, {}
        settings = replace(config.settings, attempts=1)
        last_request = now
        for spec in specs:
            attempted_at = clock() if clock else now
            _check_now(attempted_at)
            if attempted_at < last_request:
                raise StateError("Local clock moved backwards during the batch")
            last_request = attempted_at
            previous = state["sources"].get(spec.id, {}).get("accepted")
            row = {"last_attempt_at": attempted_at.isoformat(), "accepted": previous, "error": None}
            state["sources"][spec.id] = row
            _save_state(state, state_dir)  # Durable before any request, including a failed one.
            try:
                snap = PARSERS[spec.adapter](
                    download(spec.url, settings, client), spec, attempted_at
                )
                records, notices = _normalized_records(spec, snap, settings, attempted_at)
                deadline = _deadline(spec, snap, settings, attempted_at, empty=not records)
                if snap.generated_at is None or deadline is None:
                    raise SourceError("missing_generated_at")
                if attempted_at >= deadline:
                    raise SourceError("stale_snapshot")
                if previous:
                    last_generated = _time(previous["generated_at"])
                    if snap.generated_at < last_generated:
                        raise SourceError("generated_at_regression")
                    if snap.generated_at == last_generated:
                        if snap.sha256 != previous["sha256"]:
                            raise SourceError("inconsistent_snapshot")
                        deadline = min(deadline, _time(previous["valid_until"]))
                        if attempted_at >= deadline:
                            raise SourceError("stale_snapshot")
                    if (
                        len(records.keys() - set(previous["targets"])) >= settings.anomaly_new
                        and len(records) > len(previous["targets"]) * settings.anomaly_ratio
                    ):
                        raise SourceError("anomalous_growth")
                targets = sorted(records, key=sort_key)
                excluded = [target for target in targets if is_allowed(target, config.allowlist)]
                excluded_set = set(excluded)
                accepted[spec.id] = {
                    "generated_at": snap.generated_at.isoformat(),
                    "valid_until": deadline.isoformat(),
                    "fetched_at": attempted_at.isoformat(),
                    "targets": targets,
                    "sha256": snap.sha256,
                }
                sources[spec.id] = {
                    "url": spec.url,
                    "license_url": spec.license_url,
                    "attribution": spec.attribution,
                    "enabled": spec.enabled,
                    "public_approved": spec.public_approved,
                    "generated_at": snap.generated_at.isoformat(),
                    "fetched_at": attempted_at.isoformat(),
                    "valid_until": deadline.isoformat(),
                    "snapshot_hours": settings.snapshot_hours,
                    "upstream_expires_at": snap.upstream_expires_at.isoformat()
                    if snap.upstream_expires_at
                    else None,
                    "sha256": snap.sha256,
                    "notices": list(notices),
                    "targets": [target for target in targets if target not in excluded_set],
                    "excluded_allowlist": excluded,
                    "accepted_count": len(targets),
                }
            except (SourceError, ValueError, OSError) as error:
                row["error"] = str(error)
                _save_state(state, state_dir)
                raise
        completed_at = clock() if clock else now
        _check_now(completed_at)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=output.parent, prefix=f".{output.name}.") as temporary:
            stage = Path(temporary)
            common = {
                "protocol": _PROTOCOL,
                "local_only": True,
                "build_id": build_id,
                "generated_at": completed_at.isoformat(),
            }
            metadata = {**common, "sources": sources}
            raw_metadata = _json_bytes(metadata)
            _atomic_write(stage / "metadata.json", raw_metadata)
            lists = {}
            for sid, source in sources.items():
                key = f"network-ipv{sid[-1]}"
                raw = _network_bytes(source)
                _atomic_write(stage / (key + ".txt"), raw)
                lists[key] = {
                    "status": "ok" if source["targets"] else "empty",
                    "count": len(source["targets"]),
                    "sha256": _digest(raw),
                    "valid_until": source["valid_until"],
                    "source_id": sid,
                }
            _atomic_write(
                stage / "status.json",
                _json_bytes({**common, "metadata_sha256": _digest(raw_metadata), "lists": lists}),
            )
            validate_local_drop(stage, clock() if clock else completed_at)
            if output.exists() or output.is_symlink():
                raise FileExistsError(f"Output already exists: {output}")
            # Persist before visibility; roll back success baselines on a rename
            # failure while retaining the durable request attempts.
            prior = {sid: state["sources"][sid]["accepted"] for sid in accepted}
            try:
                for sid, baseline in accepted.items():
                    state["sources"][sid]["accepted"] = baseline
                _save_state(state, state_dir)
                stage.rename(output)
            except OSError:
                for sid, baseline in prior.items():
                    state["sources"][sid]["accepted"] = baseline
                _save_state(state, state_dir)
                raise
