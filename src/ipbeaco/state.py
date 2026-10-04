"""Strict schema-v1 codec and checksum-protected, fail-closed persistence."""

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ipbeaco.models import Evidence, Presence, RunRecord, SourceState, State, StateError


def _object(value, fields=None):
    if type(value) is not dict:
        raise StateError("Expected a JSON object")
    if any(type(key) is not str for key in value):
        raise StateError("Object keys must be strings")
    if fields is not None and set(value) != set(fields.split()):
        raise StateError("Missing or unexpected state fields")
    return value


def _string(value, *, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str:
        raise StateError("Expected a string")
    return value


def _array(value):
    if type(value) is not list:
        raise StateError("Expected an array")
    return value


def _time(value, *, nullable=False):
    if nullable and value is None:
        return None
    parsed = datetime.fromisoformat(_string(value))
    if parsed.utcoffset() is None:
        raise StateError("State timestamps must have a timezone")
    return parsed.astimezone(timezone.utc)


def _choice(value, choices):
    value = _string(value)
    if value not in choices:
        raise StateError("Unknown state enum value")
    return value


def _evidence(value):
    row = _object(
        value,
        "source_id target category first_seen_at observed_at snapshot_at "
        "time_basis block_until observe_until expires_at",
    )
    return Evidence(
        source_id=_string(row["source_id"]),
        target=_string(row["target"]),
        category=_string(row["category"]),
        first_seen_at=_time(row["first_seen_at"]),
        observed_at=_time(row["observed_at"], nullable=True),
        snapshot_at=_time(row["snapshot_at"], nullable=True),
        time_basis=_choice(row["time_basis"], {"observed", "rolling", "unknown", "snapshot"}),
        block_until=_time(row["block_until"], nullable=True),
        observe_until=_time(row["observe_until"], nullable=True),
        expires_at=_time(row["expires_at"]),
    )


def _presence(value):
    row = _object(value, "first_seen_at present")
    if type(row["present"]) is not bool:
        raise StateError("Presence.present must be a boolean")
    return Presence(first_seen_at=_time(row["first_seen_at"]), present=row["present"])


def _source(value):
    row = _object(
        value,
        "last_attempt_at last_success_at status generated_at valid_until "
        "accepted_count sha256 notices error",
    )
    count = row["accepted_count"]
    if type(count) is not int or count < 0:
        raise StateError("accepted_count must be a nonnegative integer")
    return SourceState(
        last_attempt_at=_time(row["last_attempt_at"], nullable=True),
        last_success_at=_time(row["last_success_at"], nullable=True),
        status=_choice(row["status"], {"ok", "empty", "error", "stale", "disabled", "unavailable"}),
        generated_at=_time(row["generated_at"], nullable=True),
        valid_until=_time(row["valid_until"], nullable=True),
        accepted_count=count,
        sha256=_string(row["sha256"], nullable=True),
        notices=tuple(_string(notice) for notice in _array(row["notices"])),
        error=_string(row["error"], nullable=True),
    )


def _run(value):
    row = _object(value, "build_id generated_at")
    return RunRecord(build_id=_string(row["build_id"]), generated_at=_time(row["generated_at"]))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StateError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise StateError(f"Invalid JSON constant: {value}")


def decode_state(raw: bytes) -> State:
    """Decode the complete schema; unknown, missing and mistyped fields are errors."""
    if type(raw) is not bytes:
        raise StateError("State input must be bytes")
    try:
        row = _object(
            json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_invalid_constant,
            ),
            "schema_version evidence presence sources history",
        )
        if type(row["schema_version"]) is not int or row["schema_version"] != 1:
            raise StateError("Unsupported state schema version")
        return State(
            schema_version=1,
            evidence=tuple(_evidence(value) for value in _array(row["evidence"])),
            presence={
                source: {target: _presence(marker) for target, marker in _object(markers).items()}
                for source, markers in _object(row["presence"]).items()
            },
            sources={source: _source(value) for source, value in _object(row["sources"]).items()},
            history=tuple(_run(value) for value in _array(row["history"])),
        )
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        if isinstance(exc, StateError):
            raise
        raise StateError(f"Invalid state: {exc}") from exc


def _json_value(value):
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            raise StateError("State timestamps must have a timezone")
        return value.astimezone(timezone.utc).isoformat()
    if type(value) is dict:
        _object(value)
        return {key: _json_value(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [_json_value(item) for item in value]
    return value


def encode_state(state: State) -> bytes:
    """Encode stable UTF-8 JSON, with timestamps normalized to UTC."""
    if type(state) is not State:
        raise StateError("Expected a State model")
    try:
        raw = (
            json.dumps(
                _json_value(asdict(state)),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        decode_state(raw)  # Validate model fields as strictly as loaded state.
        return raw
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        if isinstance(exc, StateError):
            raise
        raise StateError(f"Cannot encode state: {exc}") from exc


def _path_present(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def load_state(directory: Path, *, bootstrap: bool = False) -> State:
    """Load both files, permitting explicit bootstrap only when both are absent."""
    data_path = directory / "state.json"
    checksum_path = directory / "state.sha256"
    try:
        data_exists = _path_present(data_path)
        checksum_exists = _path_present(checksum_path)
        if not data_exists and not checksum_exists and bootstrap:
            return State()
        if not data_exists or not checksum_exists:
            raise StateError("State file pair is missing or incomplete")
        raw = data_path.read_bytes()
        checksum = checksum_path.read_bytes()
        if not re.fullmatch(rb"[0-9a-f]{64}\n", checksum):
            raise StateError("Invalid state checksum file")
        if checksum != hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n":
            raise StateError("State checksum mismatch; restore the last complete committed state")
        return decode_state(raw)
    except OSError as exc:
        raise StateError(f"Cannot load state: {exc}") from exc


def _atomic_write(path: Path, raw: bytes):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_state(state: State, directory: Path) -> None:
    """Replace data then checksum; interrupted pairs deliberately fail validation."""
    raw = encode_state(state)
    checksum = hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        _atomic_write(directory / "state.json", raw)
        _atomic_write(directory / "state.sha256", checksum)
    except OSError as exc:
        raise StateError(f"Cannot save state: {exc}") from exc
