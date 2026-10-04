"""Parse DROP NDJSON, preserving generation time and attribution."""

import json
from datetime import datetime, timezone

from ipbeaco.models import InputRecord, Snapshot, SourceError, SourceSpec

from ._common import decode, snapshot, target


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SourceError("invalid_format: duplicate JSON field")
        result[key] = value
    return result


def _text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def parse(raw: bytes, spec: SourceSpec, fetched_at: datetime) -> Snapshot:
    records = []
    notices = [spec.url]
    metadata = None
    entry_size = 0
    for line in decode(raw).splitlines(keepends=True):
        if not line.strip():
            raise SourceError("invalid_format: empty NDJSON line")
        try:
            item = json.loads(line, object_pairs_hook=_object)
        except (ValueError, TypeError):
            raise SourceError("invalid_format: malformed DROP JSON") from None
        if not isinstance(item, dict) or metadata is not None:
            raise SourceError("invalid_format: DROP metadata must be the final object")
        if item.get("type") == "metadata":
            metadata = item
        else:
            if set(item) - {"cidr", "sblid", "rir"} or not _text(item.get("sblid")):
                raise SourceError("invalid_format: malformed DROP entry")
            if "rir" in item and not _text(item["rir"]):
                raise SourceError("invalid_format: malformed DROP registry")
            cidr = target(item.get("cidr"), network=True)
            records.append(InputRecord(cidr, "network_drop"))
            notices.append(f"SBL {cidr} {item['sblid']}")
            entry_size += len(line.encode("utf-8"))
    if metadata is None:
        raise SourceError("invalid_format: missing DROP metadata")
    if set(metadata) - {"type", "timestamp", "size", "records", "copyright", "terms"}:
        raise SourceError("invalid_format: unknown DROP metadata field")
    timestamp = metadata.get("timestamp")
    if type(timestamp) is not int or timestamp < 0:
        raise SourceError("invalid_format: invalid DROP timestamp")
    try:
        generated_at = datetime.fromtimestamp(timestamp, timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise SourceError("invalid_format: invalid DROP timestamp") from None
    for field, expected in (("records", len(records)), ("size", entry_size)):
        if field in metadata and (type(metadata[field]) is not int or metadata[field] != expected):
            raise SourceError(f"invalid_format: DROP {field} does not match payload")
    if not _text(metadata.get("copyright")):
        raise SourceError("invalid_format: missing DROP copyright")
    notices.append(metadata["copyright"])
    if "terms" in metadata:
        if not _text(metadata["terms"]):
            raise SourceError("invalid_format: invalid DROP terms")
        notices.append(metadata["terms"])
    return snapshot(raw, spec, fetched_at, generated_at, records, notices)
