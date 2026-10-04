"""Structural parsing helpers; public-address admission is a later stage."""

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address, ip_network

from ipbeaco.models import InputRecord, Snapshot, SourceError, SourceSpec


def decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SourceError("invalid_format: feed must be UTF-8 text") from None


def target(text: str, *, network: bool = False) -> str:
    if not isinstance(text, str) or "%" in text or ("/" in text) != network:
        raise SourceError("invalid_format: expected IP" + (" network" if network else " address"))
    try:
        return str(ip_network(text, strict=True) if network else ip_address(text))
    except ValueError:
        raise SourceError("invalid_format: malformed target") from None


def snapshot(
    raw: bytes,
    spec: SourceSpec,
    fetched_at: datetime,
    generated_at: datetime | None,
    records: list[InputRecord],
    notices: list[str] | None = None,
) -> Snapshot:
    return Snapshot(
        source_id=spec.id,
        fetched_at=fetched_at.astimezone(timezone.utc) if fetched_at.utcoffset() else fetched_at,
        generated_at=generated_at,
        records=tuple(records),
        sha256=sha256(raw).hexdigest(),
        notices=tuple(notices or ()),
    )
