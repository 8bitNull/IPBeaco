"""Parse CINS Army IPv4 reputation without inventing attack times."""

from datetime import datetime

from ipbeaco.models import InputRecord, Snapshot, SourceError, SourceSpec

from ._common import decode, snapshot, target


def parse(raw: bytes, spec: SourceSpec, fetched_at: datetime) -> Snapshot:
    records = []
    for line in decode(raw).split("\n"):
        if not line.strip():
            continue
        address = target(line.strip())
        if ":" in address:
            raise SourceError("invalid_format: CINS Army requires IPv4")
        records.append(InputRecord(address, "unknown"))
    return snapshot(raw, spec, fetched_at, None, records)
