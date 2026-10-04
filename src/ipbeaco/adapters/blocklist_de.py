"""Parse category-specific plain TXT without inventing observation times."""

from datetime import datetime

from ipbeaco.models import InputRecord, Snapshot, SourceSpec

from ._common import decode, snapshot, target


def parse(raw: bytes, spec: SourceSpec, fetched_at: datetime) -> Snapshot:
    records = []
    for line in decode(raw).splitlines():
        if line.strip():
            records.append(InputRecord(target(line.strip()), spec.category))
    return snapshot(raw, spec, fetched_at, None, records)
