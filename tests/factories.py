import hashlib
from dataclasses import replace
from datetime import datetime, timezone

from ipbeaco.models import InputRecord, Snapshot, SourceSpec

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def source(**changes) -> SourceSpec:
    base = SourceSpec(
        id="test-web",
        family="test-family",
        purpose="web",
        adapter="blocklist_de",
        url="https://example.invalid/feed.txt",
        enabled=True,
        public_approved=True,
        license_url="https://example.invalid/license",
        reviewed_at=NOW,
        time_mode="observed",
        max_tier="block",
        independent=True,
        category="web_attack",
    )
    return replace(base, **changes)


def snapshot(*targets: str, **changes) -> Snapshot:
    raw = "".join(target + "\n" for target in targets).encode()
    base = Snapshot(
        source_id="test-web",
        fetched_at=NOW,
        generated_at=NOW,
        records=tuple(InputRecord(target, "web_attack", NOW) for target in targets),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    return replace(base, **changes)
