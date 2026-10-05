import hashlib
import importlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ipbeaco.models import SourceError
from tests.factories import NOW, source

FIXTURES = Path(__file__).parent / "fixtures"


def parser(name):
    try:
        return importlib.import_module(f"ipbeaco.adapters.{name}").parse
    except ModuleNotFoundError:
        pytest.fail(f"missing {name} adapter")


def drop_metadata(**changes):
    import json

    fields = {"type": "metadata", "timestamp": 1791072000, "copyright": "TEST NOTICE"}
    fields.update(changes)
    return json.dumps(fields).encode() + b"\n"


DROP_ENTRY = b'{"cidr":"192.0.2.0/24","sblid":"SBL-TEST"}\n'
FEODO = b"# Last updated: 2026-10-04 00:00:00 UTC\n# DstIP\n192.0.2.1\n# END 1 entries\n"


def test_blocklist_preserves_unknown_time_and_configured_category():
    raw = (FIXTURES / "blocklist/valid.txt").read_bytes()
    parsed = parser("blocklist_de")(raw, source(time_mode="unknown", category="web_candidate"), NOW)
    assert [item.target for item in parsed.records] == ["192.0.2.1", "2001:db8::1"]
    assert all(
        item.category == "web_candidate" and item.observed_at is None for item in parsed.records
    )
    assert parsed.generated_at is None
    assert parsed.fetched_at == NOW
    assert parsed.sha256 == hashlib.sha256(raw).hexdigest()


def test_blocklist_empty_is_valid():
    assert parser("blocklist_de")(b"", source(time_mode="unknown"), NOW).records == ()


@pytest.mark.parametrize(
    "raw",
    [
        b"<html>192.0.2.1</html>",
        b"# updated today\n192.0.2.1",
        b"192.0.2.0/24",
        b"192.0.2.1 garbage",
        b"\xff",
        b"fe80::1%eth0",
    ],
)
def test_blocklist_rejects_broken_lines(raw):
    with pytest.raises(SourceError):
        parser("blocklist_de")(raw, source(), NOW)


def test_drop_separates_metadata_and_retains_provenance():
    raw = (FIXTURES / "drop/valid.ndjson").read_bytes()
    spec = source(purpose="network", adapter="spamhaus_drop", time_mode="snapshot")
    parsed = parser("spamhaus")(raw, spec, NOW)
    assert [item.target for item in parsed.records] == ["192.0.2.0/24", "2001:db8::/32"]
    assert all(
        item.category == "network_drop" and item.observed_at is None for item in parsed.records
    )
    assert parsed.generated_at == NOW
    assert parsed.sha256 == hashlib.sha256(raw).hexdigest()
    assert "TEST NOTICE" in parsed.notices
    assert "https://example.invalid/terms" in parsed.notices
    assert spec.url in parsed.notices
    assert "SBL 192.0.2.0/24 SBL-TEST-V4" in parsed.notices
    assert "SBL 2001:db8::/32 SBL-TEST-V6" in parsed.notices


def test_drop_validates_count_and_size_without_counting_metadata():
    raw = DROP_ENTRY + drop_metadata(records=1, size=len(DROP_ENTRY))
    parsed = parser("spamhaus")(raw, source(purpose="network"), NOW)
    assert len(parsed.records) == 1


def test_drop_empty_metadata_snapshot():
    parsed = parser("spamhaus")(drop_metadata(records=0, size=0), source(purpose="network"), NOW)
    assert parsed.records == ()
    assert parsed.generated_at == NOW


@pytest.mark.parametrize(
    "raw",
    [
        DROP_ENTRY,
        b"",
        b"<html>error</html>",
        DROP_ENTRY + b'{"type":',
        DROP_ENTRY + drop_metadata() + drop_metadata(),
        drop_metadata() + DROP_ENTRY,
        DROP_ENTRY + drop_metadata(records=2),
        DROP_ENTRY + drop_metadata(records=True),
        DROP_ENTRY + drop_metadata(size=0),
        DROP_ENTRY + drop_metadata(timestamp="bad"),
        DROP_ENTRY + drop_metadata(timestamp=True),
        DROP_ENTRY + drop_metadata(timestamp=1e100),
        DROP_ENTRY + drop_metadata(copyright=""),
        b"{}\n" + drop_metadata(),
        b'{"cidr":"192.0.2.1/24","sblid":"SBL-TEST"}\n' + drop_metadata(),
        b'{"cidr":"192.0.2.0/24"}\n' + drop_metadata(),
        b'{"cidr":"192.0.2.0/24","sblid":123}\n' + drop_metadata(),
        b'{"cidr":"192.0.2.0/24","cidr":"2001:db8::/32","sblid":"SBL-TEST"}\n' + drop_metadata(),
        b"[]\n" + drop_metadata(),
        b"\xff",
    ],
)
def test_drop_rejects_malformed_or_inconsistent_feed(raw):
    with pytest.raises(SourceError):
        parser("spamhaus")(raw, source(purpose="network"), NOW)


def test_feodo_keeps_old_embedded_time_not_download_time():
    raw = (FIXTURES / "feodo/valid.txt").read_bytes()
    parsed = parser("feodo")(raw, source(purpose="c2", adapter="feodo", time_mode="snapshot"), NOW)
    assert parsed.generated_at == datetime(2026, 3, 4, 14, 28, 39, tzinfo=timezone.utc)
    assert parsed.fetched_at == NOW
    assert parsed.records[0].target == "192.0.2.1"
    assert parsed.records[0].category == "botnet_c2"
    assert parsed.records[0].observed_at is None
    assert parsed.sha256 == hashlib.sha256(raw).hexdigest()


def test_feodo_validated_empty_snapshot():
    raw = (FIXTURES / "feodo/empty.txt").read_bytes()
    parsed = parser("feodo")(raw, source(purpose="c2"), NOW)
    assert parsed.records == ()
    assert parsed.generated_at == NOW


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"<html>192.0.2.1</html>",
        FEODO.replace(b"END 1", b"END 2"),
        FEODO.replace(b"2026-10-04", b"2026-13-04"),
        FEODO.replace(b" UTC", b" XYZ"),
        FEODO.replace(b"# DstIP\n", b""),
        FEODO.replace(b"# END 1 entries\n", b""),
        FEODO + b"192.0.2.2\n",
        FEODO.replace(b"192.0.2.1", b"broken"),
        FEODO.replace(b"192.0.2.1", b"192.0.2.0/24"),
        FEODO.replace(b"# DstIP", b"# DstIP\n# DstIP"),
        FEODO.replace(b"# DstIP", b"# Last updated: 2026-10-04 00:00:00 UTC\n# DstIP"),
        FEODO.replace(b"# DstIP", b"# END broken entries\n# DstIP"),
        FEODO.replace(
            b"# DstIP", b"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (aggressive) #\n# DstIP"
        ),
        b"\xff",
    ],
)
def test_feodo_rejects_broken_structure(raw):
    with pytest.raises(SourceError):
        parser("feodo")(raw, source(purpose="c2"), NOW)


def test_registry_exposes_all_adapter_contracts():
    try:
        from ipbeaco.adapters import PARSERS
    except ModuleNotFoundError:
        pytest.fail("missing adapter registry")
    assert set(PARSERS) == {"blocklist_de", "spamhaus_drop", "feodo", "cins_army"}
    for name, module in (
        ("blocklist_de", "blocklist_de"),
        ("spamhaus_drop", "spamhaus"),
        ("feodo", "feodo"),
    ):
        assert PARSERS[name] is parser(module)


def test_feodo_accepts_official_descriptive_header_comments():
    raw = FEODO.replace(
        b"# DstIP",
        b"# For questions please contact feodotracker [at] abuse.ch #\n"
        b"# Additional feed description #\n#                 #\n"
        b"############################################################\n# DstIP",
    )
    assert len(parser("feodo")(raw, source(purpose="c2"), NOW).records) == 1


@pytest.mark.parametrize("position", ["between", "after_end"])
def test_feodo_accepts_nonstructural_comments_around_records(position):
    comments = b"# Explanatory comment\n##########\n#           #\n"
    if position == "between":
        raw = FEODO.replace(b"192.0.2.1\n", comments + b"192.0.2.1\n" + comments)
    else:
        raw = FEODO + comments
    parsed = parser("feodo")(raw, source(purpose="c2"), NOW)
    assert [record.target for record in parsed.records] == ["192.0.2.1"]
    assert parsed.generated_at == NOW


@pytest.mark.parametrize(
    "comment",
    [
        b"# Last updated: 2026-10-04 00:00:00 UTC\n",
        b"# Last updated: broken\n",
        b"# DstIP\n",
        b"# END broken entries\n",
        b"# END 1 entries\n",
        b"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (aggressive) #\n",
    ],
)
@pytest.mark.parametrize("position", ["between", "after_end"])
def test_feodo_rejects_structural_comments_outside_header(comment, position):
    raw = FEODO.replace(b"192.0.2.1\n", comment + b"192.0.2.1\n")
    if position == "after_end":
        raw = FEODO + comment
    with pytest.raises(SourceError):
        parser("feodo")(raw, source(purpose="c2"), NOW)


def test_feodo_rejects_data_after_end_even_with_trailing_comments():
    raw = FEODO + b"# harmless comment\n192.0.2.2\n"
    with pytest.raises(SourceError):
        parser("feodo")(raw, source(purpose="c2"), NOW)
