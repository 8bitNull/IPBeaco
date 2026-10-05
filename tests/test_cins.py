import hashlib
import importlib
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from ipbeaco.config import load_config, validate_config
from ipbeaco.models import Config, ConfigError, Settings, SourceError
from ipbeaco.pipeline import run_once
from ipbeaco.state import load_state
from tests.factories import NOW, source


def cins_source(**changes):
    spec = source(
        id="cins-army",
        family="cins",
        adapter="cins_army",
        time_mode="unknown",
        max_tier="observe",
        category="unknown",
        independent=False,
        trusted_single=False,
        ip_versions=(4,),
    )
    return replace(spec, **changes)


def parse(raw):
    try:
        module = importlib.import_module("ipbeaco.adapters.cins")
    except ModuleNotFoundError:
        pytest.fail("CINS parser is not implemented")
    return module.parse(raw, cins_source(), NOW)


def run_feed(tmp_path, now, build_id, raw=b"8.8.8.8\n", *, status=200, allowlist=()):
    cfg = Config((cins_source(),), Settings(attempts=1), allowlist)
    output = tmp_path / build_id
    response = httpx.Response(
        status,
        content=raw,
        headers={"Last-Modified": "Sat, 10 Oct 2026 00:00:00 GMT"},
    )
    with httpx.Client(transport=httpx.MockTransport(lambda request: response)) as client:
        state = run_once(
            cfg,
            tmp_path / "state",
            output,
            client,
            now,
            build_id,
            bootstrap=build_id == "first",
        )
    return state, output


def test_parser_preserves_unknown_time_without_inventing_web_attacks():
    raw = b" 8.8.8.8\r\n\n10.0.0.1\n8.8.8.8\n"
    parsed = parse(raw)
    assert [record.target for record in parsed.records] == ["8.8.8.8", "10.0.0.1", "8.8.8.8"]
    assert all(record.category == "unknown" for record in parsed.records)
    assert all(record.observed_at is None for record in parsed.records)
    assert parsed.generated_at is None
    assert parsed.fetched_at == NOW
    assert parsed.sha256 == hashlib.sha256(raw).hexdigest()


def test_empty_feed_is_structurally_valid():
    assert parse(b"\n \r\n").records == ()


@pytest.mark.parametrize(
    "raw",
    [
        b"8.8.8.8\nnot-an-ip\n",
        b"8.8.8.0/24\n",
        b"2001:4860:4860::8888\n",
        b"8.8.8.8 extra\n",
        b"# updated today\n8.8.8.8\n",
        b"<html>8.8.8.8</html>",
        b"8.8.8.8\v1.1.1.1\n",
        b"\xff",
    ],
)
def test_parser_rejects_entire_malformed_or_unexpected_feed(raw):
    with pytest.raises(SourceError, match="invalid_format"):
        parse(raw)


def test_observation_config_is_valid():
    validate_config(Config((cins_source(),), Settings(), ()))


@pytest.mark.parametrize(
    "changes,field",
    [
        ({"purpose": "network", "time_mode": "snapshot"}, "purpose"),
        ({"purpose": "c2", "time_mode": "snapshot"}, "purpose"),
        ({"time_mode": "observed"}, "time_mode"),
        ({"time_mode": "rolling", "window_hours": 24}, "time_mode"),
        ({"time_mode": "snapshot"}, "time_mode"),
        ({"max_tier": "block"}, "max_tier"),
        ({"category": "web_attack"}, "category"),
        ({"independent": True}, "independent"),
        ({"trusted_single": True}, "trusted_single"),
        ({"ip_versions": (4, 6)}, "ip_versions"),
    ],
)
def test_capability_changes_fail_before_network_or_state_creation(tmp_path, changes, field):
    cfg = Config((cins_source(**changes),), Settings(), ())

    def forbidden(request):
        pytest.fail("invalid CINS configuration reached HTTP")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(ConfigError, match=f"cins-army.*{field}"):
            run_once(
                cfg, tmp_path / "state", tmp_path / "site", client, NOW, "invalid", bootstrap=True
            )
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "site").exists()


def test_pipeline_publishes_deduplicated_public_addresses_only_in_observe(tmp_path):
    state, output = run_feed(tmp_path, NOW, "first", b"8.8.8.8\n10.0.0.1\n1.1.1.1\n8.8.8.8\n")
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b"1.1.1.1\n8.8.8.8\n"
    for path in (output / "lists").glob("*.txt"):
        if path.name != "observe-ipv4.txt":
            assert path.read_bytes() == b""
    assert len(list((output / "lists").glob("*.txt"))) == 8
    status = json.loads((output / "lists/status.json").read_bytes())
    assert status["lists"]["observe-ipv4"]["status"] == "ok"
    assert status["lists"]["observe-ipv4"]["count"] == 2
    assert status["lists"]["observe-ipv6"]["status"] == "unavailable"
    assert all(e.category == "unknown" and e.block_until is None for e in state.evidence)
    assert load_state(tmp_path / "state") == state


def test_repeated_download_does_not_renew_expiry_or_resurrect_old_ips(tmp_path):
    first, _ = run_feed(tmp_path, NOW, "first")
    expiry = NOW + timedelta(days=7)
    assert first.evidence[0].expires_at == expiry
    repeated, _ = run_feed(tmp_path, NOW + timedelta(days=6), "repeated")
    assert repeated.evidence[0].expires_at == expiry
    assert repeated.evidence[0].snapshot_at is None
    expired, output = run_feed(tmp_path, expiry, "expired")
    assert expired.evidence == ()
    assert expired.presence["cins-army"]["8.8.8.8"].present
    assert expired.sources["cins-army"].status == "stale"
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b""


@pytest.mark.parametrize(
    "status,raw",
    [
        (503, b""),
        (200, b"<html>maintenance</html>"),
        (200, b"8.8.8.8\ninvalid-line\n"),
    ],
)
def test_failed_collection_retains_last_evidence_and_cannot_confirm_absence(tmp_path, status, raw):
    first, _ = run_feed(tmp_path, NOW, "first")
    failed, output = run_feed(tmp_path, NOW + timedelta(days=1), "failed", raw, status=status)
    assert failed.evidence == first.evidence
    assert failed.presence["cins-army"]["8.8.8.8"].present
    manifest = json.loads((output / "lists/status.json").read_bytes())
    assert manifest["lists"]["observe-ipv4"]["status"] == "degraded"
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b"8.8.8.8\n"
    expired, output = run_feed(tmp_path, NOW + timedelta(days=8), "expired", raw, status=status)
    assert expired.evidence == ()
    assert expired.presence["cins-army"]["8.8.8.8"].present
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b""


def test_successful_absence_allows_a_later_reappearance_to_start_new_observation(tmp_path):
    run_feed(tmp_path, NOW, "first")
    absent, _ = run_feed(tmp_path, NOW + timedelta(days=1), "absent", b"")
    assert not absent.presence["cins-army"]["8.8.8.8"].present
    returned, _ = run_feed(tmp_path, NOW + timedelta(days=2), "returned")
    assert returned.evidence[0].first_seen_at == NOW + timedelta(days=2)
    assert returned.evidence[0].expires_at == NOW + timedelta(days=9)


def test_allowlist_wins_over_cins_reputation(tmp_path):
    _, output = run_feed(tmp_path, NOW, "first", allowlist=("8.8.8.0/24",))
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b""
    metadata = json.loads((output / "lists/metadata.json").read_bytes())
    assert metadata["exclusions"] == [
        {"target": "8.8.8.8", "source_id": "cins-army", "reason": "allowlisted"}
    ]


def test_production_config_uses_cins_without_fetching_unapproved_feeds(tmp_path):
    config = load_config(Path(__file__).resolve().parents[1])

    def feeds(request):
        if str(request.url) == "https://cinsscore.com/list/ci-badguys.txt":
            return httpx.Response(200, content=b"8.8.8.8\n")
        if request.url.host == "feodotracker.abuse.ch":
            return httpx.Response(404)
        pytest.fail("production config fetched an unapproved source")

    with httpx.Client(transport=httpx.MockTransport(feeds)) as client:
        state = run_once(
            config, tmp_path / "state", tmp_path / "site", client, NOW, "production", bootstrap=True
        )
    assert (tmp_path / "site/lists/observe-ipv4.txt").read_bytes() == b"8.8.8.8\n"
    assert {e.source_id for e in state.evidence} == {"cins-army"}


def test_partial_absence_after_all_evidence_expires_allows_reappearance(tmp_path):
    run_feed(tmp_path, NOW, "first", b"8.8.8.8\n1.1.1.1\n")
    absent, output = run_feed(tmp_path, NOW + timedelta(days=8), "absent", b"1.1.1.1\n")
    assert absent.evidence == ()
    assert absent.sources["cins-army"].status == "stale"
    assert not absent.presence["cins-army"]["8.8.8.8"].present
    assert absent.presence["cins-army"]["1.1.1.1"].present
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b""
    returned, output = run_feed(
        tmp_path, NOW + timedelta(days=9), "returned", b"8.8.8.8\n1.1.1.1\n"
    )
    assert [e.target for e in returned.evidence] == ["8.8.8.8"]
    assert returned.evidence[0].expires_at == NOW + timedelta(days=16)
    assert (output / "lists/observe-ipv4.txt").read_bytes() == b"8.8.8.8\n"
