"""Publication behavior through real selection, state transitions, and files."""

import hashlib
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from ipbeaco.export import validate_site, write_site
from ipbeaco.models import Config, Outcome, Settings, SourceState, State
from ipbeaco.policy import Entry, Selection, select
from ipbeaco.temporal import advance
from tests.factories import NOW, snapshot, source

KEYS = {
    f"{kind}-ipv{version}" for kind in ("block", "observe", "network", "c2") for version in (4, 6)
}


def publish(output, specs=(), targets=("8.8.8.8",), *, allowlist=(), notices=()):
    cfg = Config(tuple(specs), Settings(), allowlist)
    outcomes = tuple(
        Outcome(spec.id, NOW, snapshot(*targets, source_id=spec.id, notices=notices))
        for spec in specs
    )
    state = advance(State(), cfg, outcomes, NOW, "run-1")
    write_site(select(state, cfg, NOW), state, cfg, NOW, "run-1", output)
    return state, cfg


def read_json(output, filename):
    return json.loads((output / "lists" / filename).read_text())


def rewrite_json(output, filename, value):
    path = output / "lists" / filename
    path.write_text(json.dumps(value), encoding="utf-8")
    if filename == "metadata.json":
        status = read_json(output, "status.json")
        status["metadata"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        rewrite_json(output, "status.json", status)


def rewrite_list(output, key, raw):
    (output / "lists" / f"{key}.txt").write_bytes(raw)
    status = read_json(output, "status.json")
    status["lists"][key]["sha256"] = hashlib.sha256(raw).hexdigest()
    rewrite_json(output, "status.json", status)


def test_unavailable_lists_exist_but_are_not_healthy(tmp_path):
    publish(tmp_path)
    assert {p.stem for p in (tmp_path / "lists").glob("*.txt")} == KEYS
    status = read_json(tmp_path, "status.json")
    assert status["schema_version"] == 1
    assert status["build_id"] == "run-1"
    assert status["generated_at"] == "2026-10-04T00:00:00+00:00"
    assert set(status["lists"]) == KEYS
    for key, row in status["lists"].items():
        assert row == {
            "path": f"lists/{key}.txt",
            "status": "unavailable",
            "count": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "valid_until": None,
        }
        assert (tmp_path / row["path"]).read_bytes() == b""
    metadata = read_json(tmp_path, "metadata.json")
    assert set(metadata) == {
        "schema_version",
        "build_id",
        "generated_at",
        "entries",
        "exclusions",
        "source_licenses",
    }
    assert set(metadata["entries"]) == KEYS
    assert (
        status["metadata"]["sha256"]
        == hashlib.sha256((tmp_path / "lists/metadata.json").read_bytes()).hexdigest()
    )
    assert (tmp_path / ".nojekyll").is_file()
    validate_site(tmp_path, NOW)


@pytest.mark.parametrize("purpose,tier", [("web", "block"), ("web", "observe"), ("c2", "c2")])
def test_numeric_sort_pure_ip_and_evidence_deadlines(tmp_path, purpose, tier):
    spec = source(
        purpose=purpose,
        trusted_single=tier == "block",
        time_mode="snapshot" if purpose == "c2" else "observed",
    )
    publish(tmp_path, (spec,), ("8.8.8.8", "1.1.1.1", "2606:4700::1111", "2001:4860::8888"))
    assert (tmp_path / f"lists/{tier}-ipv4.txt").read_bytes() == b"1.1.1.1\n8.8.8.8\n"
    assert (
        tmp_path / f"lists/{tier}-ipv6.txt"
    ).read_bytes() == b"2001:4860::8888\n2606:4700::1111\n"
    row = read_json(tmp_path, "metadata.json")["entries"][f"{tier}-ipv4"][0]
    assert row["target"] == "1.1.1.1"
    assert row["source_ids"] == [spec.id]
    assert row["evidence"][0]["observed_at"] == (NOW.isoformat() if purpose == "web" else None)
    assert row["evidence"][0]["time_basis"] == spec.time_mode
    hours = {"block": 72, "observe": 168, "c2": 48}[tier]
    assert row["valid_until"] == (NOW + timedelta(hours=hours)).isoformat()
    validate_site(tmp_path, NOW)


def test_network_headers_keep_every_source_and_prevent_notice_injection(tmp_path):
    specs = tuple(
        source(id=sid, purpose="network", time_mode="snapshot", attribution="Named owner")
        for sid in ("z", "a")
    )
    notice = '<script>alert("bad")</script>\r\n9.9.9.9/32\r8.8.4.4/32'
    publish(tmp_path, specs, ("8.8.8.0/24", "1.1.1.0/24"), notices=(notice,))
    raw = (tmp_path / "lists/network-ipv4.txt").read_bytes()
    assert b"\r" not in raw
    lines = raw.decode().splitlines()
    assert [line for line in lines if not line.startswith("#")] == ["1.1.1.0/24", "8.8.8.0/24"]
    for sid in ("a", "z"):
        assert f"# source: {sid}" in lines
    assert "# generated_at: 2026-10-04T00:00:00+00:00" in lines
    assert "# Named owner" in lines
    assert "# 9.9.9.9/32" in lines
    assert "# 8.8.4.4/32" in lines
    html = (tmp_path / "index.html").read_text()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert 'href="lists/network-ipv4.txt"' in html
    assert all(label in html for label in ("Web", "网段", "C2", "更新时间"))
    validate_site(tmp_path, NOW)


def test_current_empty_network_snapshot_keeps_copyright_comments(tmp_path):
    spec = source(purpose="network", time_mode="snapshot", attribution="Copyright owner")
    publish(tmp_path, (spec,), (), notices=("Original copyright",))
    for version in (4, 6):
        raw = (tmp_path / f"lists/network-ipv{version}.txt").read_text()
        assert "# Original copyright\n" in raw
        assert "# Copyright owner\n" in raw
        row = read_json(tmp_path, "status.json")["lists"][f"network-ipv{version}"]
        assert row["status"] == "empty"
        assert row["count"] == 0
        assert row["valid_until"] == (NOW + timedelta(hours=48)).isoformat()
    validate_site(tmp_path, NOW)


def test_allowlisted_network_still_retains_current_snapshot_attribution(tmp_path):
    spec = source(purpose="network", time_mode="snapshot")
    publish(tmp_path, (spec,), ("8.8.8.0/24",), allowlist=("8.8.8.8",), notices=("Copyright",))
    assert "# Copyright\n" in (tmp_path / "lists/network-ipv4.txt").read_text()
    metadata = read_json(tmp_path, "metadata.json")
    assert metadata["exclusions"] == [
        {"target": "8.8.8.0/24", "source_id": spec.id, "reason": "allowlisted"}
    ]
    assert read_json(tmp_path, "status.json")["lists"]["network-ipv4"]["status"] == "empty"
    validate_site(tmp_path, NOW)


def test_ipv4_only_capability_does_not_claim_ipv6_health(tmp_path):
    publish(tmp_path, (source(ip_versions=(4,), trusted_single=True),))
    rows = read_json(tmp_path, "status.json")["lists"]
    assert rows["block-ipv4"]["status"] == "ok"
    assert rows["block-ipv6"]["status"] == "unavailable"
    assert rows["observe-ipv4"]["status"] == "empty"


def test_ipv6_absence_in_healthy_dual_stack_source_is_empty(tmp_path):
    publish(tmp_path, (source(trusted_single=True),))
    rows = read_json(tmp_path, "status.json")["lists"]
    assert rows["block-ipv6"]["status"] == "empty"
    assert rows["block-ipv6"]["valid_until"] == (NOW + timedelta(days=7)).isoformat()
    assert (tmp_path / "lists/block-ipv6.txt").read_bytes() == b""
    validate_site(tmp_path, NOW)


@pytest.mark.parametrize(
    "health,has_entries,want",
    [
        ("ok", True, "ok"),
        ("error", True, "degraded"),
        ("stale", True, "degraded"),
        ("error", False, "degraded"),
        ("stale", False, "stale"),
        ("unavailable", False, "degraded"),
        ("empty", False, "empty"),
    ],
)
def test_list_status_distinguishes_stale_error_and_empty(tmp_path, health, has_entries, want):
    spec = source(trusted_single=True)
    cfg = Config((spec,), Settings(), ())
    state = advance(State(), cfg, (Outcome(spec.id, NOW, snapshot("8.8.8.8")),), NOW, "initial")
    state = replace(
        state,
        evidence=state.evidence if has_entries else (),
        sources={spec.id: replace(state.sources[spec.id], status=health)},
    )
    write_site(select(state, cfg, NOW), state, cfg, NOW, "run-1", tmp_path)
    row = read_json(tmp_path, "status.json")["lists"]["block-ipv4"]
    assert row["status"] == want
    if want in ("stale", "degraded") and not has_entries:
        assert row["valid_until"] is None
    validate_site(tmp_path, NOW)


def test_mixed_healthy_and_failed_sources_degrade_without_extending_records(tmp_path):
    specs = (source(id="a", trusted_single=True), source(id="b"))
    state, cfg = publish(tmp_path, specs)
    later = NOW + timedelta(hours=1)
    state = advance(state, cfg, (Outcome("b", later, error="failed"),), later, "retry")
    write_site(select(state, cfg, later), state, cfg, later, "run-2", tmp_path / "retry")
    row = read_json(tmp_path / "retry", "status.json")["lists"]["block-ipv4"]
    assert row["status"] == "degraded"
    assert row["valid_until"] == (NOW + timedelta(hours=72)).isoformat()


def test_new_fetched_at_cannot_renew_snapshot_expiry(tmp_path):
    spec = source(purpose="c2", time_mode="snapshot")
    state, cfg = publish(tmp_path, (spec,))
    later = NOW + timedelta(hours=1)
    state = advance(
        state,
        cfg,
        (Outcome(spec.id, later, snapshot("8.8.8.8", fetched_at=later)),),
        later,
        "retry",
    )
    write_site(select(state, cfg, later), state, cfg, later, "retry", tmp_path / "retry")
    assert (
        read_json(tmp_path / "retry", "status.json")["lists"]["c2-ipv4"]["valid_until"]
        == (NOW + timedelta(hours=48)).isoformat()
    )


def test_export_reevaluates_expired_source_health(tmp_path):
    state, cfg = publish(
        tmp_path, (source(purpose="network", time_mode="snapshot"),), ("8.8.8.0/24",)
    )
    later = NOW + timedelta(hours=48)
    write_site(select(state, cfg, later), state, cfg, later, "late", tmp_path / "late")
    for version in (4, 6):
        row = read_json(tmp_path / "late", "status.json")["lists"][f"network-ipv{version}"]
        assert row["status"] == "stale"
        assert row["valid_until"] is None
        assert (tmp_path / f"late/lists/network-ipv{version}.txt").read_bytes() == b""
    validate_site(tmp_path / "late", later)


@pytest.mark.parametrize("revocation", ["disabled", "unapproved", "removed"])
def test_unadmitted_state_never_leaks_raw_evidence_or_notices(tmp_path, revocation):
    spec = source(id="private-source", purpose="network", time_mode="snapshot")
    state, cfg = publish(tmp_path, (spec,), ("8.8.8.0/24",), notices=("PRIVATE NOTICE",))
    public = source(id="public", trusted_single=True)
    changed = replace(
        spec, enabled=revocation != "disabled", public_approved=revocation != "unapproved"
    )
    cfg = replace(cfg, sources=(public,) + (() if revocation == "removed" else (changed,)))
    write_site(select(state, cfg, NOW), state, cfg, NOW, "safe", tmp_path / "safe")
    metadata = (tmp_path / "safe/lists/metadata.json").read_text()
    assert "private-source" not in metadata
    assert "PRIVATE NOTICE" not in metadata
    assert "8.8.8.0/24" not in metadata
    assert "PRIVATE NOTICE" not in (tmp_path / "safe/lists/status.json").read_text()
    assert "PRIVATE NOTICE" not in (tmp_path / "safe/index.html").read_text()
    validate_site(tmp_path / "safe", NOW)


def test_stale_selection_with_unadmitted_entry_is_rejected(tmp_path):
    state, cfg = publish(tmp_path, (source(trusted_single=True),))
    selection = select(state, cfg, NOW)
    revoked = replace(cfg, sources=(replace(cfg.sources[0], public_approved=False),))
    with pytest.raises(ValueError):
        write_site(selection, state, revoked, NOW, "unsafe", tmp_path / "unsafe")


def test_missing_source_snapshot_has_no_network_comments(tmp_path):
    cfg = Config(
        (source(purpose="network", time_mode="snapshot", attribution="Copyright"),), Settings(), ()
    )
    write_site(select(State(), cfg, NOW), State(), cfg, NOW, "run", tmp_path)
    assert (tmp_path / "lists/network-ipv4.txt").read_bytes() == b""


def test_tampering_one_byte_fails_checksum(tmp_path):
    publish(tmp_path, (source(trusted_single=True),))
    (tmp_path / "lists/block-ipv4.txt").write_bytes(b"9.8.8.8\n")
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


@pytest.mark.parametrize(
    "raw",
    [
        b"8.8.8.8\r\n",
        b"8.8.8.8",
        b"10.0.0.1\n",
        b"2606:4700::1111\n",
        b"8.8.8.0/24\n",
        b"8.8.8.8\n8.8.8.8\n",
        b"# injected\n8.8.8.8\n",
    ],
)
def test_semantic_list_tampering_rejected_even_with_updated_hash(tmp_path, raw):
    publish(tmp_path, (source(trusted_single=True),))
    rewrite_list(tmp_path, "block-ipv4", raw)
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


@pytest.mark.parametrize("raw", [b"8.8.8.1/24\n", b"8.8.8.8\n", b"0.0.0.0/0\n"])
def test_invalid_cidrs_cannot_bypass_validator(tmp_path, raw):
    publish(tmp_path, (source(purpose="network", time_mode="snapshot"),), ("8.8.8.0/24",))
    rewrite_list(tmp_path, "network-ipv4", raw)
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


@pytest.mark.parametrize(
    "change",
    [
        "count",
        "build_id",
        "expiry",
        "unknown_source",
        "unapproved",
        "path",
        "missing_list",
        "metadata_hash",
        "missing_file",
    ],
)
def test_manifest_and_metadata_inconsistency_rejected(tmp_path, change):
    publish(tmp_path, (source(trusted_single=True),))
    status = read_json(tmp_path, "status.json")
    metadata = read_json(tmp_path, "metadata.json")
    if change == "count":
        status["lists"]["block-ipv4"]["count"] = 2
    elif change == "path":
        status["lists"]["block-ipv4"]["path"] = "../block-ipv4.txt"
    elif change == "missing_list":
        del status["lists"]["c2-ipv6"]
    elif change == "metadata_hash":
        status["metadata"]["sha256"] = "0" * 64
    elif change == "missing_file":
        (tmp_path / "lists/c2-ipv6.txt").unlink()
    elif change == "build_id":
        metadata["build_id"] = "other-run"
    elif change == "expiry":
        metadata["entries"]["block-ipv4"][0]["valid_until"] = NOW.isoformat()
    elif change == "unknown_source":
        metadata["entries"]["block-ipv4"][0]["evidence"][0]["source_id"] = "unapproved"
    elif change == "unapproved":
        metadata["source_licenses"]["test-web"]["public_approved"] = False
    rewrite_json(tmp_path, "status.json", status)
    rewrite_json(tmp_path, "metadata.json", metadata)
    if change == "metadata_hash":
        status["metadata"]["sha256"] = "0" * 64
        rewrite_json(tmp_path, "status.json", status)
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


def test_web_tiers_cannot_share_an_ip(tmp_path):
    publish(tmp_path, (source(trusted_single=True),))
    metadata = read_json(tmp_path, "metadata.json")
    metadata["entries"]["observe-ipv4"] = metadata["entries"]["block-ipv4"]
    rewrite_json(tmp_path, "metadata.json", metadata)
    rewrite_list(tmp_path, "observe-ipv4", b"8.8.8.8\n")
    status = read_json(tmp_path, "status.json")
    status["lists"]["observe-ipv4"].update(count=1, status="ok")
    rewrite_json(tmp_path, "status.json", status)
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


def test_expired_build_rejected_at_consumer_time(tmp_path):
    publish(tmp_path, (source(trusted_single=True),))
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW + timedelta(hours=72))


def test_selection_must_be_current_and_complete(tmp_path):
    cfg = Config((), Settings(), ())
    with pytest.raises(ValueError):
        write_site(Selection({}, ()), State(), cfg, NOW, "bad", tmp_path)
    spec = source(trusted_single=True)
    cfg = replace(cfg, sources=(spec,))
    lists = dict(select(State(), cfg, NOW).lists)
    lists["block-ipv4"] = (Entry("8.8.8.8", NOW, (spec.id,), "trusted_single"),)
    with pytest.raises(ValueError):
        write_site(Selection(lists, ()), State(), cfg, NOW, "bad", tmp_path)


def test_illegal_source_status_is_rejected(tmp_path):
    cfg = Config((source(),), Settings(), ())
    state = State(sources={"test-web": SourceState(status="degraded")})
    with pytest.raises(ValueError):
        write_site(select(state, cfg, NOW), state, cfg, NOW, "bad", tmp_path)


def test_web_attack_can_block_with_unknown_configured_category(tmp_path):
    publish(tmp_path, (source(trusted_single=True, category="unknown"),))
    assert (tmp_path / "lists/block-ipv4.txt").read_bytes() == b"8.8.8.8\n"
    validate_site(tmp_path, NOW)


def test_current_last_good_network_snapshot_keeps_empty_file_attribution(tmp_path):
    spec = source(purpose="network", time_mode="snapshot")
    state, cfg = publish(
        tmp_path, (spec,), ("8.8.8.0/24",), allowlist=("8.8.8.8",), notices=("Copyright",)
    )
    later = NOW + timedelta(hours=1)
    state = advance(
        state, cfg, (Outcome(spec.id, later, error="upstream_failed"),), later, "failed"
    )
    write_site(select(state, cfg, later), state, cfg, later, "failed", tmp_path / "failed")
    assert "# Copyright\n" in (tmp_path / "failed/lists/network-ipv4.txt").read_text()
    row = read_json(tmp_path / "failed", "status.json")["lists"]["network-ipv4"]
    assert row["status"] == "degraded"
    assert row["valid_until"] is None
    validate_site(tmp_path / "failed", later)


@pytest.mark.parametrize("change", ["category", "reason", "trust", "expired_evidence"])
def test_invalid_block_evidence_cannot_be_published_with_updated_hash(tmp_path, change):
    publish(tmp_path, (source(trusted_single=True),))
    metadata = read_json(tmp_path, "metadata.json")
    entry = metadata["entries"]["block-ipv4"][0]
    if change == "category":
        entry["evidence"][0]["category"] = "scan"
    elif change == "reason":
        entry["reason"] = "snapshot"
    elif change == "trust":
        metadata["source_licenses"]["test-web"]["trusted_single"] = False
    elif change == "expired_evidence":
        entry["evidence"][0]["expires_at"] = NOW.isoformat()
    rewrite_json(tmp_path, "metadata.json", metadata)
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


def test_entry_order_in_selection_does_not_change_canonical_output(tmp_path):
    state, cfg = publish(tmp_path, (source(trusted_single=True),), ("8.8.8.8", "1.1.1.1"))
    selection = select(state, cfg, NOW)
    lists = dict(selection.lists)
    lists["block-ipv4"] = tuple(reversed(lists["block-ipv4"]))
    write_site(
        Selection(lists, selection.exclusions), state, cfg, NOW, "sorted", tmp_path / "sorted"
    )
    assert (tmp_path / "sorted/lists/block-ipv4.txt").read_bytes() == b"1.1.1.1\n8.8.8.8\n"
    validate_site(tmp_path / "sorted", NOW)


@pytest.mark.parametrize("separator", [b"\v", b"\xc2\x85", b"\xe2\x80\xa8"])
def test_only_lf_can_separate_addresses(tmp_path, separator):
    publish(tmp_path, (source(trusted_single=True),), ("1.1.1.1", "8.8.8.8"))
    rewrite_list(tmp_path, "block-ipv4", b"1.1.1.1" + separator + b"8.8.8.8\n")
    with pytest.raises(ValueError):
        validate_site(tmp_path, NOW)


def test_empty_network_deadline_is_earliest_healthy_snapshot_deadline(tmp_path):
    specs = tuple(source(id=sid, purpose="network", time_mode="snapshot") for sid in ("a", "b"))
    cfg = Config(specs, Settings(), ())
    state = advance(
        State(),
        cfg,
        (
            Outcome(
                "a", NOW, snapshot(source_id="a", upstream_expires_at=NOW + timedelta(hours=12))
            ),
            Outcome("b", NOW, snapshot(source_id="b")),
        ),
        NOW,
        "run",
    )
    write_site(select(state, cfg, NOW), state, cfg, NOW, "run", tmp_path)
    assert (
        read_json(tmp_path, "status.json")["lists"]["network-ipv4"]["valid_until"]
        == (NOW + timedelta(hours=12)).isoformat()
    )
    validate_site(tmp_path, NOW)


@pytest.mark.parametrize(
    "changes",
    [
        {"max_tier": "observe"},
        {"independent": False},
        {"time_mode": "unknown", "max_tier": "observe"},
    ],
)
def test_sources_without_block_capability_leave_block_unavailable(tmp_path, changes):
    publish(tmp_path, (source(**changes),), ())
    rows = read_json(tmp_path, "status.json")["lists"]
    assert rows["block-ipv4"]["status"] == "unavailable"
    assert rows["observe-ipv4"]["status"] == "empty"
    validate_site(tmp_path, NOW)


def test_different_family_source_failures_affect_only_capable_lists(tmp_path):
    specs = (
        source(id="v4", ip_versions=(4,), trusted_single=True),
        source(id="v6", ip_versions=(6,), trusted_single=True),
    )
    cfg = Config(specs, Settings(), ())
    state = advance(
        State(),
        cfg,
        (
            Outcome("v4", NOW, snapshot("8.8.8.8", source_id="v4")),
            Outcome("v6", NOW, error="failed"),
        ),
        NOW,
        "run",
    )
    write_site(select(state, cfg, NOW), state, cfg, NOW, "run", tmp_path)
    rows = read_json(tmp_path, "status.json")["lists"]
    assert rows["block-ipv4"]["status"] == "ok"
    assert rows["block-ipv6"]["status"] == "degraded"
    validate_site(tmp_path, NOW)
