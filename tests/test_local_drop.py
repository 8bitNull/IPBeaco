"""Offline local DROP behavior: rate limits, complete batches, and validation."""

import hashlib
import json
import shutil
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from ipbeaco import cli
from ipbeaco.config import load_config_dir
from ipbeaco.pipeline import collect
from tests.factories import NOW

ROOT = Path(__file__).resolve().parents[1]
IDS = ("spamhaus-drop-v4", "spamhaus-drop-v6")
V4 = ["8.8.8.0/24", "1.1.1.0/24", "8.8.8.0/24", "10.0.0.0/8", "9.9.9.0/24"]
V6 = ["2606:4700::/32", "2001:4860::/32"]


def payload(targets, timestamp=NOW, **metadata):
    entries = "".join(json.dumps({"cidr": t, "sblid": "SBL123"}) + "\n" for t in targets)
    row = {
        "type": "metadata",
        "timestamp": int(timestamp.timestamp()),
        "records": len(targets),
        "size": len(entries.encode()),
        "copyright": "Copyright Spamhaus\n8.8.4.0/24",
        "terms": "Retain copyright and date",
        **metadata,
    }
    return (entries + json.dumps(row) + "\n").encode()


@pytest.fixture
def local(tmp_path, monkeypatch):
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    (config / "allowlist.txt").write_text("9.9.9.9\n")
    responses = {4: payload(V4), 6: payload(V6)}
    requests = []
    state = tmp_path / "drop-local-state"

    def response(request):
        family = 4 if request.url.path.endswith("drop_v4.json") else 6
        # This assertion verifies the durable production boundary, not a mock call.
        recorded = json.loads((state / "local-state.json").read_text())["data"]
        assert recorded["sources"][IDS[family == 6]]["last_attempt_at"]
        requests.append(str(request.url))
        result = responses[family]
        if isinstance(result, Exception):
            raise result
        return result if isinstance(result, httpx.Response) else httpx.Response(200, content=result)

    real_client = httpx.Client
    monkeypatch.setattr(cli, "utc_now", lambda: NOW)
    monkeypatch.setattr(
        cli, "http_client", lambda: real_client(transport=httpx.MockTransport(response))
    )
    return config, state, responses, requests


def args(tmp_path, local, name="first"):
    config, state, _, _ = local
    return [
        "drop-local",
        "--config",
        str(config),
        "--state",
        str(state),
        "--out",
        str(tmp_path / name),
        "--build-id",
        name,
    ]


def read_state(local):
    return json.loads((local[1] / "local-state.json").read_text())["data"]


def test_complete_local_batch_preserves_cidrs_notices_and_public_admission(tmp_path, local):
    original = {p.name: p.read_bytes() for p in local[0].iterdir()}
    assert cli.main(args(tmp_path, local)) == 0
    output = tmp_path / "first"
    assert {p.name for p in output.iterdir()} == {
        "network-ipv4.txt",
        "network-ipv6.txt",
        "status.json",
        "metadata.json",
    }
    v4 = (output / "network-ipv4.txt").read_text()
    assert [s for s in v4.splitlines() if not s.startswith("#")] == ["1.1.1.0/24", "8.8.8.0/24"]
    assert "# Copyright Spamhaus\n# 8.8.4.0/24" in v4
    assert "Retain copyright and date" in v4 and NOW.isoformat() in v4
    status = json.loads((output / "status.json").read_text())
    assert status["local_only"] is True
    assert set(status["lists"]) == {"network-ipv4", "network-ipv6"}
    assert status["lists"]["network-ipv4"]["count"] == 2
    assert status["lists"]["network-ipv4"]["status"] == "ok"
    meta = json.loads((output / "metadata.json").read_text())
    source = meta["sources"][IDS[0]]
    assert source["excluded_allowlist"] == ["9.9.9.0/24"]
    assert source["public_approved"] is False and source["enabled"] is False
    assert source["generated_at"] == NOW.isoformat()
    assert source["valid_until"] == "2026-10-06T00:00:00+00:00"
    assert any("non_public_address" in notice for notice in source["notices"])
    assert original == {p.name: p.read_bytes() for p in local[0].iterdir()}
    assert not (local[1] / "state.json").exists()
    assert cli.main(["validate-drop-local", "--dir", str(output)]) == 0
    assert cli.main(["validate", "--site", str(output)]) == 1


def test_public_collect_still_excludes_disabled_drop(local):
    requested = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: requested.append(str(request.url)) or httpx.Response(404)
        )
    ) as client:
        config = load_config_dir(local[0])
        outcomes = collect(config, NOW, client)
    assert not set(IDS) & {outcome.source_id for outcome in outcomes}
    assert not any("spamhaus" in url for url in requested)


@pytest.mark.parametrize("failure", ["http", "timeout", "format", "wrong_family"])
def test_failed_family_never_publishes_and_attempts_cannot_retry(tmp_path, local, failure):
    local[2][6] = {
        "http": httpx.Response(503),
        "timeout": httpx.ReadTimeout("offline failure"),
        "format": b"bad JSON",
        "wrong_family": payload(["8.8.8.0/24"]),
    }[failure]
    assert cli.main(args(tmp_path, local)) == 1
    assert not (tmp_path / "first").exists()
    assert not list(tmp_path.glob(".first.*"))
    state = read_state(local)
    assert all(state["sources"][sid]["last_attempt_at"] == NOW.isoformat() for sid in IDS)
    assert state["sources"][IDS[1]]["error"]
    assert len(local[3]) == 2  # A 503 or timeout must not cause immediate download retries.
    local[2][6] = payload(V6)
    assert cli.main(args(tmp_path, local, "retry")) == 1
    assert len(local[3]) == 2


def test_cooldown_boundary_records_attempts_and_preserves_success_on_failure(
    tmp_path, local, monkeypatch
):
    assert cli.main(args(tmp_path, local)) == 0
    before = {p.name: p.read_bytes() for p in (tmp_path / "first").iterdir()}
    success = read_state(local)["sources"][IDS[0]]["accepted"]
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(hours=24, seconds=-1))
    assert cli.main(args(tmp_path, local, "early")) == 1
    assert len(local[3]) == 2
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(hours=24))
    local[2][4] = httpx.Response(503)
    assert cli.main(args(tmp_path, local, "failure")) == 1
    assert len(local[3]) == 3
    assert read_state(local)["sources"][IDS[0]]["accepted"] == success
    assert before == {p.name: p.read_bytes() for p in (tmp_path / "first").iterdir()}
    assert cli.main(args(tmp_path, local, "retry")) == 1
    assert len(local[3]) == 3


@pytest.mark.parametrize("offset", [timedelta(minutes=5, seconds=1), timedelta(hours=-48)])
def test_stale_or_future_body_timestamp_fails_before_publication(tmp_path, local, offset):
    local[2][4] = payload(V4, NOW + offset)
    assert cli.main(args(tmp_path, local)) == 1
    assert not (tmp_path / "first").exists()
    assert read_state(local)["sources"][IDS[0]]["error"]


@pytest.mark.parametrize("case", ["inconsistent", "regressed", "growth"])
def test_timestamp_and_growth_checks_use_last_accepted_baseline(tmp_path, local, monkeypatch, case):
    policy = local[0] / "policy.toml"
    policy.write_text(policy.read_text().replace("anomaly_new = 1000", "anomaly_new = 1"))
    local[2][4] = payload(["1.1.1.0/24"])
    assert cli.main(args(tmp_path, local)) == 0
    accepted = read_state(local)["sources"][IDS[0]]["accepted"]
    later = NOW + timedelta(hours=24)
    monkeypatch.setattr(cli, "utc_now", lambda: later)
    local[2][4] = {
        "inconsistent": payload(["8.8.8.0/24"]),
        "regressed": payload(["1.1.1.0/24"], NOW - timedelta(seconds=1)),
        "growth": payload(["1.1.1.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24"], later),
    }[case]
    assert cli.main(args(tmp_path, local, "second")) == 1
    assert read_state(local)["sources"][IDS[0]]["accepted"] == accepted
    assert not (tmp_path / "second").exists()


def test_new_timestamp_after_cooldown_builds_new_batch(tmp_path, local, monkeypatch):
    assert cli.main(args(tmp_path, local)) == 0
    later = NOW + timedelta(days=1)
    monkeypatch.setattr(cli, "utc_now", lambda: later)
    local[2].update({4: payload(V4, later), 6: payload(V6, later)})
    assert cli.main(args(tmp_path, local, "second")) == 0
    assert read_state(local)["sources"][IDS[0]]["accepted"]["generated_at"] == later.isoformat()
    assert cli.main(["validate-drop-local", "--dir", str(tmp_path / "second")]) == 0


def test_empty_batch_is_valid_and_expires_at_body_deadline(tmp_path, local, monkeypatch):
    local[2].update({4: payload([]), 6: payload([])})
    assert cli.main(args(tmp_path, local)) == 0
    status = json.loads((tmp_path / "first/status.json").read_text())
    assert all(row["status"] == "empty" and row["count"] == 0 for row in status["lists"].values())
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(hours=48))
    assert cli.main(["validate-drop-local", "--dir", str(tmp_path / "first")]) == 1


@pytest.mark.parametrize("collision", ["public", "config", "overlap", "existing_output"])
def test_path_collisions_do_not_mutate_existing_data_or_request(tmp_path, local, collision):
    if collision == "public":
        local[1].mkdir()
        (local[1] / "state.json").write_text("public state")
        (local[1] / "state.sha256").write_text("public checksum")
    if collision == "existing_output":
        (tmp_path / "first").mkdir()
        (tmp_path / "first/sentinel").write_text("old")
    command = args(tmp_path, local)
    if collision == "config":
        command[command.index("--state") + 1] = str(local[0])
    if collision == "overlap":
        command[command.index("--out") + 1] = str(local[1] / "child")
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert cli.main(command) == 1
    assert before == {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert not local[3]


@pytest.mark.parametrize("corruption", ["truncated", "checksum", "future", "missing"])
def test_local_state_corruption_fails_closed(tmp_path, local, monkeypatch, corruption):
    assert cli.main(args(tmp_path, local)) == 0
    path = local[1] / "local-state.json"
    envelope = json.loads(path.read_text())
    if corruption == "truncated":
        path.write_text("{")
    elif corruption == "missing":
        path.unlink()
    else:
        data = envelope["data"]
        data["sources"][IDS[0]]["last_attempt_at"] = (NOW + timedelta(days=3)).isoformat()
        if corruption == "future":
            # Match the canonical local-state encoding, then test semantic validation.
            raw = (json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
            envelope["sha256"] = hashlib.sha256(raw).hexdigest()
        path.write_text(json.dumps(envelope))
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(days=1))
    assert cli.main(args(tmp_path, local, "second")) == 1
    assert len(local[3]) == 2


def test_concurrent_run_cannot_request_or_mutate_state(tmp_path, local):
    import fcntl

    assert cli.main(args(tmp_path, local)) == 0
    before = (local[1] / "local-state.json").read_bytes()
    with (local[1] / "local.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert cli.main(args(tmp_path, local, "concurrent")) == 1
    assert before == (local[1] / "local-state.json").read_bytes()
    assert len(local[3]) == 2


@pytest.mark.parametrize("tamper", ["text", "metadata", "status", "family", "expiry", "protocol"])
def test_local_validator_rejects_tampering(tmp_path, local, tamper):
    assert cli.main(args(tmp_path, local)) == 0
    output = tmp_path / "first"
    if tamper == "text":
        (output / "network-ipv4.txt").write_text("8.8.4.0/24\n")
    elif tamper in {"metadata", "protocol"}:
        path = output / "metadata.json"
        meta = json.loads(path.read_text())
        if tamper == "metadata":
            meta["sources"][IDS[0]]["notices"] = []
        else:
            meta["local_only"] = False
        path.write_text(json.dumps(meta))
    else:
        path = output / "status.json"
        status = json.loads(path.read_text())
        row = status["lists"]["network-ipv4"]
        if tamper == "status":
            row["count"] = 3
        elif tamper == "family":
            row["source_id"] = IDS[1]
        else:
            row["valid_until"] = "2030-01-01T00:00:00+00:00"
        path.write_text(json.dumps(status))
    assert cli.main(["validate-drop-local", "--dir", str(output)]) == 1


def test_validation_failure_cleans_stage_and_keeps_prior_success(tmp_path, local, monkeypatch):
    assert cli.main(args(tmp_path, local)) == 0
    from ipbeaco import local_drop

    accepted = read_state(local)["sources"][IDS[0]]["accepted"]
    later = NOW + timedelta(days=1)
    monkeypatch.setattr(cli, "utc_now", lambda: later)
    local[2].update({4: payload(V4, later), 6: payload(V6, later)})

    def fail(*_):
        raise ValueError("injected validation failure")

    monkeypatch.setattr(local_drop, "validate_local_drop", fail)
    assert cli.main(args(tmp_path, local, "second")) == 1
    assert not (tmp_path / "second").exists()
    assert not list(tmp_path.glob(".second.*"))
    assert read_state(local)["sources"][IDS[0]]["accepted"] == accepted


def test_identical_fresh_snapshot_can_repeat_without_renewing_expiry(tmp_path, local, monkeypatch):
    assert cli.main(args(tmp_path, local)) == 0
    original = read_state(local)["sources"][IDS[1]]["accepted"]["valid_until"]
    later = NOW + timedelta(hours=24)
    monkeypatch.setattr(cli, "utc_now", lambda: later)
    local[2][4] = payload(V4, later)
    assert cli.main(args(tmp_path, local, "second")) == 0
    metadata = json.loads((tmp_path / "second/metadata.json").read_text())
    assert metadata["sources"][IDS[1]]["valid_until"] == original
    assert metadata["sources"][IDS[0]]["valid_until"] == "2026-10-07T00:00:00+00:00"
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(hours=48))
    assert cli.main(["validate-drop-local", "--dir", str(tmp_path / "second")]) == 1
    assert cli.main(args(tmp_path, local, "expired")) == 1


def test_rename_failure_preserves_accepted_state_and_old_output(tmp_path, local, monkeypatch):
    assert cli.main(args(tmp_path, local)) == 0
    prior = read_state(local)["sources"][IDS[0]]["accepted"]
    before = {p.name: p.read_bytes() for p in (tmp_path / "first").iterdir()}
    later = NOW + timedelta(days=1)
    monkeypatch.setattr(cli, "utc_now", lambda: later)
    local[2].update({4: payload(V4, later), 6: payload(V6, later)})

    def fail(*_):
        raise OSError("injected rename failure")

    monkeypatch.setattr(Path, "rename", fail)
    assert cli.main(args(tmp_path, local, "second")) == 1
    assert read_state(local)["sources"][IDS[0]]["accepted"] == prior
    assert not (tmp_path / "second").exists()
    assert before == {p.name: p.read_bytes() for p in (tmp_path / "first").iterdir()}


def test_attempt_persistence_failure_prevents_network_request(tmp_path, local, monkeypatch):
    from ipbeaco import local_drop

    def fail(*_):
        raise OSError("injected disk error")

    monkeypatch.setattr(local_drop, "_save_state", fail)
    assert cli.main(args(tmp_path, local)) == 1
    assert not local[3]
    assert not (tmp_path / "first").exists()


def test_each_attempt_uses_request_time_and_validation_uses_completion_time(
    tmp_path, local, monkeypatch
):
    current = [NOW]
    original_factory = cli.http_client
    monkeypatch.setattr(cli, "utc_now", lambda: current[0])

    def advance(_):
        current[0] += timedelta(seconds=30)

    def client():
        result = original_factory()
        result.event_hooks["response"] = [advance]
        return result

    monkeypatch.setattr(cli, "http_client", client)
    assert cli.main(args(tmp_path, local)) == 0
    assert read_state(local)["sources"][IDS[1]]["last_attempt_at"] == "2026-10-04T00:00:30+00:00"
    status = json.loads((tmp_path / "first/status.json").read_text())
    assert status["generated_at"] == "2026-10-04T00:01:00+00:00"
    assert cli.main(["validate-drop-local", "--dir", str(tmp_path / "first")]) == 0


def test_expiration_during_staging_is_rejected_at_fresh_validation_time(
    tmp_path, local, monkeypatch
):
    from ipbeaco import local_drop

    current = [NOW]
    original_write = local_drop._atomic_write
    monkeypatch.setattr(cli, "utc_now", lambda: current[0])

    def write(path, raw):
        original_write(path, raw)
        if path.name == "status.json":
            current[0] = NOW + timedelta(hours=48)

    monkeypatch.setattr(local_drop, "_atomic_write", write)
    assert cli.main(args(tmp_path, local)) == 1
    assert not (tmp_path / "first").exists()
    assert not list(tmp_path.glob(".first.*"))
    assert all(row["accepted"] is None for row in read_state(local)["sources"].values())
