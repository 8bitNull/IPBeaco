"""Temporal evidence boundaries and recovery through the public advance API."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from ipbeaco.models import Config, InputRecord, Outcome, RunRecord, Settings, SourceError, State
from ipbeaco.temporal import advance
from tests.factories import NOW, snapshot, source


def run(previous=None, spec=None, snap=None, *, at=NOW, error=None, settings=None):
    spec = spec or source()
    outcome = Outcome(spec.id, at, snap, error)
    return advance(
        previous or State(), Config((spec,), settings or Settings(), ()), (outcome,), at, "run"
    )


def unknown_snapshot(*targets, **changes):
    snap = snapshot(*targets, generated_at=None, **changes)
    return replace(snap, records=tuple(replace(r, observed_at=None) for r in snap.records))


def test_unknown_time_does_not_renew_on_download():
    spec = source(time_mode="unknown", max_tier="observe")
    first = run(spec=spec, snap=unknown_snapshot("8.8.8.8"))
    assert len(first.evidence) == 1
    later = NOW + timedelta(days=8)
    second = run(first, spec, unknown_snapshot("8.8.8.8", fetched_at=later), at=later)
    assert second.evidence == ()
    assert second.presence[spec.id]["8.8.8.8"].first_seen_at == NOW


def test_repeated_old_observation_does_not_renew():
    first = run(snap=snapshot("8.8.8.8"))
    assert len(first.evidence) == 1
    later = NOW + timedelta(days=8)
    result = run(first, snap=snapshot("8.8.8.8", fetched_at=later), at=later)
    assert result.evidence == ()
    assert result.sources["test-web"].status == "stale"


@pytest.mark.parametrize("hours,count", [(71, 1), (72, 1), (167, 1), (168, 0)])
def test_observed_expiry_boundary_preserves_observation(hours, count):
    first = run(snap=snapshot("8.8.8.8"))
    later = NOW + timedelta(hours=hours)
    result = advance(first, Config((source(),), Settings(), ()), (), later, "later")
    assert len(result.evidence) == count
    if count:
        assert result.evidence[0].block_until == NOW + timedelta(hours=72)
        assert result.evidence[0].observe_until == NOW + timedelta(days=7)


@pytest.mark.parametrize("purpose,target", [("network", "8.8.8.0/24"), ("c2", "8.8.8.8")])
@pytest.mark.parametrize("hours,count", [(47, 1), (48, 0)])
def test_snapshot_expiry_boundary(purpose, target, hours, count):
    spec = source(purpose=purpose, time_mode="snapshot")
    first = run(spec=spec, snap=snapshot(target))
    assert first.presence[spec.id][target].present
    later = NOW + timedelta(hours=hours)
    result = run(first, spec, snapshot(target, fetched_at=later), at=later)
    assert len(result.evidence) == count
    assert result.sources[spec.id].valid_until == NOW + timedelta(hours=48)


@pytest.mark.parametrize("field", ["generated_at", "observed_at"])
def test_future_301_seconds_rejects_whole_snapshot(field):
    future = NOW + timedelta(seconds=301)
    snap = snapshot("8.8.8.8")
    if field == "observed_at":
        snap = replace(snap, records=(replace(snap.records[0], observed_at=future),))
    else:
        snap = replace(snap, generated_at=future)
    result = run(snap=snap)
    assert result.evidence == ()
    assert result.sources["test-web"].status == "error"
    assert result.sources["test-web"].last_success_at is None


def test_future_300_seconds_is_accepted():
    result = run(snap=snapshot("8.8.8.8", generated_at=NOW + timedelta(seconds=300)))
    assert len(result.evidence) == 1


def test_rolling_window_deducted_and_disappearance_replaces():
    spec = source(time_mode="rolling", window_hours=48)
    first = run(spec=spec, snap=snapshot("8.8.8.8"))
    assert first.evidence[0].block_until == NOW + timedelta(hours=24)
    assert first.evidence[0].observe_until == NOW + timedelta(hours=120)
    later = NOW + timedelta(hours=24)
    second = run(first, spec, snapshot("1.1.1.1", generated_at=later), at=later)
    assert [e.target for e in second.evidence] == ["1.1.1.1"]
    assert not second.presence[spec.id]["8.8.8.8"].present


def test_newer_observed_record_wins_same_source_and_first_seen_is_stable():
    first = run(snap=snapshot("8.8.8.8"))
    later = NOW + timedelta(hours=2)
    records = (
        InputRecord("8.8.8.8", "web_attack", later),
        InputRecord("8.8.8.8", "web_attack", NOW),
    )
    second = run(first, snap=snapshot(generated_at=later, records=records), at=later)
    third = run(second, snap=snapshot("8.8.8.8", generated_at=later), at=later)
    assert len(third.evidence) == 1
    assert third.evidence[0].observed_at == later
    assert third.evidence[0].first_seen_at == NOW


@pytest.mark.parametrize("intervening", ["empty", "failure", "stale"])
def test_unknown_reappearance_only_resets_after_valid_absence(intervening):
    spec = source(time_mode="unknown", max_tier="observe")
    first = run(spec=spec, snap=unknown_snapshot("8.8.8.8"))
    middle_time = NOW + timedelta(days=2)
    if intervening == "failure":
        middle = run(first, spec, at=middle_time, error="download_failed")
    elif intervening == "stale":
        middle = run(first, spec, snapshot(generated_at=NOW - timedelta(days=8)), at=middle_time)
    else:
        middle = run(first, spec, unknown_snapshot(), at=middle_time)
    later = NOW + timedelta(days=8)
    result = run(middle, spec, unknown_snapshot("8.8.8.8"), at=later)
    if intervening == "empty":
        assert result.evidence[0].first_seen_at == later
    else:
        assert result.evidence == ()
        assert result.presence[spec.id]["8.8.8.8"].first_seen_at == NOW


def test_generated_at_rollback_does_not_restore_deleted_target():
    spec = source(purpose="c2", time_mode="snapshot")
    first = run(spec=spec, snap=snapshot("8.8.8.8"))
    later = NOW + timedelta(hours=1)
    second = run(first, spec, snapshot(generated_at=later), at=later)
    result = run(second, spec, snapshot("8.8.8.8"), at=later)
    assert result.evidence == ()
    assert not result.presence[spec.id]["8.8.8.8"].present
    assert result.sources[spec.id].generated_at == later
    assert result.sources[spec.id].status == "error"


def test_upstream_shorter_expiry_takes_precedence():
    spec = source(purpose="network", time_mode="snapshot")
    snap = snapshot("8.8.8.0/24", upstream_expires_at=NOW + timedelta(hours=6))
    first = run(spec=spec, snap=snap)
    assert first.evidence[0].expires_at == NOW + timedelta(hours=6)
    result = run(first, spec, snap, at=NOW + timedelta(hours=6))
    assert result.evidence == ()
    assert result.sources[spec.id].status == "stale"


@pytest.mark.parametrize("mode", ["observed", "unknown", "snapshot", "rolling"])
def test_empty_without_upstream_time_has_24_hour_health_only(mode):
    spec = source(time_mode=mode, window_hours=48 if mode == "rolling" else None)
    first = run(spec=spec, snap=snapshot(generated_at=None))
    assert first.evidence == ()
    assert first.sources[spec.id].status == "empty"
    assert first.sources[spec.id].valid_until == NOW + timedelta(hours=24)
    later = NOW + timedelta(hours=24)
    result = advance(first, Config((spec,), Settings(), ()), (), later, "later")
    assert result.sources[spec.id].status == "stale"


def test_empty_snapshot_has_generated_time_expiry():
    spec = source(purpose="c2", time_mode="snapshot")
    result = run(spec=spec, snap=snapshot(generated_at=NOW - timedelta(hours=12)))
    assert result.sources[spec.id].status == "empty"
    assert result.sources[spec.id].valid_until == NOW + timedelta(hours=36)


def test_all_failed_sources_still_expire_and_do_not_change_evidence_dates():
    first = run(snap=snapshot("8.8.8.8"))
    mid = run(first, at=NOW + timedelta(days=1), error="offline")
    assert mid.evidence == first.evidence
    assert mid.sources["test-web"].last_success_at == NOW
    result = run(mid, at=NOW + timedelta(days=7), error="offline")
    assert result.evidence == ()
    assert result.presence["test-web"]["8.8.8.8"].present


@pytest.mark.parametrize("revocation", ["disabled", "unapproved", "removed"])
def test_revocation_scrubs_source_evidence_presence_and_notices(revocation):
    first = run(snap=snapshot("8.8.8.8", notices=("attribution",)))
    spec = source(enabled=revocation != "disabled", public_approved=revocation != "unapproved")
    cfg = Config(() if revocation == "removed" else (spec,), Settings(), ())
    result = advance(first, cfg, (), NOW, "revoke")
    assert result.evidence == ()
    assert "test-web" not in result.presence
    health = result.sources["test-web"]
    assert health.status == "disabled"
    assert health.notices == ()
    assert health.sha256 is None
    assert health.generated_at is None
    assert health.accepted_count == 0
    assert health.error


@pytest.mark.parametrize(
    "purpose,targets",
    [
        ("web", ("1.1.1.1", "8.8.8.8", "9.9.9.9")),
        ("network", ("1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24")),
        ("c2", ("1.1.1.1", "8.8.8.8", "9.9.9.9")),
    ],
)
def test_anomaly_uses_prior_present_targets_and_keeps_accepted_baseline(purpose, targets):
    spec = source(purpose=purpose, time_mode="observed" if purpose == "web" else "snapshot")
    settings = Settings(anomaly_new=2, anomaly_ratio=2)
    first = run(spec=spec, snap=snapshot(targets[0]), settings=settings)
    later = NOW + timedelta(hours=1)
    result = run(first, spec, snapshot(*targets, generated_at=later), at=later, settings=settings)
    assert result.evidence == first.evidence
    assert result.presence == first.presence
    assert result.sources[spec.id].error == "anomalous_growth"
    assert result.sources[spec.id].sha256 == first.sources[spec.id].sha256
    assert result.sources[spec.id].accepted_count == 1
    assert result.sources[spec.id].last_success_at == NOW


def test_zero_count_accepted_baseline_can_detect_anomaly():
    settings = Settings(anomaly_new=2)
    first = run(snap=snapshot(), settings=settings)
    result = run(first, snap=snapshot("8.8.8.8", "1.1.1.1"), settings=settings)
    assert result.sources["test-web"].error == "anomalous_growth"
    assert result.evidence == ()


def test_history_30_days_pruned_but_unknown_tombstone_survives():
    spec = source(time_mode="unknown", max_tier="observe")
    first = run(spec=spec, snap=unknown_snapshot("8.8.8.8"))
    later = NOW + timedelta(days=31)
    first = replace(
        first,
        history=(
            RunRecord("old", NOW),
            RunRecord("boundary", later - timedelta(days=30)),
            RunRecord("recent", later - timedelta(days=29)),
        ),
    )
    result = advance(first, Config((spec,), Settings(), ()), (), later, "new")
    assert [r.build_id for r in result.history] == ["boundary", "recent", "new"]
    assert result.evidence == ()
    assert result.presence[spec.id]["8.8.8.8"].first_seen_at == NOW


@pytest.mark.parametrize("target", ["oops", "8.8.8.8/32", "fe80::1%eth0"])
def test_malformed_target_rejects_whole_snapshot(target):
    result = run(snap=snapshot("1.1.1.1", target))
    assert result.evidence == ()
    assert result.sources["test-web"].status == "error"


def test_non_public_filtered_and_normalized_duplicates_collapsed():
    result = run(snap=snapshot(" 8.8.8.8 ", "8.8.8.8", "10.0.0.1"))
    assert [e.target for e in result.evidence] == ["8.8.8.8"]
    assert result.sources["test-web"].accepted_count == 1
    assert any("non_public_address" in n for n in result.sources["test-web"].notices)


def test_disallowed_address_family_rejects_whole_snapshot():
    result = run(spec=source(ip_versions=(4,)), snap=snapshot("8.8.8.8", "2606:4700:4700::1111"))
    assert result.evidence == ()
    assert result.sources["test-web"].status == "error"


@pytest.mark.parametrize("snap,error", [(None, None), (snapshot(), "failed")])
def test_outcome_requires_exactly_snapshot_or_error(snap, error):
    with pytest.raises(SourceError):
        run(snap=snap, error=error)


def test_duplicate_outcome_source_id_rejects_run():
    outcome = Outcome("test-web", NOW, snapshot())
    with pytest.raises(SourceError):
        advance(State(), Config((source(),), Settings(), ()), (outcome, outcome), NOW, "bad")


def test_advance_does_not_mutate_or_alias_previous():
    first = run(snap=snapshot("8.8.8.8"))
    saved = deepcopy(first)
    second = run(first, snap=snapshot(), at=NOW + timedelta(hours=1))
    assert first == saved
    assert second is not first
    second.presence["test-web"].clear()
    assert first == saved


def test_anomaly_rejection_still_expires_evidence_without_marking_absence():
    spec = source(purpose="c2", time_mode="snapshot")
    settings = Settings(anomaly_new=2, anomaly_ratio=2)
    first = run(spec=spec, snap=snapshot("8.8.8.8"), settings=settings)
    later = NOW + timedelta(hours=48)
    result = run(
        first,
        spec,
        snapshot("1.1.1.1", "9.9.9.9", "4.2.2.2", generated_at=later),
        at=later,
        settings=settings,
    )
    assert result.evidence == ()
    assert result.sources[spec.id].error == "anomalous_growth"
    assert result.presence[spec.id]["8.8.8.8"].present
    assert result.sources[spec.id].last_success_at == NOW


def test_anomaly_new_target_count_uses_presence_after_evidence_expiry():
    spec = source(purpose="c2", time_mode="snapshot")
    settings = Settings(anomaly_new=3, anomaly_ratio=2)
    first = run(spec=spec, snap=snapshot("8.8.8.8"), settings=settings)
    later = NOW + timedelta(hours=48)
    expired = run(first, spec, error="offline", at=later, settings=settings)
    result = run(
        expired,
        spec,
        snapshot("8.8.8.8", "1.1.1.1", "9.9.9.9", generated_at=later),
        at=later,
        settings=settings,
    )
    assert len(result.evidence) == 3
    assert result.sources[spec.id].status == "ok"


@pytest.mark.parametrize("kind", ["stale", "anomaly", "failure"])
def test_rejected_snapshots_cannot_confirm_unknown_target_absence(kind):
    spec = source(time_mode="unknown", max_tier="observe")
    settings = Settings(anomaly_new=2, anomaly_ratio=2)
    first = run(spec=spec, snap=unknown_snapshot("8.8.8.8"), settings=settings)
    later = NOW + timedelta(hours=1)
    if kind == "stale":
        snap, error = snapshot(generated_at=NOW - timedelta(days=8)), None
    elif kind == "anomaly":
        snap, error = unknown_snapshot("1.1.1.1", "9.9.9.9", "4.2.2.2"), None
    else:
        snap, error = None, "offline"
    result = run(first, spec, snap, at=later, error=error, settings=settings)
    assert result.evidence == first.evidence
    assert result.presence == first.presence
    assert result.sources[spec.id].accepted_count == 1


@pytest.mark.parametrize("mode", ["observed", "rolling", "snapshot"])
def test_required_reliable_time_cannot_be_replaced_by_fetch_time(mode):
    spec = source(
        time_mode=mode,
        window_hours=48 if mode == "rolling" else None,
        purpose="c2" if mode == "snapshot" else "web",
    )
    result = run(spec=spec, snap=unknown_snapshot("8.8.8.8"))
    assert result.evidence == ()
    assert result.sources[spec.id].status == "error"


def test_snapshot_source_mismatch_rejects_without_refreshing_accepted_baseline():
    first = run(snap=snapshot("8.8.8.8"))
    result = run(first, snap=snapshot(source_id="another-source"))
    assert result.evidence == first.evidence
    assert result.sources["test-web"].sha256 == first.sources["test-web"].sha256
    assert result.sources["test-web"].status == "error"


def staggered_evidence(mode):
    spec = source(time_mode=mode, max_tier="observe")
    later = NOW + timedelta(hours=1)
    if mode == "unknown":
        first = run(spec=spec, snap=unknown_snapshot("8.8.8.8"))
        snap = unknown_snapshot("8.8.8.8", "1.1.1.1")
    else:
        first = run(spec=spec, snap=snapshot("8.8.8.8"))
        snap = snapshot(
            generated_at=later,
            records=(
                InputRecord("8.8.8.8", "web_attack", NOW),
                InputRecord("1.1.1.1", "web_attack", later),
            ),
        )
    return spec, run(first, spec, snap, at=later)


@pytest.mark.parametrize("mode", ["observed", "unknown"])
def test_cleanup_recomputes_health_from_remaining_staggered_evidence(mode):
    spec, first = staggered_evidence(mode)
    cfg = Config((spec,), Settings(), ())
    later = NOW + timedelta(days=7)
    result = advance(first, cfg, (), later, "expire-first")
    assert [e.target for e in result.evidence] == ["1.1.1.1"]
    assert result.sources[spec.id].valid_until == later + timedelta(hours=1)
    assert result.sources[spec.id].status == "ok"
    assert result.sources[spec.id].error is None
    assert result.sources[spec.id].last_success_at == NOW + timedelta(hours=1)
    expired = advance(result, cfg, (), later + timedelta(hours=1), "expire-last")
    assert expired.evidence == ()
    assert expired.sources[spec.id].valid_until is None
    assert expired.sources[spec.id].status == "stale"


@pytest.mark.parametrize("mode", ["observed", "unknown"])
def test_cleanup_recomputed_deadline_keeps_explicit_source_error(mode):
    spec, first = staggered_evidence(mode)
    later = NOW + timedelta(days=7)
    result = run(first, spec, at=later, error="offline")
    assert [e.target for e in result.evidence] == ["1.1.1.1"]
    assert result.sources[spec.id].valid_until == later + timedelta(hours=1)
    assert result.sources[spec.id].status == "error"
    assert result.sources[spec.id].error == "offline"
    expired = advance(
        result, Config((spec,), Settings(), ()), (), later + timedelta(hours=1), "expire-last"
    )
    assert expired.evidence == ()
    assert expired.sources[spec.id].status == "error"
    assert expired.sources[spec.id].error == "offline"


@pytest.mark.parametrize("mode", ["observed", "unknown"])
def test_cleanup_preserves_empty_check_deadline_with_historical_evidence(mode):
    spec, first = staggered_evidence(mode)
    accepted = NOW + timedelta(hours=2)
    empty = run(first, spec, snapshot(generated_at=None), at=accepted)
    cfg = Config((spec,), Settings(), ())
    result = advance(empty, cfg, (), accepted + timedelta(hours=23), "still-empty")
    assert len(result.evidence) == 2
    assert result.sources[spec.id].valid_until == accepted + timedelta(hours=24)
    assert result.sources[spec.id].status == "empty"
    expired_check = advance(result, cfg, (), accepted + timedelta(hours=24), "check-expired")
    assert len(expired_check.evidence) == 2
    assert expired_check.sources[spec.id].valid_until == accepted + timedelta(hours=24)
    assert expired_check.sources[spec.id].status == "stale"
