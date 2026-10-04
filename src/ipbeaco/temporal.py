"""Advance durable evidence without letting downloads extend its lifetime."""

from dataclasses import replace
from datetime import datetime, timedelta
from ipaddress import ip_network

from ipbeaco.addresses import normalize_target, sort_key
from ipbeaco.models import (
    Config,
    Evidence,
    InputRecord,
    Outcome,
    Presence,
    RunRecord,
    Settings,
    Snapshot,
    SourceError,
    SourceSpec,
    SourceState,
    State,
)


def _normalized_records(
    spec: SourceSpec, snap: Snapshot, settings: Settings, now: datetime
) -> tuple[dict[str, InputRecord], tuple[str, ...]]:
    future_limit = now + timedelta(seconds=settings.future_skew_seconds)
    if snap.generated_at is not None and snap.generated_at > future_limit:
        raise SourceError("future_timestamp")
    records: dict[str, InputRecord] = {}
    rejected = 0
    for record in snap.records:
        if record.observed_at is not None and record.observed_at > future_limit:
            raise SourceError("future_timestamp")
        if spec.time_mode == "observed" and record.observed_at is None:
            raise SourceError("missing_observed_at")
        # Check the declared family even for syntactically valid private targets.
        try:
            target = normalize_target(record.target, spec.purpose)
        except SourceError as exc:
            if not str(exc).startswith("non_public_address:"):
                raise
            if ip_network(record.target.strip(), strict=True).version not in spec.ip_versions:
                raise SourceError("unsupported_ip_version") from None
            rejected += 1
            continue
        if ip_network(target, strict=True).version not in spec.ip_versions:
            raise SourceError("unsupported_ip_version")
        current = records.get(target)
        if current is None or (
            record.observed_at is not None
            and (current.observed_at is None or record.observed_at > current.observed_at)
        ):
            records[target] = replace(record, target=target)
    notices = snap.notices
    if rejected:
        notices += (f"non_public_address: {rejected} records filtered",)
    return records, notices


def _deadline(
    spec: SourceSpec, snap: Snapshot, settings: Settings, now: datetime, *, empty: bool
) -> datetime | None:
    if snap.generated_at is None:
        if empty:
            return now + timedelta(hours=24)
        if spec.purpose != "web" or spec.time_mode in ("rolling", "snapshot"):
            raise SourceError("missing_generated_at")
        return None
    if spec.purpose != "web" or spec.time_mode == "snapshot":
        deadline = snap.generated_at + timedelta(hours=settings.snapshot_hours)
        if snap.upstream_expires_at is not None:
            deadline = min(deadline, snap.upstream_expires_at)
        return deadline
    if spec.time_mode == "rolling":
        if spec.window_hours is None:
            raise SourceError("missing_window_hours")
        return snap.generated_at + timedelta(hours=settings.observe_hours - spec.window_hours)
    # Generated empty snapshots must also be fresh before they establish absence.
    if empty:
        return snap.generated_at + timedelta(hours=24)
    return None


def _evidence(
    spec: SourceSpec,
    record: InputRecord,
    snap: Snapshot,
    settings: Settings,
    first_seen: datetime,
    snapshot_until: datetime | None,
) -> Evidence:
    block_until = None
    observe_until = None
    if spec.purpose != "web" or spec.time_mode == "snapshot":
        assert snapshot_until is not None
        expires_at = snapshot_until
    elif spec.time_mode == "observed":
        assert record.observed_at is not None
        if spec.max_tier == "block":
            block_until = record.observed_at + timedelta(hours=settings.block_hours)
        observe_until = record.observed_at + timedelta(hours=settings.observe_hours)
        expires_at = observe_until
    elif spec.time_mode == "rolling":
        assert snap.generated_at is not None and spec.window_hours is not None
        if spec.max_tier == "block":
            block_until = snap.generated_at + timedelta(
                hours=settings.block_hours - spec.window_hours
            )
        observe_until = snap.generated_at + timedelta(
            hours=settings.observe_hours - spec.window_hours
        )
        expires_at = observe_until
    elif spec.time_mode == "unknown":
        observe_until = first_seen + timedelta(hours=settings.observe_hours)
        expires_at = observe_until
    else:
        raise SourceError("invalid_time_mode")
    return Evidence(
        source_id=spec.id,
        target=record.target,
        category=record.category,
        first_seen_at=first_seen,
        observed_at=record.observed_at if spec.time_mode == "observed" else None,
        snapshot_at=snap.generated_at,
        time_basis=spec.time_mode,
        block_until=block_until,
        observe_until=observe_until,
        expires_at=expires_at,
    )


def advance(
    previous: State,
    config: Config,
    outcomes: tuple[Outcome, ...],
    now: datetime,
    build_id: str,
) -> State:
    """Accept complete valid snapshots, then expire evidence for every source.

    Rejected snapshots cannot establish absence or replace the anomaly baseline.
    Presence outlives evidence so continuously published unknown-time records
    cannot resurrect after expiry, including after history pruning.
    """
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise SourceError("now must be a timezone-aware datetime")
    seen = set()
    for outcome in outcomes:
        if outcome.source_id in seen:
            raise SourceError(f"duplicate_outcome: {outcome.source_id}")
        seen.add(outcome.source_id)
        if (outcome.snapshot is None) == (outcome.error is None):
            raise SourceError(f"invalid_outcome: {outcome.source_id}")

    specs = {spec.id: spec for spec in config.sources}
    admitted = {sid for sid, spec in specs.items() if spec.enabled and spec.public_approved}
    evidence = {(e.source_id, e.target): e for e in previous.evidence if e.source_id in admitted}
    presence = {sid: dict(targets) for sid, targets in previous.presence.items() if sid in admitted}
    sources = dict(previous.sources)
    known = set(sources) | set(previous.presence) | {e.source_id for e in previous.evidence}
    for sid in known | set(specs) | seen:
        if sid not in admitted:
            spec = specs.get(sid)
            reason = (
                "removed"
                if spec is None
                else ("disabled" if not spec.enabled else "public_approval_revoked")
            )
            # Recreate rather than replace: audit fields can contain revoked data.
            sources[sid] = SourceState(status="disabled", error=reason)
        else:
            sources.setdefault(sid, SourceState())

    for outcome in outcomes:
        sid = outcome.source_id
        if sid not in admitted:
            continue
        spec = specs[sid]
        health = replace(sources[sid], last_attempt_at=outcome.attempted_at)
        if outcome.error is not None:
            sources[sid] = replace(health, status="error", error=outcome.error)
            continue
        snap = outcome.snapshot
        assert snap is not None
        try:
            if snap.source_id != sid:
                raise SourceError("source_id_mismatch")
            records, notices = _normalized_records(spec, snap, config.settings, now)
            if (
                health.generated_at is not None
                and snap.generated_at is not None
                and snap.generated_at < health.generated_at
            ):
                raise SourceError("generated_at_regression")
            deadline = _deadline(spec, snap, config.settings, now, empty=not records)
            if deadline is not None and now >= deadline:
                sources[sid] = replace(health, status="stale", error="stale_snapshot")
                continue
            old_presence = presence.get(sid, {})
            candidates = {}
            for target, record in records.items():
                marker = old_presence.get(target)
                first_seen = marker.first_seen_at if marker and marker.present else now
                old = evidence.get((sid, target))
                if old is not None and spec.time_mode != "unknown":
                    first_seen = old.first_seen_at
                candidate = _evidence(spec, record, snap, config.settings, first_seen, deadline)
                if (
                    old is not None
                    and spec.time_mode == "observed"
                    and old.observed_at is not None
                    and candidate.observed_at is not None
                    and candidate.observed_at < old.observed_at
                ):
                    candidate = old
                candidates[target] = candidate
            valid_candidates = [e for e in candidates.values() if now < e.expires_at]
            if records and not valid_candidates:
                sources[sid] = replace(health, status="stale", error="stale_snapshot")
                continue
            previous_targets = {target for target, p in old_presence.items() if p.present}
            if (
                health.last_success_at is not None
                and len(records.keys() - previous_targets) >= config.settings.anomaly_new
                and len(records) > health.accepted_count * config.settings.anomaly_ratio
            ):
                raise SourceError("anomalous_growth")
        except SourceError as exc:
            sources[sid] = replace(health, status="error", error=str(exc))
            continue

        updated_presence = {
            target: replace(marker, present=False) for target, marker in old_presence.items()
        }
        for target, candidate in candidates.items():
            updated_presence[target] = Presence(candidate.first_seen_at, True)
        presence[sid] = updated_presence
        if spec.purpose != "web" or spec.time_mode in ("rolling", "snapshot"):
            evidence = {key: e for key, e in evidence.items() if key[0] != sid}
        for target, candidate in candidates.items():
            evidence[(sid, target)] = candidate
        sources[sid] = SourceState(
            last_attempt_at=outcome.attempted_at,
            last_success_at=now,
            status="ok" if records else "empty",
            generated_at=snap.generated_at
            if snap.generated_at is not None
            else health.generated_at,
            valid_until=deadline,
            accepted_count=len(records),
            sha256=snap.sha256,
            notices=notices,
        )

    evidence = {key: e for key, e in evidence.items() if now < e.expires_at}
    active_deadlines: dict[str, datetime] = {}
    for (sid, _), item in evidence.items():
        active_deadlines[sid] = min(active_deadlines.get(sid, item.expires_at), item.expires_at)
    for sid, health in sources.items():
        spec = specs.get(sid)
        if (
            sid in admitted
            and spec is not None
            and spec.purpose == "web"
            and spec.time_mode in ("observed", "unknown")
            and health.accepted_count > 0
        ):
            # Empty checks have their own health deadline; errors keep their
            # status even though the remaining evidence deadline moves forward.
            health = replace(health, valid_until=active_deadlines.get(sid))
            sources[sid] = health
        if health.status in ("ok", "empty") and (
            health.valid_until is None or now >= health.valid_until
        ):
            sources[sid] = replace(health, status="stale", error="expired")
    cutoff = now - timedelta(days=30)
    return State(
        schema_version=previous.schema_version,
        evidence=tuple(sorted(evidence.values(), key=lambda e: (e.source_id, sort_key(e.target)))),
        presence=presence,
        sources=sources,
        history=tuple(r for r in previous.history if r.generated_at >= cutoff)
        + (RunRecord(build_id, now),),
    )
