"""Selection rules through real evidence and temporal transitions."""

from dataclasses import replace
from datetime import timedelta

import pytest

from ipbeaco.models import Config, InputRecord, Outcome, Settings, State
from ipbeaco.policy import select
from ipbeaco.temporal import advance
from tests.factories import NOW, snapshot, source

KEYS = (
    "block-ipv4",
    "block-ipv6",
    "observe-ipv4",
    "observe-ipv6",
    "network-ipv4",
    "network-ipv6",
    "c2-ipv4",
    "c2-ipv6",
)


def collected(specs, targets=("8.8.8.8",), *, allowlist=(), observations=None, categories=None):
    cfg = Config(tuple(specs), Settings(), allowlist)
    outcomes = []
    for spec in specs:
        records = tuple(
            InputRecord(
                target,
                (categories or {}).get(spec.id, spec.category),
                (observations or {}).get(spec.id, NOW),
            )
            for target in targets
        )
        outcomes.append(Outcome(spec.id, NOW, snapshot(source_id=spec.id, records=records)))
    return advance(State(), cfg, tuple(outcomes), NOW, "run"), cfg


def targets(result, key):
    return [entry.target for entry in result.lists[key]]


def test_empty_selection_has_all_eight_keys():
    result = select(State(), Config((), Settings(), ()), NOW)
    assert tuple(result.lists) == KEYS
    assert all(entries == () for entries in result.lists.values())
    assert result.exclusions == ()


@pytest.mark.parametrize(
    "changes,blocked",
    [
        ({"family": "shared"}, False),
        ({"family": "other"}, True),
        ({"family": "other", "independent": False}, False),
        ({"family": "other", "max_tier": "observe"}, False),
        ({"family": "shared", "trusted_single": True, "independent": False}, True),
    ],
)
def test_independent_family_threshold(changes, blocked):
    state, cfg = collected((source(id="a", family="shared"), source(id="b", **changes)))
    result = select(state, cfg, NOW)
    assert targets(result, "block-ipv4") == (["8.8.8.8"] if blocked else [])
    assert targets(result, "observe-ipv4") == ([] if blocked else ["8.8.8.8"])


def test_trusted_single_can_block_without_independence():
    state, cfg = collected((source(trusted_single=True, independent=False),))
    (entry,) = select(state, cfg, NOW).lists["block-ipv4"]
    assert entry.source_ids == ("test-web",)
    assert entry.valid_until == NOW + timedelta(hours=72)
    assert entry.reason


@pytest.mark.parametrize(
    "category,configured,blocked",
    [
        ("web_attack", "unknown", True),
        ("web_exploit", "web_exploit", True),
        ("web_bruteforce", "web_bruteforce", True),
        ("web_exploit", "web_attack", False),
        ("web_bruteforce", "unknown", False),
        ("scan", "scan", False),
        ("unknown", "unknown", False),
    ],
)
def test_category_requires_explicit_permission_for_exploit_and_bruteforce(
    category, configured, blocked
):
    spec = source(trusted_single=True, category=configured)
    state, cfg = collected((spec,), categories={spec.id: category})
    result = select(state, cfg, NOW)
    assert bool(result.lists["block-ipv4"]) is blocked
    assert bool(result.lists["observe-ipv4"]) is not blocked


def test_block_support_deadline_and_expiry_downgrade():
    specs = (source(id="a", family="a"), source(id="b", family="b"))
    state, cfg = collected(specs, observations={"a": NOW - timedelta(hours=24)})
    result = select(state, cfg, NOW)
    (entry,) = result.lists["block-ipv4"]
    assert entry.source_ids == ("a", "b")
    assert entry.valid_until == NOW + timedelta(hours=48)
    later = NOW + timedelta(hours=48)
    for current in (state, advance(state, cfg, (), later, "expire")):
        result = select(current, cfg, later)
        assert result.lists["block-ipv4"] == ()
        (entry,) = result.lists["observe-ipv4"]
        assert entry.valid_until == NOW + timedelta(hours=144)
        assert entry.source_ids == ("a", "b")
    assert all(
        not entries for entries in select(state, cfg, NOW + timedelta(days=7)).lists.values()
    )


def test_observe_only_evidence_never_supports_block():
    specs = (source(id="block", trusted_single=True), source(id="observe", max_tier="observe"))
    state, cfg = collected(specs, observations={"observe": NOW - timedelta(days=6)})
    # Even persisted block deadlines cannot override current observe-only configuration.
    state = replace(
        state,
        evidence=tuple(
            replace(e, block_until=NOW + timedelta(hours=1)) if e.source_id == "observe" else e
            for e in state.evidence
        ),
    )
    (entry,) = select(state, cfg, NOW).lists["block-ipv4"]
    assert entry.source_ids == ("block",)
    assert entry.valid_until == NOW + timedelta(hours=72)


def test_same_ip_can_appear_in_web_network_and_c2_without_c2_promotion():
    web = source(id="web")
    c2 = source(id="c2", purpose="c2", time_mode="snapshot", trusted_single=True)
    state, cfg = collected((web, c2))
    network = source(id="network", purpose="network", time_mode="snapshot")
    cfg = replace(cfg, sources=cfg.sources + (network,))
    state = advance(
        state,
        cfg,
        (Outcome(network.id, NOW, snapshot("8.8.8.8/32", source_id=network.id)),),
        NOW,
        "network",
    )
    result = select(state, cfg, NOW)
    assert targets(result, "observe-ipv4") == ["8.8.8.8"]
    assert targets(result, "network-ipv4") == ["8.8.8.8/32"]
    assert targets(result, "c2-ipv4") == ["8.8.8.8"]
    assert result.lists["block-ipv4"] == ()
    c2_only = select(state, replace(cfg, sources=(c2, network)), NOW)
    assert c2_only.lists["observe-ipv4"] == ()
    assert c2_only.lists["block-ipv4"] == ()


@pytest.mark.parametrize(
    "purpose,values",
    [
        ("network", ("8.8.8.0/24", "8.8.8.0/25", "8.8.8.0/24")),
        ("c2", ("8.8.8.8", "8.8.8.8")),
    ],
)
def test_snapshot_targets_merge_exact_duplicates_and_expire(purpose, values):
    specs = tuple(source(id=sid, purpose=purpose, time_mode="snapshot") for sid in ("z", "a"))
    state, cfg = collected(specs, values)
    state = replace(
        state,
        evidence=tuple(
            replace(e, expires_at=NOW + timedelta(hours=6)) if e.source_id == "a" else e
            for e in state.evidence
        ),
    )
    entries = select(state, cfg, NOW).lists[f"{purpose}-ipv4"]
    assert [entry.target for entry in entries] == list(dict.fromkeys(values))
    assert all(entry.source_ids == ("a", "z") for entry in entries)
    assert all(entry.valid_until == NOW + timedelta(hours=6) for entry in entries)
    later = select(state, cfg, NOW + timedelta(hours=6)).lists[f"{purpose}-ipv4"]
    assert all(entry.source_ids == ("z",) for entry in later)
    assert not select(state, cfg, NOW + timedelta(hours=48)).lists[f"{purpose}-ipv4"]


@pytest.mark.parametrize(
    "purpose,target,allowlist",
    [
        ("web", "8.8.8.8", ("8.8.8.0/24",)),
        ("c2", "8.8.8.8", ("8.8.8.8",)),
        ("network", "8.8.8.0/24", ("8.8.8.1",)),
        ("network", "8.8.8.0/24", ("8.8.8.128/25",)),
        ("network", "2606:4700::/32", ("2606:4700:4700::1111",)),
    ],
)
def test_allowlist_overrides_selection_and_excludes_entire_network(purpose, target, allowlist):
    spec = source(
        purpose=purpose,
        time_mode="observed" if purpose == "web" else "snapshot",
        trusted_single=True,
    )
    state, cfg = collected((spec,), (target,), allowlist=allowlist)
    result = select(state, cfg, NOW)
    assert all(not entries for entries in result.lists.values())
    assert result.exclusions == ({"target": target, "source_id": spec.id, "reason": "allowlisted"},)
    assert select(state, cfg, NOW + timedelta(days=7)).exclusions == ()


@pytest.mark.parametrize("revocation", ["disabled", "unapproved", "removed"])
def test_revoked_sources_are_neither_selected_nor_disclosed_in_exclusions(revocation):
    spec = source(trusted_single=True)
    state, cfg = collected((spec,))
    revised = replace(
        spec, enabled=revocation != "disabled", public_approved=revocation != "unapproved"
    )
    cfg = replace(cfg, sources=() if revocation == "removed" else (revised,))
    for rules in ((), ("8.8.8.8",)):
        result = select(state, replace(cfg, allowlist=rules), NOW)
        assert all(not entries for entries in result.lists.values())
        assert result.exclusions == ()


@pytest.mark.parametrize(
    "purpose,tier", [("web", "block"), ("web", "observe"), ("network", "network"), ("c2", "c2")]
)
def test_ipv6_and_numeric_sort_are_stable_under_input_permutations(purpose, tier):
    values = ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888")
    if purpose == "network":
        values = tuple(value + ("/32" if ":" not in value else "/128") for value in values)
    specs = tuple(
        source(
            id=sid,
            purpose=purpose,
            trusted_single=True,
            max_tier="observe" if tier == "observe" else "block",
            time_mode="observed" if purpose == "web" else "snapshot",
        )
        for sid in ("z", "a")
    )
    state, cfg = collected(specs, values)
    result = select(state, cfg, NOW)
    assert targets(result, f"{tier}-ipv4") == [values[1], values[0]]
    assert targets(result, f"{tier}-ipv6") == [values[3], values[2]]
    assert result == select(
        replace(state, evidence=tuple(reversed(state.evidence))),
        replace(cfg, sources=tuple(reversed(cfg.sources))),
        NOW,
    )
    allowlisted = select(state, replace(cfg, allowlist=values), NOW)
    assert [(e["target"], e["source_id"]) for e in allowlisted.exclusions] == [
        (value, sid) for value in (values[1], values[0], values[3], values[2]) for sid in ("a", "z")
    ]
