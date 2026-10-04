"""Select independent publication lists from current admitted evidence."""

from dataclasses import dataclass
from datetime import datetime

from ipbeaco.addresses import is_allowed, sort_key
from ipbeaco.models import Config, Evidence, SourceSpec, State


@dataclass(frozen=True)
class Entry:
    target: str
    valid_until: datetime
    source_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class Selection:
    lists: dict[str, tuple[Entry, ...]]
    exclusions: tuple[dict[str, str], ...]


def _qualifies(item: Evidence, spec: SourceSpec, now: datetime) -> bool:
    return (
        item.block_until is not None
        and now < item.block_until
        and spec.max_tier == "block"
        and (
            item.category == "web_attack"
            or (
                item.category in {"web_exploit", "web_bruteforce"}
                and spec.category == item.category
            )
        )
    )


def select(state: State, config: Config, now: datetime) -> Selection:
    """Reevaluate current eligibility without mutating or renewing evidence.

    Only evidence supporting the selected tier supplies its attribution and
    deadline. Exact targets merge within a purpose; CIDR boundaries survive.
    """
    specs = {spec.id: spec for spec in config.sources if spec.enabled and spec.public_approved}
    lists: dict[str, list[Entry]] = {
        f"{tier}-ipv{version}": []
        for tier in ("block", "observe", "network", "c2")
        for version in (4, 6)
    }
    groups: dict[tuple[str, str], list[Evidence]] = {}
    excluded: set[tuple[str, str]] = set()
    for item in state.evidence:
        spec = specs.get(item.source_id)
        if spec is None or now >= item.expires_at:
            continue
        if is_allowed(item.target, config.allowlist):
            excluded.add((item.target, item.source_id))
            continue
        groups.setdefault((spec.purpose, item.target), []).append(item)

    for (purpose, target), evidence in groups.items():
        tier = purpose
        if purpose == "web":
            qualifying = [item for item in evidence if _qualifies(item, specs[item.source_id], now)]
            families = {
                specs[item.source_id].family
                for item in qualifying
                if specs[item.source_id].independent
            }
            trusted = any(specs[item.source_id].trusted_single for item in qualifying)
            if trusted or len(families) >= 2:
                tier = "block"
                support = [
                    item
                    for item in qualifying
                    if specs[item.source_id].independent or specs[item.source_id].trusted_single
                ]
                deadlines = [min(item.expires_at, item.block_until) for item in support]
                reason = "trusted_single" if trusted else "independent_families"
            else:
                tier = "observe"
                support = [
                    item
                    for item in evidence
                    if item.observe_until is not None and now < item.observe_until
                ]
                deadlines = [min(item.expires_at, item.observe_until) for item in support]
                reason = "observation"
        else:
            support = evidence
            deadlines = [item.expires_at for item in support]
            reason = "snapshot"
        if not support:
            continue
        entry = Entry(
            target=target,
            valid_until=min(deadlines),
            source_ids=tuple(sorted({item.source_id for item in support})),
            reason=reason,
        )
        version = sort_key(target)[0]
        lists[f"{tier}-ipv{version}"].append(entry)

    return Selection(
        lists={
            key: tuple(sorted(entries, key=lambda entry: sort_key(entry.target)))
            for key, entries in lists.items()
        },
        exclusions=tuple(
            {"target": target, "source_id": sid, "reason": "allowlisted"}
            for target, sid in sorted(excluded, key=lambda pair: (sort_key(pair[0]), pair[1]))
        ),
    )
