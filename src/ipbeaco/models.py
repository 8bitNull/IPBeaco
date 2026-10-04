"""Shared immutable data contracts for collection, evidence, and persistence."""

from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Literal

Purpose = Literal["web", "network", "c2"]
TimeMode = Literal["observed", "rolling", "unknown", "snapshot"]
Tier = Literal["block", "observe"]


class ConfigError(ValueError):
    pass


class SourceError(ValueError):
    pass


class StateError(ValueError):
    pass


class _TimezoneAware:
    def __post_init__(self) -> None:
        for item in fields(self):
            if item.type not in (datetime, datetime | None):
                continue
            value = getattr(self, item.name)
            if value is None and item.type == datetime | None:
                continue
            if not isinstance(value, datetime) or value.utcoffset() is None:
                identity = getattr(self, "id", type(self).__name__)
                if not isinstance(identity, str):
                    identity = type(self).__name__
                raise ValueError(f"{identity}: {item.name} must be a timezone-aware datetime")


@dataclass(frozen=True)
class SourceSpec(_TimezoneAware):
    id: str
    family: str
    purpose: Purpose
    adapter: str
    url: str
    enabled: bool
    public_approved: bool
    license_url: str
    reviewed_at: datetime | None
    time_mode: TimeMode
    max_tier: Tier = "observe"
    trusted_single: bool = False
    independent: bool = False
    category: str = "unknown"
    window_hours: int | None = None
    attribution: str = ""
    disabled_reason: str = ""
    ip_versions: tuple[int, ...] = (4, 6)


@dataclass(frozen=True)
class InputRecord(_TimezoneAware):
    target: str
    category: str
    observed_at: datetime | None = None


@dataclass(frozen=True)
class Snapshot(_TimezoneAware):
    source_id: str
    fetched_at: datetime
    generated_at: datetime | None
    records: tuple[InputRecord, ...]
    sha256: str
    upstream_expires_at: datetime | None = None
    notices: tuple[str, ...] = ()


@dataclass(frozen=True)
class Outcome(_TimezoneAware):
    source_id: str
    attempted_at: datetime
    snapshot: Snapshot | None = None
    error: str | None = None


@dataclass(frozen=True)
class Evidence(_TimezoneAware):
    source_id: str
    target: str
    category: str
    first_seen_at: datetime
    observed_at: datetime | None
    snapshot_at: datetime | None
    time_basis: TimeMode
    block_until: datetime | None
    observe_until: datetime | None
    expires_at: datetime


@dataclass(frozen=True)
class Presence(_TimezoneAware):
    first_seen_at: datetime
    present: bool


@dataclass(frozen=True)
class SourceState(_TimezoneAware):
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    status: str = "unavailable"
    generated_at: datetime | None = None
    valid_until: datetime | None = None
    accepted_count: int = 0
    sha256: str | None = None
    notices: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class RunRecord(_TimezoneAware):
    build_id: str
    generated_at: datetime


@dataclass(frozen=True)
class State:
    schema_version: int = 1
    evidence: tuple[Evidence, ...] = ()
    presence: dict[str, dict[str, Presence]] = field(default_factory=dict)
    sources: dict[str, SourceState] = field(default_factory=dict)
    history: tuple[RunRecord, ...] = ()


@dataclass(frozen=True)
class Settings:
    block_hours: int = 72
    observe_hours: int = 168
    snapshot_hours: int = 48
    future_skew_seconds: int = 300
    anomaly_new: int = 1000
    anomaly_ratio: int = 3
    max_bytes: int = 10_485_760
    timeout_seconds: int = 20
    attempts: int = 3


@dataclass(frozen=True)
class Config:
    sources: tuple[SourceSpec, ...]
    settings: Settings
    allowlist: tuple[str, ...]
