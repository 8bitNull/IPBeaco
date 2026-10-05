"""Load and validate local source, policy, and allowlist configuration."""

import ipaddress
import re
import tomllib
from dataclasses import MISSING, asdict, fields
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from ipbeaco.models import Config, ConfigError, Settings, SourceSpec

_ADAPTER_PURPOSES = {
    "blocklist_de": "web",
    "spamhaus_drop": "network",
    "feodo": "c2",
    "cins_army": "web",
}


def _error(identity: str, field: str, reason: str) -> ConfigError:
    return ConfigError(f"{identity}: {field} {reason}")


def _https_url(value: str) -> bool:
    if not value or any(character.isspace() for character in value):
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
        )
    except ValueError:
        return False


def validate_source(spec: SourceSpec) -> None:
    identity = spec.id if isinstance(spec.id, str) else "<source>"
    for name in (
        "id",
        "family",
        "purpose",
        "adapter",
        "url",
        "license_url",
        "time_mode",
        "max_tier",
        "category",
        "attribution",
        "disabled_reason",
    ):
        value = getattr(spec, name)
        if not isinstance(value, str):
            raise _error(identity, name, "must be a string")
        if name not in ("license_url", "attribution", "disabled_reason") and not value.strip():
            raise _error(identity, name, "must not be empty")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", spec.id) is None:
        raise _error(identity, "id", "must be a simple source identifier")
    for name in ("enabled", "public_approved", "trusted_single", "independent"):
        if type(getattr(spec, name)) is not bool:
            raise _error(identity, name, "must be a boolean")
    if spec.adapter == "abuseipdb":
        raise _error(identity, "adapter", "abuseipdb is unsupported for public sources")
    if spec.adapter not in _ADAPTER_PURPOSES:
        raise _error(identity, "adapter", "is unknown")
    if spec.purpose not in ("web", "network", "c2"):
        raise _error(identity, "purpose", "is unknown")
    if spec.time_mode not in ("observed", "rolling", "unknown", "snapshot"):
        raise _error(identity, "time_mode", "is unknown")
    if spec.purpose != _ADAPTER_PURPOSES[spec.adapter]:
        raise _error(
            identity, "purpose", f"{spec.adapter} requires {_ADAPTER_PURPOSES[spec.adapter]}"
        )
    if spec.adapter == "cins_army":
        for name, expected in (
            ("time_mode", "unknown"),
            ("max_tier", "observe"),
            ("category", "unknown"),
            ("independent", False),
            ("trusted_single", False),
            ("ip_versions", (4,)),
        ):
            if getattr(spec, name) != expected:
                raise _error(identity, name, f"cins_army requires {expected}")
    if spec.purpose in ("network", "c2") and spec.time_mode != "snapshot":
        raise _error(identity, "time_mode", "network and c2 require snapshot")
    if spec.max_tier not in ("block", "observe"):
        raise _error(identity, "max_tier", "is unknown")
    if not _https_url(spec.url):
        raise _error(identity, "url", "must be an absolute HTTPS URL without credentials")
    if spec.license_url and not _https_url(spec.license_url):
        raise _error(identity, "license_url", "must be an absolute HTTPS URL without credentials")
    if spec.reviewed_at is not None and (
        not isinstance(spec.reviewed_at, datetime) or spec.reviewed_at.utcoffset() is None
    ):
        raise _error(identity, "reviewed_at", "must be a timezone-aware datetime")
    if (
        not isinstance(spec.ip_versions, tuple)
        or not spec.ip_versions
        or any(type(version) is not int or version not in (4, 6) for version in spec.ip_versions)
        or len(set(spec.ip_versions)) != len(spec.ip_versions)
    ):
        raise _error(identity, "ip_versions", "must contain distinct address families 4 and/or 6")
    if spec.window_hours is not None and (
        type(spec.window_hours) is not int or not 0 < spec.window_hours <= 72
    ):
        raise _error(identity, "window_hours", "must be an integer between 1 and 72")
    if spec.time_mode == "rolling" and spec.window_hours is None:
        raise _error(identity, "window_hours", "is required for rolling sources")
    if spec.time_mode == "snapshot" and spec.purpose not in ("network", "c2"):
        raise _error(identity, "time_mode", "snapshot requires network or c2 purpose")
    if spec.time_mode == "unknown" and spec.max_tier == "block":
        raise _error(identity, "max_tier", "unknown time cannot directly block")
    if spec.enabled:
        if not spec.public_approved:
            raise _error(identity, "public_approved", "must be true before enabling")
        if spec.reviewed_at is None:
            raise _error(identity, "reviewed_at", "is required before enabling")
        if not spec.license_url:
            raise _error(identity, "license_url", "is required before enabling")


def _read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError, UnicodeError):
        raise ConfigError(f"{path.name}: cannot read valid TOML") from None


def _table(value: object, identity: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{identity}: must be a TOML table")
    return value


def _known_keys(table: dict, allowed: set[str], identity: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise _error(identity, sorted(unknown)[0], "is an unknown field")


def _load_sources(document: dict) -> tuple[SourceSpec, ...]:
    _known_keys(document, {"sources", "optional"}, "sources.toml")
    if "optional" in document:
        optional = _table(document["optional"], "optional")
        _known_keys(optional, {"abuseipdb"}, "optional")
        if "abuseipdb" in optional:
            abuse = _table(optional["abuseipdb"], "optional.abuseipdb")
            _known_keys(abuse, {"enabled"}, "optional.abuseipdb")
            if type(abuse.get("enabled")) is not bool:
                raise _error("optional.abuseipdb", "enabled", "must be a boolean")
            if abuse["enabled"]:
                raise _error("optional.abuseipdb", "enabled", "must remain false")
    entries = document.get("sources")
    if not isinstance(entries, list):
        raise ConfigError("sources.toml: sources must be an array of tables")
    result = []
    ids = set()
    source_fields = fields(SourceSpec)
    for index, entry in enumerate(entries):
        entry = _table(entry, f"sources[{index}]")
        identity = entry.get("id")
        if not isinstance(identity, str):
            identity = f"sources[{index}]"
        _known_keys(entry, {item.name for item in source_fields}, identity)
        for item in source_fields:
            if item.name == "reviewed_at":
                continue
            if (
                item.default is MISSING
                and item.default_factory is MISSING
                and item.name not in entry
            ):
                raise _error(identity, item.name, "is required")
        values = dict(entry)
        values.setdefault("reviewed_at", None)
        if "ip_versions" in values:
            if not isinstance(values["ip_versions"], list):
                raise _error(identity, "ip_versions", "must be an array of address families")
            values["ip_versions"] = tuple(values["ip_versions"])
        try:
            spec = SourceSpec(**values)
        except (TypeError, ValueError) as error:
            raise ConfigError(str(error)) from None
        validate_source(spec)
        if spec.id in ids:
            raise _error(spec.id, "id", "is duplicated")
        ids.add(spec.id)
        result.append(spec)
    return tuple(result)


def _load_settings(document: dict) -> Settings:
    _known_keys(document, {"policy"}, "policy.toml")
    policy = _table(document.get("policy"), "policy")
    _known_keys(policy, {item.name for item in fields(Settings)}, "policy")
    maximums = {
        "block_hours": 72,
        "observe_hours": 168,
        "snapshot_hours": 48,
        "future_skew_seconds": 300,
    }
    for name, value in policy.items():
        minimum = 0 if name == "future_skew_seconds" else 1
        if type(value) is not int or value < minimum:
            raise _error("policy", name, f"must be an integer >= {minimum}")
        if name in maximums and value > maximums[name]:
            raise _error("policy", name, f"must be <= {maximums[name]}")
    return Settings(**policy)


def _load_allowlist(path: Path) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise ConfigError(f"{path.name}: cannot read allowlist") from None
    entries = []
    for number, line in enumerate(lines, 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            address = (
                ipaddress.ip_network(value, strict=False)
                if "/" in value
                else ipaddress.ip_address(value)
            )
        except ValueError:
            raise ConfigError(f"{path.name}: line {number} must be an IP address or CIDR") from None
        normalized = str(address)
        if normalized not in entries:
            entries.append(normalized)
    return tuple(entries)


def validate_config(config: Config) -> None:
    """Validate a Config after TOML normalization or direct construction."""
    if not isinstance(config, Config):
        raise ConfigError("config: must be a Config")
    if not isinstance(config.sources, tuple):
        raise ConfigError("sources: must be a tuple")
    ids = set()
    for spec in config.sources:
        if not isinstance(spec, SourceSpec):
            raise ConfigError("sources: must contain SourceSpec values")
        validate_source(spec)
        if spec.id in ids:
            raise _error(spec.id, "id", "is duplicated")
        ids.add(spec.id)
    if not isinstance(config.settings, Settings):
        raise ConfigError("policy: must be Settings")
    _load_settings({"policy": asdict(config.settings)})
    if not isinstance(config.allowlist, tuple):
        raise ConfigError("allowlist: must be a tuple")
    for index, value in enumerate(config.allowlist, 1):
        try:
            if not isinstance(value, str) or "%" in value:
                raise ValueError
            if "/" in value:
                # Direct Config inputs must be usable by strict policy parsing.
                ipaddress.ip_network(value, strict=True)
            else:
                ipaddress.ip_address(value)
        except ValueError:
            raise ConfigError(f"allowlist: entry {index} must be an IP address or CIDR") from None


def load_config_dir(folder: Path) -> Config:
    """Load a configuration directory directly, regardless of its basename."""
    config = Config(
        sources=_load_sources(_read_toml(folder / "sources.toml")),
        settings=_load_settings(_read_toml(folder / "policy.toml")),
        allowlist=_load_allowlist(folder / "allowlist.txt"),
    )
    validate_config(config)
    return config


def load_config(root: Path) -> Config:
    """Keep the original repository-root loading interface."""
    return load_config_dir(root / "config")
