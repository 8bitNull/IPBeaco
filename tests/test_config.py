from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ipbeaco.config import load_config, validate_config, validate_source
from ipbeaco.models import (
    Config,
    ConfigError,
    Evidence,
    InputRecord,
    Outcome,
    Presence,
    RunRecord,
    Settings,
    SourceState,
)
from tests.factories import NOW, snapshot, source

VALID_SOURCE = """[[sources]]
id = "test-web"
family = "test-family"
purpose = "web"
adapter = "blocklist_de"
url = "https://example.invalid/feed.txt"
enabled = true
public_approved = true
license_url = "https://example.invalid/license"
reviewed_at = 2026-10-04T00:00:00Z
time_mode = "observed"
max_tier = "block"
independent = true
category = "web_attack"
ip_versions = [4, 6]
"""

INCOMPATIBLE_SOURCE_RULES = [
    ("blocklist_de", "network", "snapshot", "purpose"),
    ("blocklist_de", "c2", "snapshot", "purpose"),
    ("spamhaus_drop", "web", "unknown", "purpose"),
    ("spamhaus_drop", "c2", "snapshot", "purpose"),
    ("feodo", "web", "unknown", "purpose"),
    ("feodo", "network", "snapshot", "purpose"),
    ("spamhaus_drop", "network", "observed", "time_mode"),
    ("spamhaus_drop", "network", "rolling", "time_mode"),
    ("spamhaus_drop", "network", "unknown", "time_mode"),
    ("feodo", "c2", "observed", "time_mode"),
    ("feodo", "c2", "rolling", "time_mode"),
    ("feodo", "c2", "unknown", "time_mode"),
]


def config_root(tmp_path, sources=VALID_SOURCE, policy="[policy]\n", allowlist=""):
    folder = tmp_path / "config"
    folder.mkdir()
    (folder / "sources.toml").write_text(sources, encoding="utf-8")
    (folder / "policy.toml").write_text(policy, encoding="utf-8")
    (folder / "allowlist.txt").write_text(allowlist, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "changes,field",
    [
        ({"public_approved": False}, "public_approved"),
        ({"reviewed_at": None}, "reviewed_at"),
        ({"license_url": ""}, "license_url"),
        ({"url": "http://example.invalid/feed"}, "url"),
        ({"url": "https:///feed"}, "url"),
        ({"url": "https://user:password@example.invalid/feed"}, "url"),
        ({"adapter": "mystery"}, "adapter"),
        ({"adapter": "abuseipdb"}, "adapter"),
        ({"family": " "}, "family"),
        ({"purpose": "malware"}, "purpose"),
        ({"time_mode": "yesterday"}, "time_mode"),
        ({"time_mode": "unknown"}, "max_tier"),
        ({"time_mode": "snapshot"}, "time_mode"),
        ({"time_mode": "rolling"}, "window_hours"),
        ({"time_mode": "rolling", "window_hours": 0}, "window_hours"),
        ({"time_mode": "rolling", "window_hours": 73}, "window_hours"),
        ({"time_mode": "rolling", "window_hours": True}, "window_hours"),
        ({"max_tier": "deny"}, "max_tier"),
        ({"enabled": "true"}, "enabled"),
        ({"public_approved": "true"}, "public_approved"),
        ({"independent": 1}, "independent"),
        ({"trusted_single": 1}, "trusted_single"),
        ({"ip_versions": ()}, "ip_versions"),
        ({"ip_versions": (4, 7)}, "ip_versions"),
        ({"ip_versions": (4, 4)}, "ip_versions"),
        ({"category": ""}, "category"),
    ],
)
def test_invalid_source_identifies_source_and_field(changes, field):
    with pytest.raises(ConfigError) as error:
        validate_source(source(**changes))
    assert "test-web" in str(error.value)
    assert field in str(error.value)
    assert "password" not in str(error.value)


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"enabled": False, "public_approved": False, "reviewed_at": None, "license_url": ""},
        {"time_mode": "unknown", "max_tier": "observe"},
        {"time_mode": "rolling", "window_hours": 1},
        {"time_mode": "rolling", "window_hours": 72},
        {"purpose": "network", "time_mode": "snapshot", "adapter": "spamhaus_drop"},
        {"purpose": "c2", "time_mode": "snapshot", "adapter": "feodo"},
    ],
)
def test_source_accepts_valid_approval_and_time_rules(changes):
    validate_source(source(**changes))


@pytest.mark.parametrize(
    "adapter,purpose,time_mode,max_tier,window_hours",
    [
        ("blocklist_de", "web", "observed", "block", None),
        ("blocklist_de", "web", "observed", "observe", None),
        ("blocklist_de", "web", "rolling", "block", 24),
        ("blocklist_de", "web", "rolling", "observe", 24),
        ("blocklist_de", "web", "unknown", "observe", None),
        ("spamhaus_drop", "network", "snapshot", "block", None),
        ("spamhaus_drop", "network", "snapshot", "observe", None),
        ("feodo", "c2", "snapshot", "block", None),
        ("feodo", "c2", "snapshot", "observe", None),
    ],
)
@pytest.mark.parametrize("independent,trusted_single", [(True, False), (False, True)])
def test_supported_adapter_purpose_time_matrix_preserves_policy_options(
    adapter, purpose, time_mode, max_tier, window_hours, independent, trusted_single
):
    spec = source(
        adapter=adapter,
        purpose=purpose,
        time_mode=time_mode,
        max_tier=max_tier,
        window_hours=window_hours,
        family="operator-selected-family",
        independent=independent,
        trusted_single=trusted_single,
    )
    validate_source(spec)
    validate_config(Config((spec,), Settings(), ()))


@pytest.mark.parametrize("adapter,purpose,time_mode,field", INCOMPATIBLE_SOURCE_RULES)
@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("boundary", ["source", "config"])
def test_incompatible_source_semantics_rejected_at_both_boundaries(
    adapter, purpose, time_mode, field, enabled, boundary
):
    spec = source(
        adapter=adapter,
        purpose=purpose,
        time_mode=time_mode,
        max_tier="observe",
        window_hours=24 if time_mode == "rolling" else None,
        enabled=enabled,
    )
    with pytest.raises(ConfigError, match=f"test-web.*{field}"):
        if boundary == "source":
            validate_source(spec)
        else:
            validate_config(Config((spec,), Settings(), ()))


@pytest.mark.parametrize("adapter,purpose,time_mode,field", INCOMPATIBLE_SOURCE_RULES)
def test_toml_loader_rejects_incompatible_source_semantics(
    tmp_path, adapter, purpose, time_mode, field
):
    text = VALID_SOURCE.replace('adapter = "blocklist_de"', f'adapter = "{adapter}"')
    text = text.replace('purpose = "web"', f'purpose = "{purpose}"')
    text = text.replace('time_mode = "observed"', f'time_mode = "{time_mode}"')
    text = text.replace('max_tier = "block"', 'max_tier = "observe"')
    if time_mode == "rolling":
        text += "window_hours = 24\n"
    with pytest.raises(ConfigError, match=f"test-web.*{field}"):
        load_config(config_root(tmp_path, sources=text))


def test_load_config_preserves_identity_and_normalizes_collections(tmp_path):
    root = config_root(tmp_path, allowlist="# local addresses\n192.0.2.1\n2001:db8::/32\n")
    config = load_config(root)
    assert config.sources[0].id == "test-web"
    assert config.sources[0].reviewed_at == NOW
    assert config.sources[0].ip_versions == (4, 6)
    assert config.allowlist == ("192.0.2.1", "2001:db8::/32")
    assert config.settings.max_bytes == 10_485_760
    assert config.settings.attempts == 3


def test_disabled_source_allows_omitted_review_timestamp(tmp_path):
    text = VALID_SOURCE.replace("enabled = true", "enabled = false")
    text = text.replace("public_approved = true", "public_approved = false")
    text = text.replace("reviewed_at = 2026-10-04T00:00:00Z\n", "")
    assert load_config(config_root(tmp_path, sources=text)).sources[0].reviewed_at is None


def test_duplicate_source_ids_are_rejected(tmp_path):
    with pytest.raises(ConfigError, match="test-web.*id"):
        load_config(config_root(tmp_path, sources=VALID_SOURCE + "\n" + VALID_SOURCE))


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "family",
        "purpose",
        "adapter",
        "url",
        "enabled",
        "public_approved",
        "license_url",
        "time_mode",
    ],
)
def test_missing_required_source_field_is_a_configuration_error(tmp_path, field):
    text = "\n".join(
        line for line in VALID_SOURCE.splitlines() if not line.startswith(f"{field} =")
    )
    with pytest.raises(ConfigError, match=field):
        load_config(config_root(tmp_path, sources=text))


@pytest.mark.parametrize("extra", ['unexpected = "secret"', 'api_key = "secret"'])
def test_unknown_source_keys_are_rejected_without_echoing_values(tmp_path, extra):
    with pytest.raises(ConfigError) as error:
        load_config(config_root(tmp_path, sources=VALID_SOURCE + extra))
    assert "test-web" in str(error.value)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    "replacement,field",
    [
        ('enabled = "yes"', "enabled"),
        ('reviewed_at = "2026-10-04T00:00:00Z"', "reviewed_at"),
        ("reviewed_at = 2026-10-04T00:00:00", "reviewed_at"),
        ('ip_versions = "4,6"', "ip_versions"),
        ("family = 42", "family"),
    ],
)
def test_loader_rejects_wrong_source_types(tmp_path, replacement, field):
    text = "\n".join(
        replacement if line.startswith(f"{field} =") else line for line in VALID_SOURCE.splitlines()
    )
    with pytest.raises(ConfigError, match=field):
        load_config(config_root(tmp_path, sources=text))


def test_optional_abuseipdb_is_not_a_runnable_source(tmp_path):
    config = load_config(
        config_root(tmp_path, sources=VALID_SOURCE + "\n[optional.abuseipdb]\nenabled = false\n")
    )
    assert [spec.id for spec in config.sources] == ["test-web"]


def test_optional_abuseipdb_cannot_be_enabled(tmp_path):
    with pytest.raises(ConfigError, match="abuseipdb.*enabled"):
        load_config(
            config_root(tmp_path, sources=VALID_SOURCE + "\n[optional.abuseipdb]\nenabled = true\n")
        )


@pytest.mark.parametrize(
    "policy,field",
    [
        ("[policy]\nattempts = 0", "attempts"),
        ('[policy]\nmax_bytes = "huge"', "max_bytes"),
        ("[policy]\ntimeout_seconds = true", "timeout_seconds"),
        ("[policy]\nfuture_skew_seconds = -1", "future_skew_seconds"),
        ("[policy]\nfuture_skew_seconds = 301", "future_skew_seconds"),
        ("[policy]\nblock_hours = 73", "block_hours"),
        ("[policy]\nobserve_hours = 169", "observe_hours"),
        ("[policy]\nsnapshot_hours = 49", "snapshot_hours"),
        ('[policy]\nextra = "secret"', "extra"),
        ("policy = []", "policy"),
    ],
)
def test_policy_rejects_invalid_values(tmp_path, policy, field):
    with pytest.raises(ConfigError, match=field):
        load_config(config_root(tmp_path, policy=policy))


def test_policy_accepts_shorter_windows_and_zero_clock_skew(tmp_path):
    config = load_config(
        config_root(tmp_path, policy="[policy]\nblock_hours = 24\nfuture_skew_seconds = 0\n")
    )
    assert config.settings.block_hours == 24
    assert config.settings.future_skew_seconds == 0


@pytest.mark.parametrize("sources", ["sources = {}", 'sources = ["wrong"]', "[unexpected]\nx = 1"])
def test_loader_rejects_malformed_source_structure(tmp_path, sources):
    with pytest.raises(ConfigError):
        load_config(config_root(tmp_path, sources=sources))


def test_invalid_toml_does_not_echo_sensitive_content(tmp_path):
    with pytest.raises(ConfigError) as error:
        load_config(config_root(tmp_path, sources='secret_token = "never-echo-this'))
    assert "sources.toml" in str(error.value)
    assert "never-echo-this" not in str(error.value)


def test_malformed_source_identity_does_not_echo_nested_values(tmp_path):
    text = VALID_SOURCE.replace('id = "test-web"', 'id = { api_key = "never-echo-this" }')
    text = text.replace("reviewed_at = 2026-10-04T00:00:00Z", 'reviewed_at = "invalid"')
    with pytest.raises(ConfigError) as error:
        load_config(config_root(tmp_path, sources=text))
    assert "never-echo-this" not in str(error.value)


def test_missing_config_files_are_configuration_errors(tmp_path):
    with pytest.raises(ConfigError, match="sources.toml"):
        load_config(tmp_path)


def test_invalid_allowlist_reports_line_without_echoing_input(tmp_path):
    with pytest.raises(ConfigError, match="allowlist.*2") as error:
        load_config(config_root(tmp_path, allowlist="192.0.2.1\nnever-echo-this\n"))
    assert "never-echo-this" not in str(error.value)


def test_production_config_loads_with_approved_sources_only():
    config = load_config(Path(__file__).resolve().parents[1])
    assert [spec.id for spec in config.sources] == [
        "blocklist-de-apache",
        "spamhaus-drop-v4",
        "spamhaus-drop-v6",
        "feodo-recommended",
        "cins-army",
    ]
    assert all(not spec.enabled for spec in config.sources[:3])
    assert all(spec.disabled_reason for spec in config.sources[:3])
    assert config.sources[1].family == config.sources[2].family
    assert config.sources[1].ip_versions == (4,)
    assert config.sources[2].ip_versions == (6,)
    assert config.sources[3].public_approved is True
    assert config.sources[0].trusted_single is False


def test_input_record_rejects_naive_datetime():
    with pytest.raises(ValueError, match="observed_at"):
        InputRecord("192.0.2.1", "web_attack", datetime(2026, 10, 4))


def test_snapshot_rejects_naive_datetime():
    with pytest.raises(ValueError, match="fetched_at"):
        snapshot(fetched_at=datetime(2026, 10, 4))


@pytest.mark.parametrize(
    "factory,field",
    [
        (lambda timestamp: source(reviewed_at=timestamp), "reviewed_at"),
        (lambda timestamp: Outcome("test-web", timestamp), "attempted_at"),
        (lambda timestamp: Presence(timestamp, True), "first_seen_at"),
        (lambda timestamp: SourceState(valid_until=timestamp), "valid_until"),
        (lambda timestamp: RunRecord("test-build", timestamp), "generated_at"),
        (
            lambda timestamp: Evidence(
                "test-web",
                "192.0.2.1",
                "web_attack",
                NOW,
                None,
                None,
                "observed",
                None,
                None,
                timestamp,
            ),
            "expires_at",
        ),
    ],
)
def test_shared_models_reject_naive_datetime(factory, field):
    with pytest.raises(ValueError, match=field):
        factory(datetime(2026, 10, 4))


def test_models_accept_aware_non_utc_datetime():
    timestamp = datetime.fromisoformat("2026-10-04T08:00:00+08:00")
    record = InputRecord("192.0.2.1", "web_attack", timestamp)
    assert record.observed_at.astimezone(timezone.utc) == NOW


def test_source_contract_rejects_extra_identity_fields():
    with pytest.raises(TypeError):
        replace(source(), api_key="secret")
