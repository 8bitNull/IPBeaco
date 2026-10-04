import shutil
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from ipbeaco import pipeline
from ipbeaco.config import load_config_dir, validate_config
from ipbeaco.models import Config, ConfigError, Settings, StateError
from ipbeaco.state import load_state
from tests.factories import NOW, source

FIXTURES = Path(__file__).parent / "fixtures/integration"


def integration_config(tmp_path):
    folder = tmp_path / "synthetic-config"
    shutil.copytree(FIXTURES, folder)
    return load_config_dir(folder)


def feed_response(request):
    names = {"/web": "web.txt", "/network": "network.json", "/c2": "c2.txt"}
    return httpx.Response(200, content=(FIXTURES / names[request.url.path]).read_bytes())


def test_offline_pipeline_expires_evidence_but_keeps_presence(tmp_path):
    import json

    cfg = integration_config(tmp_path)
    state_dir = tmp_path / "state"
    with httpx.Client(transport=httpx.MockTransport(feed_response)) as client:
        state = pipeline.run_once(
            cfg, state_dir, tmp_path / "first", client, NOW, "first", bootstrap=True
        )
    assert len(list((tmp_path / "first/lists").glob("*.txt"))) == 8
    assert (tmp_path / "first/lists/observe-ipv4.txt").read_text() == "8.8.8.8\n"
    assert "8.8.8.0/24\n" in (tmp_path / "first/lists/network-ipv4.txt").read_text()
    assert (tmp_path / "first/lists/c2-ipv4.txt").read_text() == "1.1.1.1\n"
    assert load_state(state_dir) == state
    with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(404))) as client:
        state = pipeline.run_once(
            cfg, state_dir, tmp_path / "third", client, NOW + timedelta(days=3), "third"
        )
        assert {e.source_id for e in state.evidence} == {"web"}
        assert (tmp_path / "third/lists/network-ipv4.txt").read_bytes() == b""
        assert (tmp_path / "third/lists/c2-ipv4.txt").read_bytes() == b""
        assert (tmp_path / "third/lists/observe-ipv4.txt").read_text() == "8.8.8.8\n"
        status = json.loads((tmp_path / "third/lists/status.json").read_text())
        assert status["lists"]["observe-ipv4"]["status"] == "degraded"
        state = pipeline.run_once(
            cfg, state_dir, tmp_path / "eighth", client, NOW + timedelta(days=8), "eighth"
        )
    assert state.evidence == ()
    assert state.presence["web"]["8.8.8.8"].present
    assert (tmp_path / "eighth/lists/observe-ipv4.txt").read_bytes() == b""
    assert load_state(state_dir) == state


def test_collect_never_downloads_disabled_or_unapproved_sources():
    specs = (source(enabled=False), source(id="unapproved", public_approved=False))
    cfg = Config(specs, Settings(), ())

    def forbidden(request):
        pytest.fail("unadmitted source was downloaded")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        assert pipeline.collect(cfg, NOW, client) == ()


@pytest.mark.parametrize("response", [httpx.Response(404), httpx.Response(200, content=b"bad")])
def test_collect_converts_download_and_parse_errors_to_outcomes(response):
    cfg = Config((source(time_mode="unknown", max_tier="observe"),), Settings(), ())
    with httpx.Client(transport=httpx.MockTransport(lambda request: response)) as client:
        outcomes = pipeline.collect(cfg, NOW, client)
    assert len(outcomes) == 1
    assert outcomes[0].snapshot is None
    assert outcomes[0].error
    assert outcomes[0].attempted_at == NOW


@pytest.mark.parametrize("kind", ["directory", "file", "broken_symlink"])
def test_existing_output_rejected_before_collection(tmp_path, kind):
    cfg = integration_config(tmp_path)
    output = tmp_path / "existing"
    if kind == "directory":
        output.mkdir()
    elif kind == "file":
        output.write_text("keep")
    else:
        output.symlink_to(tmp_path / "missing")

    def forbidden(request):
        pytest.fail("collection began with existing output")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(FileExistsError):
            pipeline.run_once(cfg, tmp_path / "state", output, client, NOW, "test", bootstrap=True)
    assert not (tmp_path / "state").exists()


def test_output_validation_failure_leaves_saved_state_bytes_unchanged(tmp_path, monkeypatch):
    cfg = integration_config(tmp_path)
    state_dir = tmp_path / "state"
    with httpx.Client(transport=httpx.MockTransport(feed_response)) as client:
        pipeline.run_once(cfg, state_dir, tmp_path / "first", client, NOW, "first", bootstrap=True)
        before = {p.name: p.read_bytes() for p in state_dir.iterdir()}

        def invalid(output, now):
            raise ValueError("injected output validation failure")

        monkeypatch.setattr(pipeline, "validate_site", invalid)
        with pytest.raises(ValueError, match="injected"):
            pipeline.run_once(
                cfg, state_dir, tmp_path / "invalid", client, NOW + timedelta(hours=1), "invalid"
            )
    assert before == {p.name: p.read_bytes() for p in state_dir.iterdir()}


def test_bad_state_stops_before_collection(tmp_path):
    cfg = integration_config(tmp_path)

    def forbidden(request):
        pytest.fail("collection began before state validation")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(StateError):
            pipeline.run_once(cfg, tmp_path / "missing", tmp_path / "out", client, NOW, "test")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"sources": (source(public_approved=False),)},
        {"sources": (source(), source())},
        {"settings": Settings(snapshot_hours=49)},
        {"settings": Settings(attempts=True)},
        {"allowlist": ("not-an-ip",)},
    ],
)
def test_programmatic_config_rejected_before_state_and_collection(tmp_path, change):
    cfg = replace(Config((source(),), Settings(), ()), **change)
    with pytest.raises(ConfigError):
        validate_config(cfg)

    def forbidden(request):
        pytest.fail("invalid config reached network")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(ConfigError):
            pipeline.run_once(cfg, tmp_path / "state", tmp_path / "out", client, NOW, "test")


@pytest.mark.parametrize(
    "adapter,purpose,time_mode,field",
    [
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
    ],
)
def test_incompatible_source_rejected_before_http_state_and_output_creation(
    tmp_path, adapter, purpose, time_mode, field
):
    spec = source(
        adapter=adapter,
        purpose=purpose,
        time_mode=time_mode,
        max_tier="observe",
        window_hours=24 if time_mode == "rolling" else None,
    )
    cfg = Config((spec,), Settings(attempts=1), ())
    requests = []

    def unavailable(request):
        requests.append(request)
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(unavailable)) as client:
        with pytest.raises(ConfigError, match=f"test-web.*{field}"):
            pipeline.run_once(
                cfg, tmp_path / "state", tmp_path / "site", client, NOW, "invalid", bootstrap=True
            )
    assert requests == []
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "site").exists()


def test_stale_feodo_cannot_be_redeclared_as_fresh_web_observation(tmp_path):
    spec = source(
        adapter="feodo", purpose="web", time_mode="unknown", max_tier="observe", category="c2"
    )
    cfg = Config((spec,), Settings(attempts=1), ())
    raw = (Path(__file__).parent / "fixtures/feodo/valid.txt").read_bytes()
    raw = raw.replace(b"192.0.2.1", b"8.8.8.8")
    requests = []

    def stale_feodo(request):
        requests.append(request)
        return httpx.Response(200, content=raw)

    with httpx.Client(transport=httpx.MockTransport(stale_feodo)) as client:
        with pytest.raises(ConfigError, match="test-web.*purpose"):
            pipeline.run_once(
                cfg, tmp_path / "state", tmp_path / "site", client, NOW, "stale", bootstrap=True
            )
    assert requests == []
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "site").exists()


@pytest.mark.parametrize("purpose", ["network", "c2"])
def test_failed_download_cannot_reclassify_persisted_web_evidence(tmp_path, purpose):
    spec = source(time_mode="unknown", max_tier="observe")
    cfg = Config((spec,), Settings(attempts=1), ())
    state_dir, first, next_output = tmp_path / "state", tmp_path / "first", tmp_path / "next"
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"8.8.8.8\n"))
    ) as client:
        saved = pipeline.run_once(cfg, state_dir, first, client, NOW, "first", bootstrap=True)
    assert (first / "lists/observe-ipv4.txt").read_bytes() == b"8.8.8.8\n"
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    changed = replace(cfg, sources=(replace(spec, purpose=purpose),))
    requests = []

    def unavailable(request):
        requests.append(request)
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(unavailable)) as client:
        with pytest.raises(ConfigError, match="test-web.*purpose"):
            pipeline.run_once(changed, state_dir, next_output, client, NOW, "changed-purpose")
    assert requests == []
    assert not next_output.exists()
    assert load_state(state_dir) == saved
    assert before == {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize(
    "relationship",
    [
        "state_inside_output",
        "output_inside_state",
        "same",
        "symlink_alias",
    ],
)
def test_overlapping_state_and_output_paths_rejected_before_download(tmp_path, relationship):
    cfg = integration_config(tmp_path)
    output = tmp_path / "site"
    state_dir = output / "state"
    if relationship == "output_inside_state":
        state_dir = tmp_path / "state"
        output = state_dir / "site"
    elif relationship == "same":
        state_dir = output
    elif relationship == "symlink_alias":
        alias = tmp_path / "alias"
        alias.symlink_to(output, target_is_directory=True)
        state_dir = alias / "state"

    def forbidden(request):
        pytest.fail("overlapping paths reached download")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(ValueError, match="overlap"):
            pipeline.run_once(cfg, state_dir, output, client, NOW, "overlap", bootstrap=True)
    assert not output.exists()
    assert not state_dir.exists()


@pytest.mark.parametrize("rule", ["8.8.8.8/24", "2001:4860::8888/32"])
def test_programmatic_host_bit_allowlist_rejected_before_collection(tmp_path, rule):
    cfg = replace(integration_config(tmp_path), allowlist=(rule,))

    def forbidden(request):
        pytest.fail("host-bit allowlist reached collection")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(ConfigError, match="allowlist"):
            pipeline.run_once(
                cfg,
                tmp_path / "state",
                tmp_path / "site",
                client,
                NOW,
                "invalid-allowlist",
                bootstrap=True,
            )
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "site").exists()


def test_loaded_host_bit_allowlist_is_normalized_before_pipeline(tmp_path):
    integration_config(tmp_path)
    folder = tmp_path / "synthetic-config"
    (folder / "allowlist.txt").write_text("8.8.8.8/24\n2001:4860::8888/32\n")
    cfg = load_config_dir(folder)
    assert cfg.allowlist == ("8.8.8.0/24", "2001:4860::/32")
    with httpx.Client(transport=httpx.MockTransport(feed_response)) as client:
        pipeline.run_once(
            cfg,
            tmp_path / "state",
            tmp_path / "site",
            client,
            NOW,
            "normalized-allowlist",
            bootstrap=True,
        )
    assert (tmp_path / "site/lists/observe-ipv4.txt").read_bytes() == b""
    network_lines = (tmp_path / "site/lists/network-ipv4.txt").read_text().splitlines()
    assert [line for line in network_lines if not line.startswith("#")] == []
    assert (tmp_path / "site/lists/c2-ipv4.txt").read_text() == "1.1.1.1\n"
