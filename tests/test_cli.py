import json
import shutil
from datetime import timedelta

import httpx
import pytest

from ipbeaco import cli, pipeline
from ipbeaco.models import StateError
from tests.factories import NOW
from tests.test_git_store import local_remote  # noqa: F401
from tests.test_pipeline import FIXTURES, feed_response


@pytest.fixture
def setup_cli(tmp_path, monkeypatch):
    folder = tmp_path / "arbitrary-config-folder"
    shutil.copytree(FIXTURES, folder)
    real_client = httpx.Client
    monkeypatch.setattr(cli, "utc_now", lambda: NOW)
    monkeypatch.setattr(
        cli, "http_client", lambda: real_client(transport=httpx.MockTransport(feed_response))
    )
    return folder


def run_args(tmp_path, folder, name="site"):
    return [
        "run",
        "--config",
        str(folder),
        "--state",
        str(tmp_path / "state"),
        "--out",
        str(tmp_path / name),
        "--build-id",
        name,
        "--bootstrap",
    ]


def test_run_then_validate_returns_zero_and_prints_unavailable_summary(tmp_path, setup_cli, capsys):
    assert cli.main(run_args(tmp_path, setup_cli)) == 0
    summary = capsys.readouterr().out
    assert "unavailable" in summary and "observe-ipv4" in summary and "site" in summary
    assert cli.main(["validate", "--site", str(tmp_path / "site")]) == 0
    assert (tmp_path / "state/state.json").exists()
    assert set(p.name for p in tmp_path.iterdir()) == {"arbitrary-config-folder", "site", "state"}


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["bad-command"],
        ["run"],
        ["run", "--now", "2026-10-04"],
        ["validate", "--site", "missing", "--ignore-time"],
    ],
)
def test_argument_errors_return_two(args):
    assert cli.main(args) == 2


def test_invalid_config_returns_two(tmp_path, capsys):
    assert cli.main(run_args(tmp_path, tmp_path / "missing")) == 2
    assert capsys.readouterr().err
    assert not (tmp_path / "site").exists()


def test_state_save_failure_returns_one_without_success_summary(
    tmp_path, setup_cli, monkeypatch, capsys
):
    def fail(state, directory):
        raise StateError("injected save failure")

    monkeypatch.setattr(pipeline, "save_state", fail)
    assert cli.main(run_args(tmp_path, setup_cli)) == 1
    capture = capsys.readouterr()
    assert "injected save failure" in capture.err
    assert capture.out == ""
    assert not (tmp_path / "state").exists()
    assert (tmp_path / "site/lists/status.json").exists()


def test_existing_output_and_missing_state_return_one(tmp_path, setup_cli):
    assert cli.main(run_args(tmp_path, setup_cli)) == 0
    assert cli.main(run_args(tmp_path, setup_cli)) == 1
    args = run_args(tmp_path, setup_cli, "other")
    args[args.index("--state") + 1] = str(tmp_path / "missing-state")
    args.remove("--bootstrap")
    assert cli.main(args) == 1
    assert not (tmp_path / "other").exists()


def test_validate_uses_current_clock_to_reject_expired_nonempty(tmp_path, setup_cli, monkeypatch):
    assert cli.main(run_args(tmp_path, setup_cli)) == 0
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(days=3))
    assert cli.main(["validate", "--site", str(tmp_path / "site")]) == 1


def test_validate_rejects_expired_healthy_empty_but_accepts_diagnostic_empty(
    tmp_path, setup_cli, monkeypatch
):
    monkeypatch.setattr(
        cli,
        "http_client",
        lambda: httpx.Client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b""))
        ),
    )
    # Empty Web payload is valid; malformed network and C2 remain diagnostic errors.
    assert cli.main(run_args(tmp_path, setup_cli)) == 0
    manifest = json.loads((tmp_path / "site/lists/status.json").read_text())
    assert manifest["lists"]["observe-ipv4"]["status"] == "empty"
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(days=2))
    assert cli.main(["validate", "--site", str(tmp_path / "site")]) == 1
    monkeypatch.setattr(
        cli,
        "http_client",
        lambda: httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(404))),
    )
    assert cli.main(run_args(tmp_path, setup_cli, "diagnostic")) == 0
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(days=20))
    assert cli.main(["validate", "--site", str(tmp_path / "diagnostic")]) == 0


def test_inspect_disabled_candidate_is_read_only_and_does_not_dump_ips(tmp_path, setup_cli, capsys):
    path = setup_cli / "sources.toml"
    path.write_text(
        path.read_text()
        .replace("enabled = true", "enabled = false")
        .replace("public_approved = true", "public_approved = false")
    )
    before = {p.name: p.read_bytes() for p in setup_cli.iterdir()}
    assert cli.main(["inspect-source", "--config", str(setup_cli), "--source", "c2"]) == 0
    capture = capsys.readouterr()
    assert "1.1.1.1" not in capture.out
    details = json.loads(capture.out)
    assert details["record_count"] == 1
    assert details["generated_at"] == "2026-10-04T00:00:00+00:00"
    assert details["public_admitted"] is False
    assert details["freshness"] == "current"
    assert len(details["sha256"]) == 64
    assert before == {p.name: p.read_bytes() for p in setup_cli.iterdir()}
    assert set(p.name for p in tmp_path.iterdir()) == {"arbitrary-config-folder"}


@pytest.mark.parametrize("case", ["unknown", "download", "format", "stale", "future"])
def test_inspect_failures_return_one(tmp_path, setup_cli, monkeypatch, case):
    name = "unknown" if case == "unknown" else "c2"
    if case in {"download", "format"}:
        response = (
            httpx.Response(404) if case == "download" else httpx.Response(200, content=b"bad")
        )
        monkeypatch.setattr(
            cli,
            "http_client",
            lambda: httpx.Client(transport=httpx.MockTransport(lambda req: response)),
        )
    if case == "stale":
        monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(days=3))
    if case == "future":
        monkeypatch.setattr(cli, "utc_now", lambda: NOW - timedelta(minutes=6))
    assert cli.main(["inspect-source", "--config", str(setup_cli), "--source", name]) == 1
    assert not (tmp_path / "state").exists()


def test_inspect_unknown_time_does_not_invent_freshness(tmp_path, setup_cli, capsys):
    assert cli.main(["inspect-source", "--config", str(setup_cli), "--source", "web"]) == 0
    details = json.loads(capsys.readouterr().out)
    assert details["freshness"] == "unknown"
    assert details["valid_until"] is None
    assert details["generated_at"] is None
    assert details["record_count"] == 1


def test_production_client_verifies_tls_and_disables_redirects(monkeypatch):
    import ssl

    # Isolate TLS policy from the host's unrelated proxy exclusion syntax.
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    with cli.http_client() as client:
        context = client._transport._pool._ssl_context
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert client.follow_redirects is False


def test_invalid_client_environment_returns_one(tmp_path, setup_cli, monkeypatch):
    def invalid_client():
        raise httpx.InvalidURL("invalid client proxy configuration")

    monkeypatch.setattr(cli, "http_client", invalid_client)
    assert cli.main(run_args(tmp_path, setup_cli)) == 1
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "site").exists()


def state_args(tmp_path, action, *extra):
    return [
        "state",
        action,
        "--remote",
        "origin",
        "--dir",
        str(tmp_path / "state"),
        "--revision-file",
        str(tmp_path / "state-base.txt"),
        *extra,
    ]


@pytest.mark.usefixtures("local_remote")
def test_cli_state_bootstrap_run_push_pull_round_trip(tmp_path, setup_cli, capsys):
    from ipbeaco.state import load_state

    assert cli.main(state_args(tmp_path, "pull", "--bootstrap")) == 0
    assert (tmp_path / "state-base.txt").read_text() == "null\n"
    args = run_args(tmp_path, setup_cli)
    args.remove("--bootstrap")
    assert cli.main(args) == 0
    generated = load_state(tmp_path / "state")
    assert cli.main(state_args(tmp_path, "push")) == 0
    revision = (tmp_path / "state-base.txt").read_text().strip()
    assert len(revision) == 40
    shutil.rmtree(tmp_path / "state")
    assert cli.main(state_args(tmp_path, "pull")) == 0
    assert (tmp_path / "state-base.txt").read_text().strip() == revision
    assert load_state(tmp_path / "state") == generated
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "revision", [None, "garbage", "--all", '"' + "a" * 40 + '"', "a" * 40 + "\nextra"]
)
@pytest.mark.usefixtures("local_remote")
def test_cli_state_push_rejects_missing_or_invalid_revision(tmp_path, revision, capsys):
    from ipbeaco.models import State
    from ipbeaco.state import save_state

    save_state(State(), tmp_path / "state")
    if revision is not None:
        (tmp_path / "state-base.txt").write_text(revision)
    assert cli.main(state_args(tmp_path, "push")) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.usefixtures("local_remote")
def test_cli_pull_failure_leaves_revision_file_untouched(tmp_path):
    (tmp_path / "state-base.txt").write_text("prior revision\n")
    assert cli.main(state_args(tmp_path, "pull")) == 1
    assert (tmp_path / "state-base.txt").read_text() == "prior revision\n"


@pytest.mark.usefixtures("local_remote")
def test_cli_revision_file_cannot_overwrite_state_pair(tmp_path):
    from ipbeaco.models import State
    from ipbeaco.state import load_state, save_state

    save_state(State(), tmp_path / "state")
    args = state_args(tmp_path, "pull", "--bootstrap")
    args[args.index("--revision-file") + 1] = str(tmp_path / "state/state.json")
    assert cli.main(args) == 1
    assert load_state(tmp_path / "state") == State()


@pytest.mark.usefixtures("local_remote")
def test_failed_deployment_retry_rejects_expired_artifact_and_rebuilds_committed_state(
    tmp_path, setup_cli, request, monkeypatch, capsys
):
    from ipbeaco.state import load_state
    from tests.test_git_store import git

    remote, _ = request.getfixturevalue("local_remote")
    assert cli.main(state_args(tmp_path, "pull", "--bootstrap")) == 0
    args = run_args(tmp_path, setup_cli)
    args.remove("--bootstrap")
    assert cli.main(args) == 0
    assert cli.main(state_args(tmp_path, "push")) == 0
    first_revision = (tmp_path / "state-base.txt").read_text().strip()
    assert git(remote, "rev-parse", "refs/heads/data") == first_revision
    assert cli.main(["validate", "--site", str(tmp_path / "site")]) == 0
    assert (tmp_path / "site/lists/observe-ipv4.txt").read_text() == "8.8.8.8\n"
    old_artifact = {
        str(p.relative_to(tmp_path / "site")): p.read_bytes()
        for p in (tmp_path / "site").rglob("*")
        if p.is_file()
    }

    # Model a failed external deployment by leaving its committed state and
    # artifact in place. A fresh runner restores the state from the real remote.
    saved = load_state(tmp_path / "state")
    shutil.rmtree(tmp_path / "state")
    monkeypatch.setattr(cli, "utc_now", lambda: NOW + timedelta(days=8))
    assert cli.main(state_args(tmp_path, "pull")) == 0
    assert load_state(tmp_path / "state") == saved
    assert cli.main(["validate", "--site", str(tmp_path / "site")]) == 1
    assert git(remote, "rev-parse", "refs/heads/data") == first_revision
    assert "Run error:" in capsys.readouterr().err

    # A full rerun must prune expired evidence even while upstream is down.
    monkeypatch.setattr(
        cli,
        "http_client",
        lambda: httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(404))),
    )
    args = run_args(tmp_path, setup_cli, "retry")
    args.remove("--bootstrap")
    assert cli.main(args) == 0
    assert cli.main(state_args(tmp_path, "push")) == 0
    second_revision = (tmp_path / "state-base.txt").read_text().strip()
    assert second_revision != first_revision
    assert git(remote, "rev-list", "--parents", "-n", "1", second_revision) == (
        f"{second_revision} {first_revision}"
    )
    assert cli.main(["validate", "--site", str(tmp_path / "retry")]) == 0
    lists = tuple((tmp_path / "retry/lists").glob("*.txt"))
    assert len(lists) == 8
    assert all(path.read_bytes() == b"" for path in lists)
    rebuilt = load_state(tmp_path / "state")
    assert rebuilt.evidence == ()
    assert rebuilt.presence["web"]["8.8.8.8"].present
    assert rebuilt.history[-1].build_id == "retry"
    assert old_artifact == {
        str(p.relative_to(tmp_path / "site")): p.read_bytes()
        for p in (tmp_path / "site").rglob("*")
        if p.is_file()
    }
    shutil.rmtree(tmp_path / "state")
    assert cli.main(state_args(tmp_path, "pull")) == 0
    assert load_state(tmp_path / "state") == rebuilt
    assert capsys.readouterr().err == ""
