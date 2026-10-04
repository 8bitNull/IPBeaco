"""State persistence integration tests; Git transport is confined to local remotes."""

import subprocess
from datetime import timedelta

import pytest

from ipbeaco import git_store
from ipbeaco.models import RunRecord, State, StateError
from ipbeaco.state import load_state, save_state
from tests.factories import NOW


def git(directory, *args, input=None):
    return (
        subprocess.run(
            ["git", "-C", str(directory), *args], input=input, capture_output=True, check=True
        )
        .stdout.decode()
        .strip()
    )


@pytest.fixture
def local_remote(tmp_path, monkeypatch):
    # No global identity or project Git settings are touched.
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    git(checkout, "init", "--initial-branch=main")
    git(checkout, "config", "user.name", "State Test")
    git(checkout, "config", "user.email", "state-test@example.invalid")
    remote = tmp_path / "remote.git"
    remote.mkdir()
    git(remote, "init", "--bare", "--initial-branch=main")
    git(checkout, "remote", "add", "origin", "../remote.git")
    monkeypatch.chdir(checkout)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    return remote, checkout


def initial_state(tmp_path):
    folder = tmp_path / "state"
    save_state(State(), folder)
    return folder


def tip(remote):
    return git(remote, "rev-parse", "refs/heads/data")


def test_absent_branch_requires_explicit_bootstrap(tmp_path, local_remote):
    remote, _ = local_remote
    with pytest.raises(StateError, match="bootstrap"):
        git_store.pull_state(str(remote), tmp_path / "missing")
    assert not (tmp_path / "missing").exists()
    assert git_store.pull_state(str(remote), tmp_path / "fresh", bootstrap=True) is None
    assert load_state(tmp_path / "fresh") == State()


def test_round_trip_isolated_tree_and_exact_parent(tmp_path, local_remote):
    remote, _ = local_remote
    folder = initial_state(tmp_path)
    (folder / "token.txt").write_text("secret")
    first = git_store.push_state("origin", folder, None)
    assert git(remote, "ls-tree", "--name-only", first).splitlines() == [
        "state.json",
        "state.sha256",
    ]
    assert git(remote, "rev-list", "--parents", "-n", "1", first) == first
    assert git_store.pull_state("origin", tmp_path / "pulled") == first
    assert load_state(tmp_path / "pulled") == State()
    updated = State(history=(RunRecord("next", NOW),))
    save_state(updated, folder)
    second = git_store.push_state("origin", folder, first)
    assert git(remote, "rev-list", "--parents", "-n", "1", second) == f"{second} {first}"
    assert git_store.pull_state("origin", tmp_path / "pulled", bootstrap=True) == second
    assert load_state(tmp_path / "pulled") == updated


def test_relative_origin_from_checkout_subdirectory(tmp_path, local_remote, monkeypatch):
    remote, checkout = local_remote
    child = checkout / "nested"
    child.mkdir()
    monkeypatch.chdir(child)
    first = git_store.push_state("origin", initial_state(tmp_path), None)
    assert tip(remote) == first


def test_unreachable_remote_never_bootstraps(tmp_path, local_remote):
    with pytest.raises(StateError, match="Git"):
        git_store.pull_state(str(tmp_path / "nonexistent.git"), tmp_path / "state", bootstrap=True)
    assert not (tmp_path / "state").exists()


def test_checksum_failure_never_updates_remote(tmp_path, local_remote):
    remote, _ = local_remote
    folder = initial_state(tmp_path)
    first = git_store.push_state("origin", folder, None)
    (folder / "state.json").write_text("{}")
    with pytest.raises(StateError, match="checksum"):
        git_store.push_state("origin", folder, first)
    assert tip(remote) == first


def test_corrupt_remote_is_rejected_before_local_replacement(tmp_path, local_remote):
    remote, checkout = local_remote
    folder = initial_state(tmp_path)
    first = git_store.push_state("origin", folder, None)
    git(checkout, "fetch", str(remote), first)
    blob = git(checkout, "hash-object", "-w", "--stdin", input=b"{}")
    tree = git(checkout, "mktree", input=f"100644 blob {blob}\tstate.json\n".encode())
    bad = git(checkout, "commit-tree", tree, "-p", first, "-m", "corrupt")
    git(checkout, "push", str(remote), f"{bad}:refs/heads/data")
    before = (folder / "state.json").read_bytes()
    with pytest.raises(StateError):
        git_store.pull_state("origin", folder, bootstrap=True)
    assert (folder / "state.json").read_bytes() == before


def test_stale_writer_and_existing_branch_bootstrap_refused(tmp_path, local_remote):
    remote, _ = local_remote
    folder = initial_state(tmp_path)
    first = git_store.push_state("origin", folder, None)
    save_state(State(history=(RunRecord("winner", NOW),)), folder)
    winner = git_store.push_state("origin", folder, first)
    for parent in (first, None):
        with pytest.raises(StateError, match="changed|concurrent"):
            git_store.push_state("origin", folder, parent)
        assert tip(remote) == winner


@pytest.mark.parametrize("bootstrap", [True, False])
def test_competing_writer_between_preflight_and_push_is_rejected(
    tmp_path, local_remote, monkeypatch, bootstrap
):
    remote, checkout = local_remote
    folder = initial_state(tmp_path)
    parent = None if bootstrap else git_store.push_state("origin", folder, None)
    other = tmp_path / "other"
    save_state(State(history=(RunRecord("winner", NOW + timedelta(seconds=1)),)), other)
    real_run = subprocess.run
    winner = None

    def race(command, **kwargs):
        nonlocal winner
        if "push" in command and winner is None:
            monkeypatch.setattr(subprocess, "run", real_run)
            winner = git_store.push_state(str(remote), other, parent)
            monkeypatch.setattr(subprocess, "run", race)
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", race)
    with pytest.raises(StateError, match="Git|concurrent"):
        git_store.push_state(str(remote), folder, parent)
    assert winner is not None
    assert tip(remote) == winner


@pytest.mark.parametrize("parent", ["--help", "deadbeef", "a" * 40 + "\n", 123])
def test_invalid_revision_is_rejected(tmp_path, local_remote, parent):
    with pytest.raises(StateError, match="revision"):
        git_store.push_state("origin", initial_state(tmp_path), parent)


def test_git_diagnostics_never_expose_credentials(tmp_path, monkeypatch):
    def failure(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 128, b"", b"fatal https://user:SECRET@example.invalid Authorization: SECRET"
        )

    monkeypatch.setattr(subprocess, "run", failure)
    with pytest.raises(StateError) as error:
        git_store.pull_state("https://user:SECRET@example.invalid/repo.git", tmp_path / "state")
    assert "SECRET" not in str(error.value)
    assert "example.invalid" not in str(error.value)


def test_checkout_auth_is_scoped_to_calls_and_never_saved(tmp_path, local_remote, monkeypatch):
    remote, checkout = local_remote
    git(checkout, "config", "http.https://github.com/.extraheader", "AUTHORIZATION: test-secret")
    actual_run = subprocess.run
    observed = []

    def inspect(command, **kwargs):
        if "push" in command or "ls-remote" in command:
            env = kwargs.get("env", {})
            observed.append(any(value == "AUTHORIZATION: test-secret" for value in env.values()))
        return actual_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", inspect)
    first = git_store.push_state("origin", initial_state(tmp_path), None)
    assert observed and all(observed)
    assert "test-secret" not in git(remote, "show", f"{first}:state.json")
    assert git(remote, "ls-tree", "--name-only", first).splitlines() == [
        "state.json",
        "state.sha256",
    ]


def test_actions_bot_identity_is_scoped(tmp_path, local_remote, monkeypatch):
    remote, checkout = local_remote
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    first = git_store.push_state("origin", initial_state(tmp_path), None)
    assert git(remote, "show", "-s", "--format=%an <%ae>|%cn <%ce>", first) == (
        "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>|"
        "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
    )
    assert git(checkout, "config", "user.name") == "State Test"


def test_checkout_auth_include_file_is_applied_to_git_calls(tmp_path, local_remote, monkeypatch):
    _, checkout = local_remote
    auth = tmp_path / "runner-auth.config"
    auth.write_text(
        '[http "https://github.com/"]\n\textraheader = AUTHORIZATION: included-secret\n'
    )
    git(checkout, "config", "include.path", str(auth))
    actual_run = subprocess.run
    seen = []

    def inspect(command, **kwargs):
        if "push" in command or "ls-remote" in command:
            env = kwargs.get("env", {})
            seen.append(any(value == "AUTHORIZATION: included-secret" for value in env.values()))
        return actual_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", inspect)
    git_store.push_state("origin", initial_state(tmp_path), None)
    assert seen and all(seen)


def test_checkout_auth_header_is_not_applied_twice(tmp_path, local_remote, monkeypatch):
    _, checkout = local_remote
    key = "http.https://github.com/.extraheader"
    git(checkout, "config", key, "AUTHORIZATION: single-header")
    real_run = subprocess.run
    applied = []

    def inspect(command, **kwargs):
        if "ls-remote" in command:
            prefix = command[: command.index("ls-remote")]
            result = real_run(
                [*prefix, "config", "--get-all", key],
                env=kwargs.get("env"),
                capture_output=True,
                check=True,
            )
            applied.append(result.stdout.decode().splitlines())
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", inspect)
    git_store.push_state("origin", initial_state(tmp_path), None)
    assert applied == [["AUTHORIZATION: single-header"]]
