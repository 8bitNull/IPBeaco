"""Verified state on an isolated data branch, with ordinary non-force pushes.

Writers compare the exact advertised parent before pushing. Normal concurrent
writers then fail Git's fast-forward check. Operators must prohibit deleting or
force-rewinding data: ordinary push cannot provide atomic CAS against such edits.
"""

import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

from ipbeaco.models import State, StateError
from ipbeaco.state import load_state, save_state

_FILES = ("state.json", "state.sha256")
_REF = "refs/heads/data"
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def validate_revision(value: str | None) -> None:
    """Allow only full hexadecimal object IDs, or the explicit initial null."""
    if value is not None and (type(value) is not str or _OID.fullmatch(value) is None):
        raise StateError("Invalid state revision; expected a full commit ID or null")


def _git(*args: str, env=None, input=None, allowed=(0,)):
    # Git diagnostics can contain URLs, credentials, and auth headers. Discard
    # them entirely; never include command arguments or subprocess exceptions.
    try:
        result = subprocess.run(
            ["git", *args], env=env, input=input, capture_output=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        raise StateError("Git operation failed; check remote access and configuration") from None
    if result.returncode not in allowed:
        raise StateError("Git operation failed; check remote access or concurrent data updates")
    return result


def _context(remote: str) -> tuple[str, dict[str, str]]:
    if type(remote) is not str or not remote or remote.startswith("-") or "\x00" in remote:
        raise StateError("Invalid Git remote")
    env = os.environ.copy()
    # Copy only checkout-local HTTPS/credential settings and local identity to
    # call-scoped environment configuration, never to temporary config files.
    settings = _git(
        "config",
        "--local",
        "--includes",
        "--null",
        "--get-regexp",
        r"^(http\..*|credential\..*|user\.name|user\.email)$",
        allowed=(0, 1, 128),
    )
    try:
        count = int(env.get("GIT_CONFIG_COUNT", "0"))
        if count < 0:
            raise ValueError
        if settings.returncode == 0:
            for record in settings.stdout.split(b"\x00"):
                if not record:
                    continue
                key, value = record.decode("utf-8").split("\n", 1)
                env[f"GIT_CONFIG_KEY_{count}"] = key
                env[f"GIT_CONFIG_VALUE_{count}"] = value
                count += 1
        env["GIT_CONFIG_COUNT"] = str(count)
    except (ValueError, UnicodeError):
        raise StateError("Invalid Git authentication configuration") from None

    named = _git("remote", "get-url", remote, allowed=(0, 2, 128))
    base = Path.cwd()
    if named.returncode == 0:
        try:
            remote = named.stdout.decode("utf-8").strip()
            root = _git("rev-parse", "--show-toplevel")
            base = Path(root.stdout.decode("utf-8").strip())
        except UnicodeError:
            raise StateError("Invalid Git remote configuration") from None
    if not remote or remote.startswith("-") or "\x00" in remote:
        raise StateError("Invalid Git remote")
    # Schemes and scp-style SSH locations are remote addresses. All other
    # locations must remain anchored to the original checkout, not the temp repo.
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", remote) and ":" not in remote:
        path = Path(remote).expanduser()
        remote = str(path if path.is_absolute() else (base / path).resolve())
    return remote, env


def _remote_tip(remote: str, env) -> str | None:
    # Avoid reading checkout-local auth a second time after copying it into env:
    # extraheader is multi-valued, so a duplicate Authorization header can fail.
    with tempfile.TemporaryDirectory(prefix="ipbeaco-remote-") as temporary:
        result = _git(
            "-C", temporary, "ls-remote", "--exit-code", remote, _REF, env=env, allowed=(0, 2)
        )
    if result.returncode == 2:
        return None
    try:
        revision, ref = result.stdout.decode("ascii").strip().split("\t")
    except (ValueError, UnicodeError):
        raise StateError("Invalid Git data branch response") from None
    validate_revision(revision)
    if ref != _REF:
        raise StateError("Invalid Git data branch response")
    return revision


def _init(workdir: Path, revision: str | None, env) -> None:
    format_name = "sha256" if revision is not None and len(revision) == 64 else "sha1"
    _git("init", "--bare", f"--object-format={format_name}", str(workdir), env=env)


def _fetch(workdir: Path, remote: str, revision: str, env) -> None:
    _git(
        "-C", str(workdir), "fetch", "--no-tags", "--no-write-fetch-head", remote, revision, env=env
    )
    resolved = _git("-C", str(workdir), "rev-parse", f"{revision}^{{commit}}", env=env)
    if resolved.stdout.decode("ascii").strip() != revision:
        raise StateError("Data revision is not a commit")


def _verified_pair(directory: Path, staging: Path) -> State:
    try:
        staging.mkdir()
        for name in _FILES:
            (staging / name).write_bytes((directory / name).read_bytes())
    except OSError:
        raise StateError("Cannot read the complete state file pair") from None
    return load_state(staging)


def pull_state(remote: str, directory: Path, *, bootstrap: bool = False) -> str | None:
    """Export and verify the exact advertised data commit before replacing state."""
    remote, env = _context(remote)
    revision = _remote_tip(remote, env)
    if revision is None:
        if not bootstrap:
            raise StateError("Data branch is absent; explicit bootstrap is required")
        save_state(State(), directory)
        return None
    with tempfile.TemporaryDirectory(prefix="ipbeaco-state-") as temporary:
        workdir = Path(temporary) / "objects.git"
        _init(workdir, revision, env)
        _fetch(workdir, remote, revision, env)
        entries = _git("-C", str(workdir), "ls-tree", "-z", revision, env=env).stdout
        rows = entries.split(b"\x00")[:-1]
        if len(rows) != 2 or any(
            not re.fullmatch(rb"100644 blob [0-9a-f]+\t" + name.encode(), row)
            for name, row in zip(_FILES, rows, strict=False)
        ):
            raise StateError("Data branch must contain only the two regular state files")
        staging = Path(temporary) / "state"
        staging.mkdir()
        for name in _FILES:
            raw = _git("-C", str(workdir), "show", f"{revision}:{name}", env=env).stdout
            (staging / name).write_bytes(raw)
        state = load_state(staging)
        save_state(state, directory)
    return revision


def push_state(remote: str, directory: Path, expected_parent: str | None) -> str:
    """Commit a verified pair with the exact parent and push without force/rebase."""
    validate_revision(expected_parent)
    with tempfile.TemporaryDirectory(prefix="ipbeaco-state-") as temporary:
        staging = Path(temporary) / "state"
        _verified_pair(directory, staging)
        remote, env = _context(remote)
        if _remote_tip(remote, env) != expected_parent:
            raise StateError("Data branch changed; discard this candidate and pull again")
        workdir = Path(temporary) / "objects.git"
        _init(workdir, expected_parent, env)
        if expected_parent is not None:
            _fetch(workdir, remote, expected_parent, env)
        rows = []
        for name in _FILES:
            blob = _git(
                "-C",
                str(workdir),
                "hash-object",
                "-w",
                "--stdin",
                env=env,
                input=(staging / name).read_bytes(),
            ).stdout.strip()
            rows.append(b"100644 blob " + blob + b"\t" + name.encode() + b"\n")
        tree = _git("-C", str(workdir), "mktree", env=env, input=b"".join(rows)).stdout
        parent = ["-p", expected_parent] if expected_parent is not None else []
        commit_env = env.copy()
        if os.environ.get("GITHUB_ACTIONS") == "true":
            for role in ("AUTHOR", "COMMITTER"):
                commit_env[f"GIT_{role}_NAME"] = "github-actions[bot]"
                commit_env[f"GIT_{role}_EMAIL"] = (
                    "41898282+github-actions[bot]@users.noreply.github.com"
                )
        # Distinct root candidates must conflict even when their state and
        # second-resolution Git timestamps happen to be identical.
        message = f"Persist IPBeaco state\n\nTransaction: {uuid.uuid4()}\n".encode()
        commit = (
            _git(
                "-C",
                str(workdir),
                "commit-tree",
                tree.decode("ascii").strip(),
                *parent,
                env=commit_env,
                input=message,
            )
            .stdout.decode("ascii")
            .strip()
        )
        validate_revision(commit)
        _git("-C", str(workdir), "push", remote, f"{commit}:{_REF}", env=env)
        return commit
