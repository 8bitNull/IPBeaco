"""State files must preserve evidence and fail closed on damage."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from ipbeaco.models import Evidence, Presence, RunRecord, SourceState, State, StateError
from ipbeaco.state import decode_state, encode_state, load_state, save_state


@pytest.fixture
def populated():
    now = datetime(2026, 10, 4, 8, 17, tzinfo=timezone(timedelta(hours=8)))
    return State(
        evidence=(
            Evidence(
                "feed",
                "192.0.2.1",
                "扫描",
                now,
                now,
                None,
                "observed",
                now + timedelta(hours=72),
                now + timedelta(days=7),
                now + timedelta(days=7),
            ),
        ),
        presence={
            "feed": {
                "192.0.2.1": Presence(now, True),
                "192.0.2.2": Presence(now - timedelta(days=400), False),
            }
        },
        sources={
            "feed": SourceState(
                now, now, "ok", now, now + timedelta(hours=48), 1, "a" * 64, ("notice",), None
            )
        },
        history=(RunRecord("build", now),),
    )


def test_complete_roundtrip_and_canonical_encoding(populated, tmp_path):
    raw = encode_state(populated)
    assert decode_state(raw) == populated
    assert raw.endswith(b"\n")
    assert b"2026-10-04T00:17:00+00:00" in raw
    assert "扫描" in raw.decode()
    assert encode_state(decode_state(raw)) == raw
    save_state(populated, tmp_path)
    assert load_state(tmp_path) == populated
    assert (tmp_path / "state.sha256").read_text() == hashlib.sha256(raw).hexdigest() + "\n"


def test_missing_state_requires_explicit_bootstrap(tmp_path):
    with pytest.raises(StateError):
        load_state(tmp_path)
    assert load_state(tmp_path, bootstrap=True) == State()


@pytest.mark.parametrize("missing", ["state.json", "state.sha256"])
def test_partial_pair_never_bootstraps(tmp_path, missing):
    save_state(State(), tmp_path)
    (tmp_path / missing).unlink()
    with pytest.raises(StateError):
        load_state(tmp_path, bootstrap=True)


@pytest.mark.parametrize("contents", [b"{broken", b"", b"{}", b"\xff"])
def test_corruption_never_becomes_empty_state(tmp_path, contents):
    save_state(State(), tmp_path)
    (tmp_path / "state.json").write_bytes(contents)
    with pytest.raises(StateError):
        load_state(tmp_path, bootstrap=True)


@pytest.mark.parametrize("checksum", ["0" * 64 + "\n", "bad", "", "a" * 64 + "\nextra"])
def test_invalid_digest_rejected(tmp_path, checksum):
    save_state(State(), tmp_path)
    (tmp_path / "state.sha256").write_text(checksum)
    with pytest.raises(StateError):
        load_state(tmp_path)


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), 2),
        (("schema_version",), True),
        (("extra",), 1),
        (("evidence",), {}),
        (("presence",), []),
        (("sources", "feed", "accepted_count"), True),
        (("sources", "feed", "accepted_count"), -1),
        (("sources", "feed", "accepted_count"), 1.5),
        (("sources", "feed", "status"), "invented"),
        (("sources", "feed", "notices"), "notice"),
        (("sources", "feed", "sha256"), 5),
        (("sources", "feed", "error"), False),
        (("sources", "feed", "extra"), 1),
        (("evidence", 0, "source_id"), 5),
        (("evidence", 0, "time_basis"), "invented"),
        (("evidence", 0, "first_seen_at"), "2026-10-04T00:17:00"),
        (("evidence", 0, "observed_at"), "2026-10-04"),
        (("evidence", 0, "expires_at"), None),
        (("evidence", 0, "extra"), 1),
        (("presence", "feed", "192.0.2.1", "present"), 1),
        (("presence", "feed", "192.0.2.1", "extra"), 1),
        (("history", 0, "build_id"), False),
        (("history", 0, "generated_at"), "not a time"),
        (("history", 0, "extra"), 1),
    ],
)
def test_rejects_invalid_schema_fields(populated, path, value):
    document = json.loads(encode_state(populated))
    parent = document
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(StateError):
        decode_state(json.dumps(document).encode())


@pytest.mark.parametrize("section", [None, "evidence", "sources", "presence", "history"])
def test_missing_required_fields_rejected(populated, section):
    document = json.loads(encode_state(populated))
    if section is None:
        del document["history"]
    elif section == "evidence":
        del document[section][0]["observed_at"]
    elif section == "sources":
        del document[section]["feed"]["error"]
    elif section == "presence":
        del document[section]["feed"]["192.0.2.1"]["present"]
    else:
        del document[section][0]["generated_at"]
    with pytest.raises(StateError):
        decode_state(json.dumps(document).encode())


@pytest.mark.parametrize(
    "field,replacement",
    [
        ('"schema_version":1', '"schema_version":1,"schema_version":1'),
        ('"present":true', '"present":true,"present":true'),
        ('"accepted_count":1', '"accepted_count":1,"accepted_count":1'),
        ('"accepted_count":1', '"accepted_count":NaN'),
    ],
)
def test_duplicate_keys_and_non_json_constants_rejected(populated, field, replacement):
    raw = encode_state(populated).decode().replace(field, replacement, 1).encode()
    with pytest.raises(StateError):
        decode_state(raw)


def test_second_replace_failure_leaves_detectable_mismatch(populated, tmp_path, monkeypatch):
    import ipbeaco.state as module

    save_state(State(), tmp_path)
    replace = module.os.replace
    calls = 0

    def interrupt(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated power loss")
        replace(source, destination)

    monkeypatch.setattr(module.os, "replace", interrupt)
    with pytest.raises(StateError):
        save_state(populated, tmp_path)
    with pytest.raises(StateError):
        load_state(tmp_path, bootstrap=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json", "state.sha256"]


def test_encoding_rejects_invalid_model_types():
    with pytest.raises(StateError):
        encode_state(State(schema_version=True))


@pytest.mark.parametrize("inspection_error", [PermissionError, OSError])
def test_inaccessible_existing_pair_never_bootstraps(tmp_path, monkeypatch, inspection_error):
    import ipbeaco.state as module

    save_state(State(), tmp_path)

    def inaccessible(path, *args, **kwargs):
        raise inspection_error("inaccessible existing state pair")

    monkeypatch.setattr(module.os, "lstat", inaccessible)
    with pytest.raises(StateError, match="inaccessible existing state pair"):
        load_state(tmp_path, bootstrap=True)


@pytest.mark.parametrize("filename", ["state.json", "state.sha256"])
def test_broken_symlink_never_bootstraps(tmp_path, filename):
    (tmp_path / filename).symlink_to(tmp_path / "missing-target")
    with pytest.raises(StateError):
        load_state(tmp_path, bootstrap=True)
