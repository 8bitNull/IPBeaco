"""Local generation, current-time validation, and read-only source diagnostics."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ipbeaco.adapters import PARSERS
from ipbeaco.config import load_config_dir
from ipbeaco.export import validate_site
from ipbeaco.fetch import download
from ipbeaco.git_store import pull_state, push_state
from ipbeaco.models import Config, ConfigError, SourceError, StateError
from ipbeaco.pipeline import run_once
from ipbeaco.state import _atomic_write
from ipbeaco.temporal import _deadline, _evidence, _normalized_records


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def http_client() -> httpx.Client:
    """Keep HTTPX's production TLS verification and disable redirect following."""
    return httpx.Client(follow_redirects=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ipbeaco")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Generate and validate a new local site")
    run.add_argument("--config", type=Path, required=True, help="Configuration directory")
    run.add_argument("--state", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--build-id", required=True)
    run.add_argument("--bootstrap", action="store_true")
    validate = commands.add_parser("validate", help="Validate a site at the current time")
    validate.add_argument("--site", type=Path, required=True)
    inspect = commands.add_parser("inspect-source", help="Read-only format and freshness check")
    inspect.add_argument("--config", type=Path, required=True, help="Configuration directory")
    inspect.add_argument("--source", required=True)
    state = commands.add_parser("state", help="Pull or push the isolated data branch")
    state_commands = state.add_subparsers(dest="state_action", required=True)
    for action in ("pull", "push"):
        command = state_commands.add_parser(action)
        command.add_argument("--remote", required=True)
        command.add_argument("--dir", type=Path, required=True)
        command.add_argument("--revision-file", type=Path, required=True)
        if action == "pull":
            command.add_argument("--bootstrap", action="store_true")
    return parser


def _inspect(config: Config, source_id: str, now: datetime, client: httpx.Client) -> None:
    spec = next((source for source in config.sources if source.id == source_id), None)
    if spec is None:
        raise SourceError("unknown_source")
    snapshot = PARSERS[spec.adapter](download(spec.url, config.settings, client), spec, now)
    # Reuse the exact temporal checks without enabling the source or creating state.
    records, _ = _normalized_records(spec, snapshot, config.settings, now)
    deadline = _deadline(spec, snapshot, config.settings, now, empty=not records)
    if deadline is not None and now >= deadline:
        raise SourceError("stale_snapshot")
    active = [
        _evidence(spec, record, snapshot, config.settings, now, deadline)
        for record in records.values()
    ]
    active = [item for item in active if now < item.expires_at]
    if records and not active:
        raise SourceError("stale_snapshot")
    if active:
        deadline = min(item.expires_at for item in active)
    unknown_time = spec.time_mode == "unknown" or (
        snapshot.generated_at is None
        and not any(record.observed_at is not None for record in records.values())
    )
    if unknown_time:
        deadline = None
    print(
        json.dumps(
            {
                "source_id": spec.id,
                "record_count": len(snapshot.records),
                "accepted_count": len(active),
                "fetched_at": snapshot.fetched_at.isoformat(),
                "generated_at": snapshot.generated_at.isoformat()
                if snapshot.generated_at
                else None,
                "valid_until": deadline.isoformat() if deadline else None,
                "sha256": snapshot.sha256,
                "freshness": "unknown" if unknown_time else "current",
                "public_admitted": spec.enabled and spec.public_approved,
            },
            sort_keys=True,
        )
    )


def _state_command(args) -> None:
    if args.revision_file.resolve() in {
        (args.dir / "state.json").resolve(),
        (args.dir / "state.sha256").resolve(),
    }:
        raise StateError("Revision file must be separate from the state file pair")
    if args.state_action == "pull":
        revision = pull_state(args.remote, args.dir, bootstrap=args.bootstrap)
    else:
        raw = args.revision_file.read_text(encoding="ascii")
        if re.fullmatch(r"(?:null|[0-9a-f]{40}|[0-9a-f]{64})\n?", raw) is None:
            raise StateError("Invalid state revision file; pull state again")
        value = raw.removesuffix("\n")
        revision = push_state(args.remote, args.dir, None if value == "null" else value)
    args.revision_file.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(args.revision_file, ((revision or "null") + "\n").encode("ascii"))
    print(f"State {args.state_action} completed")


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    try:
        if args.command == "state":
            _state_command(args)
            return 0
        now = utc_now()
        if args.command == "validate":
            validate_site(args.site, now)
            print(f"Validated: {args.site}")
            return 0
        config = load_config_dir(args.config)
        with http_client() as client:
            if args.command == "inspect-source":
                _inspect(config, args.source, now, client)
                return 0
            run_once(
                config, args.state, args.out, client, now, args.build_id, bootstrap=args.bootstrap
            )
        manifest = json.loads((args.out / "lists/status.json").read_text(encoding="utf-8"))
        summary = ", ".join(
            f"{key}={row['status']}({row['count']})"
            for key, row in sorted(manifest["lists"].items())
        )
        print(f"Generated and validated {args.build_id}: {args.out}; {summary}")
        return 0
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    except (httpx.HTTPError, httpx.InvalidURL):
        print("HTTP client error: invalid client configuration or request", file=sys.stderr)
        return 1
    except (StateError, SourceError, OSError, ValueError) as error:
        print(f"Run error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
