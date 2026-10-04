"""Collect admitted feeds and persist state only after validating a new site."""

from datetime import datetime
from pathlib import Path

import httpx

from ipbeaco.adapters import PARSERS
from ipbeaco.config import validate_config
from ipbeaco.export import validate_site, write_site
from ipbeaco.fetch import download
from ipbeaco.models import Config, Outcome, SourceError, State
from ipbeaco.policy import select
from ipbeaco.state import load_state, save_state
from ipbeaco.temporal import advance


def collect(config: Config, now: datetime, client: httpx.Client) -> tuple[Outcome, ...]:
    """Collect only enabled, publicly approved sources; failures remain local."""
    outcomes = []
    for spec in config.sources:
        if not spec.enabled or not spec.public_approved:
            continue
        try:
            raw = download(spec.url, config.settings, client)
            snapshot = PARSERS[spec.adapter](raw, spec, now)
        except SourceError as error:
            outcomes.append(Outcome(spec.id, now, error=str(error)))
        else:
            outcomes.append(Outcome(spec.id, now, snapshot=snapshot))
    return tuple(outcomes)


def run_once(
    config: Config,
    state_dir: Path,
    output: Path,
    client: httpx.Client,
    now: datetime,
    build_id: str,
    *,
    bootstrap: bool = False,
) -> State:
    """Build locally without overwriting a previous artifact or deploying it."""
    validate_config(config)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Output already exists: {output}")
    state_path, output_path = state_dir.resolve(), output.resolve()
    if state_path.is_relative_to(output_path) or output_path.is_relative_to(state_path):
        raise ValueError("State and output directories must not overlap")
    previous = load_state(state_dir, bootstrap=bootstrap)
    outcomes = collect(config, now, client)
    candidate = advance(previous, config, outcomes, now, build_id)
    selected = select(candidate, config, now)
    write_site(selected, candidate, config, now, build_id, output)
    validate_site(output, now)
    save_state(candidate, state_dir)
    return candidate
