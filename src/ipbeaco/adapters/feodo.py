"""Parse the recommended C2 TXT snapshot, retaining its embedded timestamp."""

import re
from datetime import datetime, timezone

from ipbeaco.models import InputRecord, Snapshot, SourceError, SourceSpec

from ._common import decode, snapshot, target

_UPDATED = re.compile(r"# Last updated: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\s*#?")
_END = re.compile(r"# END (\d+) entries")
_TITLE = "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)"


def parse(raw: bytes, spec: SourceSpec, fetched_at: datetime) -> Snapshot:
    generated_at = None
    records = []
    notices = [spec.url]
    phase = "header"
    ended = False
    for line in decode(raw).splitlines():
        line = line.strip()
        if not line:
            continue
        if ended and not line.startswith("#"):
            raise SourceError("invalid_format: content after Feodo END")
        updated = _UPDATED.fullmatch(line)
        if phase == "header" and updated and generated_at is None:
            try:
                generated_at = datetime.strptime(updated[1], "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                raise SourceError("invalid_format: invalid Feodo timestamp") from None
        elif phase == "header" and line == "# DstIP" and generated_at is not None:
            phase = "records"
        elif phase == "records" and not ended and (end := _END.fullmatch(line)):
            if int(end[1]) != len(records):
                raise SourceError("invalid_format: Feodo entry count mismatch")
            ended = True
        elif line.startswith("#"):
            if line.startswith(("# Last updated", "# DstIP", "# END")):
                raise SourceError("invalid_format: malformed or repeated Feodo marker")
            if "Feodo Tracker Botnet C2 IP Blocklist" in line and line.rstrip(" #") != _TITLE:
                raise SourceError("invalid_format: Feodo list must be recommended")
            if line.startswith("# Terms Of Use: "):
                notices.append(line.removeprefix("# Terms Of Use: ").rstrip(" #"))
        elif phase == "records" and not line.startswith("#"):
            records.append(InputRecord(target(line), "botnet_c2"))
        else:
            raise SourceError("invalid_format: unexpected Feodo line")
    if not ended or generated_at is None:
        raise SourceError("invalid_format: incomplete Feodo snapshot")
    return snapshot(raw, spec, fetched_at, generated_at, records, notices)
