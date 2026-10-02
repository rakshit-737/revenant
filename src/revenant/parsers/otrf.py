"""Loader for OTRF Security-Datasets (Mordor) JSON-lines captures.

Each capture is one JSON object per line, flattened Windows events from
several channels (Sysmon, Security, System, PowerShell). Two quirks matter
for a timeline engine and are handled explicitly:

1. **Clock fields disagree.** Sysmon's ``UtcTime`` is authoritative UTC, but
   the generic ``TimeCreated`` / ``@timestamp`` / ``EventTime`` fields are
   written in the *collector's* local time -- sometimes with a misleading
   ``Z`` suffix. We estimate a per-field offset from Sysmon rows (median of
   ``field - UtcTime``, snapped to 15 minutes) and subtract it from every
   non-Sysmon row. Without this, Security 4688 and Sysmon 1 for the same
   process would appear hours apart and never corroborate.
2. **Unreadable/huge files.** Rows that fail to parse are counted, not fatal.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..fsutil import iter_files
from ..models import Event
from .timeutil import parse_ts, round_offset
from .windows import SYSMON, channel_kind, map_windows_event

# Preference order matters: ``EventTime`` is when Windows wrote the record
# (collector-local clock, whole seconds); ``@timestamp`` is when Logstash
# *ingested* it and lags by 1-45 s on the APT29 capture -- enough to break
# Sysmon/4688 fusion and misattribute causes. Use ingest time only as a
# last resort.
GENERIC_TIME_FIELDS = ("TimeCreated", "EventTime", "@timestamp")


@dataclass
class LoadStats:
    rows: int = 0
    mapped: int = 0
    bad_rows: int = 0
    unmapped: Counter = field(default_factory=Counter)
    clock_offsets_s: dict[str, float] = field(default_factory=dict)
    # files the OS refused to open (e.g. quarantined by antivirus because the
    # log text contains attack-tool strings); reported, never silently dropped
    unreadable_files: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rows": self.rows,
            "mapped": self.mapped,
            "bad_rows": self.bad_rows,
            "coverage": round(self.mapped / self.rows, 4) if self.rows else 0.0,
            "clock_offsets_s": self.clock_offsets_s,
            "top_unmapped": self.unmapped.most_common(10),
            "unreadable_files": list(self.unreadable_files),
        }


MAX_LINE_CHARS = 4_000_000


def iter_json_lines(path: str | Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if len(line) > MAX_LINE_CHARS:  # one planted record must not abort the case
                yield {"__bad__": True}
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                yield {"__bad__": True}
                continue
            if isinstance(obj, dict):
                yield obj


def _generic_time(rec: dict[str, Any]) -> tuple[str, Any] | None:
    for f in GENERIC_TIME_FIELDS:
        if rec.get(f):
            return f, rec[f]
    return None


def estimate_clock_offsets(rows: Iterable[dict[str, Any]]) -> dict[str, float]:
    """Per generic-time-field offset (seconds) relative to Sysmon UtcTime."""
    diffs: dict[str, list[float]] = {}
    for r in rows:
        if channel_kind(r) != SYSMON or not r.get("UtcTime"):
            continue
        try:
            utc = parse_ts(r["UtcTime"])
        except ValueError:
            continue
        for f in GENERIC_TIME_FIELDS:
            if r.get(f):
                try:
                    diffs.setdefault(f, []).append((parse_ts(r[f]) - utc).total_seconds())
                except ValueError:
                    pass
    return {f: round_offset(statistics.median(v)) for f, v in diffs.items() if v}


def row_time(rec: dict[str, Any], offsets: dict[str, float]) -> datetime:
    if channel_kind(rec) == SYSMON and rec.get("UtcTime"):
        return parse_ts(rec["UtcTime"])
    g = _generic_time(rec)
    if g is None:
        raise ValueError("row has no timestamp")
    f, v = g
    return parse_ts(v) - timedelta(seconds=offsets.get(f, 0.0))


def events_from_rows(
    rows: list[dict[str, Any]], *, include_noisy: bool = False, stats: LoadStats | None = None
) -> list[Event]:
    stats = stats if stats is not None else LoadStats()
    offsets = estimate_clock_offsets(rows)
    stats.clock_offsets_s = offsets
    events: list[Event] = []
    for r in rows:
        stats.rows += 1
        if r.get("__bad__"):
            stats.bad_rows += 1
            continue
        try:
            ts = row_time(r, offsets)
            ev = map_windows_event(r, ts, include_noisy=include_noisy)
        except (ValueError, TypeError):
            stats.bad_rows += 1
            continue
        if ev is None:
            stats.unmapped[f"{channel_kind(r) or r.get('Channel')}:{r.get('EventID')}"] += 1
            continue
        stats.mapped += 1
        events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events


def _capture_files(p: Path) -> list[Path]:
    """JSON files of a capture, skipping macOS ``__MACOSX/._*`` archive junk."""
    if not p.is_dir():
        return [p]
    return [f for f in iter_files(p, (".json",)) if "__MACOSX" not in f.parts and not f.name.startswith("._")]


def load_otrf(
    path: str | Path, *, include_noisy: bool = False, stats: LoadStats | None = None
) -> list[Event]:
    """Load one OTRF JSON-lines file (or every ``*.json`` under a directory)."""
    stats = stats if stats is not None else LoadStats()
    p = Path(path)
    files = _capture_files(p)
    rows: list[dict[str, Any]] = []
    for f in files:
        try:
            rows.extend(iter_json_lines(f))
        except OSError:
            stats.unreadable_files.append(str(f))
    return events_from_rows(rows, include_noisy=include_noisy, stats=stats)


def load_raw_rows(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    files = _capture_files(p)
    out: list[dict[str, Any]] = []
    for f in files:
        try:
            out.extend(r for r in iter_json_lines(f) if not r.get("__bad__"))
        except OSError:
            continue
    return out
