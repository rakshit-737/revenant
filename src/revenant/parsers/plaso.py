"""plaso / log2timeline super-timeline connector.

REVENANT does not re-implement artefact extraction: run plaso, then feed its
output here. Two export formats are supported:

* ``psort.py -o json_line`` (preferred -- keeps typed fields)
* ``psort.py -o l2tcsv``   (the classic 17-column CSV)

Rows are mapped by ``data_type`` onto REVENANT's schema. EVTX records that
plaso extracted *with* ``xml_string`` are routed through the same Windows
mapper as native EVTX/OTRF input, so a plaso timeline and a live log export
produce identical events for the same record. NTFS ``$STANDARD_INFORMATION``
vs ``$FILE_NAME`` timestamps are preserved (``ntfs_attribute``) so the
anti-forensics module can flag SI/FN timestomping.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..integrity import finalize_event
from ..models import Event, EventType, SourceReliability
from .otrf import LoadStats
from .timeutil import parse_ts

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_PREFETCH_RE = re.compile(r"\[([^\]]+\.exe)\]", re.IGNORECASE)
_URL_RE = re.compile(r"(https?://\S+)")
_EXECUTION_TYPES = {
    "windows:prefetch:execution",
    "windows:registry:userassist",
    "windows:registry:amcache",
    "windows:registry:appcompatcache",
    "windows:registry:bam",
}
_NTFS_ATTR = {16: "$STANDARD_INFORMATION", 48: "$FILE_NAME", "16": "$STANDARD_INFORMATION", "48": "$FILE_NAME"}


def _clean_path(p: str) -> str:
    for prefix in ("OS:", "NTFS:", "TSK:"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p.strip()


def _ts(row: dict[str, Any]) -> datetime:
    t = row.get("timestamp")
    if isinstance(t, (int, float)):
        return _EPOCH + timedelta(microseconds=int(t))
    if isinstance(t, str) and t.strip().lstrip("-").isdigit():
        return _EPOCH + timedelta(microseconds=int(t))
    for k in ("datetime", "date_time", "timestamp"):
        if row.get(k):
            return parse_ts(row[k])
    raise ValueError("plaso row without timestamp")


def map_plaso_row(row: dict[str, Any]) -> Event | None:
    """Map one psort json_line row to an Event (or ``None`` for non-events)."""
    if row.get("__container_type__") not in (None, "event"):
        return None
    ts = _ts(row)
    data_type = str(row.get("data_type", ""))
    desc = str(row.get("timestamp_desc", ""))
    display = _clean_path(str(row.get("filename") or row.get("display_name") or ""))
    host = str(row.get("hostname") or "")

    if data_type == "windows:evtx:record" and row.get("xml_string"):
        from .evtx import xml_to_record
        from .windows import map_windows_event

        ev = map_windows_event(xml_to_record(row["xml_string"]), ts)
        if ev is not None:
            attrs = dict(ev.attributes, via="plaso")
            return finalize_event(ev.model_copy(update={"attributes": attrs}))
        return None

    attrs: dict[str, str] = {
        "host": host.split(".")[0].lower(),
        "data_type": data_type,
        "timestamp_desc": desc,
        "parser": str(row.get("parser", "")),
    }
    user = row.get("username")
    actor = f"user:{user}" if user and user != "-" else f"plaso:{row.get('parser') or 'unknown'}"

    if data_type in _EXECUTION_TYPES:
        exe = row.get("executable") or row.get("value_name") or row.get("full_path") or display
        m = _PREFETCH_RE.search(str(row.get("message", "")))
        if not exe and m:
            exe = m.group(1)
        attrs["run_count"] = str(row.get("run_count", ""))
        et, action, obj = EventType.EXECUTION, "executed", f"process:?:{exe}"
    elif data_type.startswith("fs:stat") or data_type.startswith("fs:ntfs"):
        at = row.get("attribute_type")
        if at in _NTFS_ATTR:
            attrs["ntfs_attribute"] = _NTFS_ATTR[at]
        d = desc.lower()
        if "creation" in d:
            et, action = EventType.FILE_WRITE, "created"
        elif "access" in d:
            et, action = EventType.FILE_READ, "accessed"
        elif "metadata" in d or "entry modification" in d:
            et, action = EventType.FILE_WRITE, "metadata_changed"
        else:
            et, action = EventType.FILE_WRITE, "modified"
        obj = f"file:{_clean_path(str(row.get('name') or display))}"
    elif data_type.startswith("windows:registry"):
        et, action = EventType.REGISTRY_SET, "last_written"
        obj = f"registry:{row.get('key_path') or display}"
    elif "history" in data_type or data_type.endswith("page_visited"):
        url = row.get("url") or (_URL_RE.search(str(row.get("message", ""))) or [None])[0]
        et, action, obj = EventType.WEB_VISIT, "visited", f"url:{url or '?'}"
    elif data_type == "windows:lnk:link":
        target = row.get("linked_path") or row.get("local_path") or display
        et, action, obj = EventType.FILE_READ, "opened", f"file:{target}"
    else:
        et, action, obj = EventType.OTHER, (desc or "observed").lower().replace(" ", "_"), display or data_type
    msg = str(row.get("message", ""))
    if msg:
        attrs["message"] = msg[:512]
    ev = Event(
        event_id="pending",
        timestamp=ts,
        event_type=et,
        actor=actor,
        action=action or "observed",
        object=obj or "unknown",
        source_artifact="plaso",
        source_reliability=SourceReliability.C,
        attributes={k: v for k, v in attrs.items() if v},
    )
    return finalize_event(ev)


L2TCSV_FIELDS = [
    "date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host",
    "short", "desc", "version", "filename", "inode", "notes", "format", "extra",
]


def l2tcsv_to_row(r: dict[str, str]) -> dict[str, Any]:
    """Convert a classic l2tcsv row into the json_line shape used above."""
    tz = (r.get("timezone") or "UTC").upper()
    dt = datetime.strptime(f"{r['date']} {r['time']}", "%m/%d/%Y %H:%M:%S")
    if tz not in ("UTC", "GMT"):
        raise ValueError(f"l2tcsv must be exported in UTC (got {tz})")
    source = (r.get("source") or "").upper()
    stype = (r.get("sourcetype") or "").lower()
    if source == "FILE":
        data_type = "fs:stat:ntfs" if "ntfs" in stype or "mft" in stype else "fs:stat"
    elif "prefetch" in stype:
        data_type = "windows:prefetch:execution"
    elif source == "REG":
        data_type = "windows:registry:key_value"
    elif source == "WEBHIST":
        data_type = "browser:history:page_visited"
    elif source == "LNK":
        data_type = "windows:lnk:link"
    else:
        data_type = f"l2tcsv:{source.lower()}:{stype}"
    return {
        "timestamp": int((dt.replace(tzinfo=timezone.utc) - _EPOCH).total_seconds() * 1_000_000),
        "timestamp_desc": r.get("type", ""),
        "data_type": data_type,
        "parser": r.get("format", ""),
        "filename": r.get("filename", ""),
        "display_name": r.get("filename", ""),
        "hostname": r.get("host", ""),
        "username": r.get("user", ""),
        "message": r.get("desc", ""),
        "key_path": r.get("short", "") if source == "REG" else None,
    }


def iter_plaso(path: str | Path) -> Iterator[dict[str, Any]]:
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):
            for line in fh:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except (json.JSONDecodeError, RecursionError):
                        yield {"__bad__": True}
        else:
            reader = csv.DictReader(fh)
            while True:
                try:
                    r = next(reader)
                except StopIteration:
                    break
                except csv.Error:  # oversized/garbled field: drop the row, keep the case
                    yield {"__bad__": True}
                    continue
                try:
                    yield l2tcsv_to_row(r)
                except (KeyError, ValueError):
                    yield {"__bad__": True}


def load_plaso(path: str | Path, *, stats: LoadStats | None = None) -> list[Event]:
    stats = stats if stats is not None else LoadStats()
    events: list[Event] = []
    for row in iter_plaso(path):
        stats.rows += 1
        if row.get("__bad__"):
            stats.bad_rows += 1
            continue
        try:
            ev = map_plaso_row(row)
        except (ValueError, TypeError):
            stats.bad_rows += 1
            continue
        if ev is None:
            stats.unmapped[str(row.get("data_type"))] += 1
            continue
        stats.mapped += 1
        events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events
