"""Binary ``.evtx`` reader built on python-evtx (Willi Ballenthin).

python-evtx renders each record as the XML Windows itself would show; this
module flattens that XML into the same dict shape OTRF uses, so both feed
`revenant.parsers.windows.map_windows_event`.

``xml_to_record`` is pure (no python-evtx needed) so it is unit-tested with
committed XML fixtures; ``iter_evtx_records`` needs the optional ``evtx``
extra (``pip install python-evtx``).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element  # nosec B405 - type only

# defusedxml blocks entity-expansion / external-entity attacks in hostile XML:
# evidence files are untrusted input by definition, so it is a hard requirement.
from defusedxml.ElementTree import fromstring as _fromstring

from ..fsutil import iter_files
from ..models import Event
from .otrf import LoadStats
from .timeutil import parse_ts
from .windows import SYSMON, channel_kind, map_windows_event


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: Element, name: str) -> Element | None:
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def xml_to_record(xml: str) -> dict[str, Any]:
    """Flatten one rendered EVTX record into an OTRF-style dict."""
    root = _fromstring(xml)
    rec: dict[str, Any] = {}
    system = _child(root, "System")
    if system is not None:
        for c in system:
            name = _local(c.tag)
            if name == "EventID":
                rec["EventID"] = int((c.text or "0").strip())
            elif name == "Channel":
                rec["Channel"] = (c.text or "").strip()
            elif name == "Computer":
                rec["Computer"] = (c.text or "").strip()
            elif name == "EventRecordID":
                rec["EventRecordID"] = (c.text or "").strip()
            elif name == "TimeCreated":
                rec["TimeCreated"] = c.attrib.get("SystemTime", "")
            elif name == "Execution":
                rec["ExecutionProcessID"] = c.attrib.get("ProcessID", "")
            elif name == "Provider":
                rec["SourceName"] = c.attrib.get("Name", "")
    for section in ("EventData", "UserData"):
        data = _child(root, section)
        if data is None:
            continue
        if section == "UserData":  # e.g. 1102 <LogFileCleared><SubjectUserName>..
            for wrapper in data:
                for c in wrapper:
                    rec.setdefault(_local(c.tag), (c.text or "").strip())
            continue
        for i, c in enumerate(data):
            key = c.attrib.get("Name") or f"Data{i}"
            rec[key] = (c.text or "").strip()
    return rec


def iter_evtx_records(path: str | Path) -> Iterator[dict[str, Any]]:
    try:
        import Evtx.Evtx as evtx  # python-evtx
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError("install the 'evtx' extra: pip install python-evtx") from exc
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                yield xml_to_record(record.xml())
            except Exception:  # noqa: BLE001 - corrupt records are counted by caller
                yield {"__bad__": True}


def load_evtx(
    path: str | Path, *, include_noisy: bool = False, stats: LoadStats | None = None
) -> list[Event]:
    """Parse a ``.evtx`` file (or a directory of them) into Events.

    EVTX ``SystemTime`` is already UTC, so no clock-offset estimation is needed.
    """
    stats = stats if stats is not None else LoadStats()
    p = Path(path)
    files = list(iter_files(p, (".evtx",))) if p.is_dir() else [p]
    events: list[Event] = []
    for f in files:
        try:
            records = list(iter_evtx_records(f))
        except OSError:
            stats.unreadable_files.append(str(f))
            continue
        for rec in records:
            stats.rows += 1
            if rec.get("__bad__") or not rec.get("TimeCreated"):
                stats.bad_rows += 1
                continue
            try:
                when = rec.get("UtcTime") if channel_kind(rec) == SYSMON else None
                ts = parse_ts(when or rec["TimeCreated"])
                ev = map_windows_event(rec, ts, include_noisy=include_noisy)
            except (ValueError, TypeError):
                stats.bad_rows += 1
                continue
            if ev is None:
                stats.unmapped[f"{rec.get('Channel')}:{rec.get('EventID')}"] += 1
                continue
            stats.mapped += 1
            events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events
