"""Volatility 3 connector (memory artefacts).

Run Volatility 3 with the JSON renderer and point REVENANT at the output::

    vol -f mem.raw -r json windows.pslist  > pslist.json
    vol -f mem.raw -r json windows.netscan > netscan.json
    vol -f mem.raw -r json windows.cmdline > cmdline.json

``load_volatility_dir`` picks up whichever of those files exist. Process
creation times from EPROCESS become PROCESS_START events (source
``memory``); they corroborate Sysmon/4688 starts for the same
host|pid|image key, and their absence from the logs is itself a signal
(a process visible in memory that no log recorded).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..entities import norm_host
from ..integrity import finalize_event
from ..models import Event, EventType, SourceReliability
from .otrf import LoadStats
from .timeutil import parse_ts


def _flatten(rows: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for r in rows:
        yield r
        kids = r.get("__children") or []
        if kids:
            yield from _flatten(kids)


def _load_json(path: Path) -> list[dict[str, Any]]:
    from ..fsutil import is_link

    if is_link(path):  # never follow links out of the evidence directory
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):  # some renderers wrap rows
        data = data.get("rows") or data.get("data") or []
    return list(_flatten(data))


def _event(ts, etype, actor, action, obj, attrs) -> Event:
    return finalize_event(
        Event(
            event_id="pending",
            timestamp=ts,
            event_type=etype,
            actor=actor,
            action=action,
            object=obj,
            source_artifact="memory",
            source_reliability=SourceReliability.B,
            attributes={k: str(v) for k, v in attrs.items() if v not in (None, "")},
        )
    )


def pslist_events(rows: list[dict[str, Any]], host: str = "", cmdlines: dict[str, str] | None = None) -> list[Event]:
    cmdlines = cmdlines or {}
    image_by_pid = {str(r.get("PID")): str(r.get("ImageFileName") or "") for r in rows}
    out: list[Event] = []
    for r in rows:
        pid, ppid = str(r.get("PID", "")), str(r.get("PPID", ""))
        image = str(r.get("ImageFileName") or "")
        base = {"host": norm_host(host), "image": image, "offset": r.get("Offset(V)"),
                "command_line": cmdlines.get(pid), "plugin": "pslist"}
        if r.get("CreateTime"):
            out.append(_event(parse_ts(r["CreateTime"]), EventType.PROCESS_START,
                              f"process:{ppid}:{image_by_pid.get(ppid, '')}", "spawned",
                              f"process:{pid}:{image}", base))
        if r.get("ExitTime"):
            out.append(_event(parse_ts(r["ExitTime"]), EventType.PROCESS_STOP,
                              f"process:{pid}:{image}", "terminated", f"process:{pid}:{image}", base))
    return out


# listening sockets have an unspecified foreign address (a comparison, not a bind)
_UNSPECIFIED = ("*", "0.0.0.0", "::")  # nosec B104


def netscan_events(rows: list[dict[str, Any]], host: str = "") -> list[Event]:
    out: list[Event] = []
    for r in rows:
        if not r.get("Created") or str(r.get("ForeignAddr") or "*") in _UNSPECIFIED:
            continue
        attrs = {"host": norm_host(host), "state": r.get("State"), "proto": r.get("Proto"),
                 "src_ip": r.get("LocalAddr"), "plugin": "netscan"}
        out.append(_event(parse_ts(r["Created"]), EventType.NETWORK_CONNECT,
                          f"process:{r.get('PID')}:{r.get('Owner') or ''}", "connected",
                          f"ip:{r.get('ForeignAddr')}:{r.get('ForeignPort')}", attrs))
    return out


def load_volatility_dir(path: str | Path, *, host: str = "", stats: LoadStats | None = None) -> list[Event]:
    stats = stats if stats is not None else LoadStats()
    p = Path(path)
    cmd: dict[str, str] = {}
    if (p / "cmdline.json").exists():
        cmd = {str(r.get("PID")): str(r.get("Args") or "") for r in _load_json(p / "cmdline.json")}
    events: list[Event] = []
    if (p / "pslist.json").exists():
        rows = _load_json(p / "pslist.json")
        stats.rows += len(rows)
        events += pslist_events(rows, host, cmd)
    elif (p / "pstree.json").exists():
        rows = _load_json(p / "pstree.json")
        stats.rows += len(rows)
        events += pslist_events(rows, host, cmd)
    if (p / "netscan.json").exists():
        rows = _load_json(p / "netscan.json")
        stats.rows += len(rows)
        events += netscan_events(rows, host)
    stats.mapped += len(events)
    events.sort(key=lambda e: e.timestamp)
    return events
