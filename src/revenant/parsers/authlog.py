"""Linux ``auth.log`` / ``secure`` connector (sshd + sudo lines).

Classic syslog lines carry no year and no time zone, so both are explicit
parameters rather than guesses.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..entities import norm_host
from ..integrity import finalize_event
from ..models import Event, EventType, SourceReliability
from .otrf import LoadStats

_LINE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_FAIL = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")


def parse_auth_line(line: str, *, year: int, utc_offset_hours: float = 0.0) -> Event | None:
    """Parse one syslog ``auth.log`` line into an Event, or None if it is not recognised.

    Parameters
    ----------
    line : str
        Raw log line.
    year : int
        Year to assume (syslog omits it).
    utc_offset_hours : float
        Offset of the host's local time from UTC.
    """
    m = _LINE.match(line.strip())
    if not m:
        return None
    local = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    ts = (local - timedelta(hours=utc_offset_hours)).replace(tzinfo=timezone.utc)
    host, msg = norm_host(m["host"]), m["msg"]
    attrs = {"host": host, "program": m["prog"], "pid": m["pid"] or ""}
    if (ok := _SSH_OK.search(msg)) or (bad := _SSH_FAIL.search(msg)):
        hit = ok or bad
        attrs.update(user=hit["user"].lower(), src_ip=hit["ip"], method=hit["method"], src_port=hit["port"])
        et = EventType.LOGON if ok else EventType.LOGON_FAILED
        action = "authenticated" if ok else "failed_logon"
        actor, obj = f"user:{hit['user'].lower()}", f"host:{host}"
    elif m["prog"] == "sudo" and (s := _SUDO.search(msg)):
        attrs.update(user=s["user"].lower(), command_line=s["cmd"])
        et, action = EventType.PROCESS_START, "sudo_exec"
        actor, obj = f"user:{s['user'].lower()}", f"process:?:{s['cmd'].split()[0] if s['cmd'] else '?'}"
    else:
        return None
    return finalize_event(
        Event(
            event_id="pending",
            timestamp=ts,
            event_type=et,
            actor=actor,
            action=action,
            object=obj,
            source_artifact="authlog",
            source_reliability=SourceReliability.B,
            attributes={k: v for k, v in attrs.items() if v},
        )
    )


def load_authlog(path: str | Path, *, year: int, utc_offset_hours: float = 0.0,
                 stats: LoadStats | None = None) -> list[Event]:
    """Load an ``auth.log`` file into Events, counting rows in ``stats``."""
    stats = stats if stats is not None else LoadStats()
    events: list[Event] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stats.rows += 1
            ev = parse_auth_line(line, year=year, utc_offset_hours=utc_offset_hours)
            if ev is None:
                stats.unmapped["unmatched_line"] += 1
                continue
            stats.mapped += 1
            events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events
