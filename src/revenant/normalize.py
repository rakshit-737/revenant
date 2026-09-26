"""Normalizer: heterogeneous raw records -> common Event schema.

Supports a small set of source shapes (Sysmon-like, auth logs, a generic
plaso-style row). The goal is not exhaustive parser coverage (Grade B/C, see
TODO) but a defensible common schema onto which real parsers can map.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .integrity import finalize_event
from .models import Event, EventType, SourceReliability


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError(f"unsupported timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# Sysmon event id -> normalized type (subset)
_SYSMON_MAP = {
    1: EventType.PROCESS_START,
    3: EventType.NETWORK_CONNECT,
    5: EventType.PROCESS_STOP,
    11: EventType.FILE_WRITE,
    13: EventType.REGISTRY_SET,
    22: EventType.DNS_QUERY,
}


def normalize_sysmon(rec: dict[str, Any]) -> Event:
    """Normalize a Sysmon-like record dict."""
    etype = _SYSMON_MAP.get(int(rec.get("EventID", 0)), EventType.OTHER)
    pid = str(rec.get("ProcessId", ""))
    image = rec.get("Image", "")
    actor = f"process:{pid}:{image}" if pid or image else "process:unknown"

    if etype == EventType.PROCESS_START:
        obj = f"process:{rec.get('ProcessId','?')}:{image}"
        actor = f"process:{rec.get('ParentProcessId','?')}:{rec.get('ParentImage','')}"
        action = "spawned"
    elif etype == EventType.NETWORK_CONNECT:
        obj = f"ip:{rec.get('DestinationIp','?')}:{rec.get('DestinationPort','?')}"
        action = "connected"
    elif etype == EventType.FILE_WRITE:
        obj = f"file:{rec.get('TargetFilename','?')}"
        action = "wrote"
    elif etype == EventType.REGISTRY_SET:
        obj = f"registry:{rec.get('TargetObject','?')}"
        action = "set"
    elif etype == EventType.DNS_QUERY:
        obj = f"dns:{rec.get('QueryName','?')}"
        action = "queried"
    else:
        obj = rec.get("TargetObject") or rec.get("TargetFilename") or "unknown"
        action = "observed"

    attrs = {
        k: str(v)
        for k, v in rec.items()
        if k in ("ProcessId", "ParentProcessId", "Image", "ParentImage", "Hashes", "User", "Host")
        and v is not None
    }
    ev = Event(
        event_id="pending",
        timestamp=_parse_ts(rec["UtcTime"]),
        event_type=etype,
        actor=actor,
        action=action,
        object=obj,
        source_artifact="sysmon",
        source_reliability=SourceReliability.B,
        attributes=attrs,
    )
    return finalize_event(ev)


def normalize_auth(rec: dict[str, Any]) -> Event:
    """Normalize an auth/security-log logon-style record."""
    etype = EventType.LOGON if rec.get("event", "logon") == "logon" else EventType.LOGOFF
    user = rec.get("user", "unknown")
    src_ip = rec.get("src_ip", "?")
    ev = Event(
        event_id="pending",
        timestamp=_parse_ts(rec["time"]),
        event_type=etype,
        actor=f"user:{user}",
        action="authenticated" if etype == EventType.LOGON else "logged_off",
        object=f"host:{rec.get('host','?')}",
        source_artifact=rec.get("source", "auth"),
        source_reliability=SourceReliability(rec.get("reliability", "B")),
        attributes={"src_ip": str(src_ip), "user": str(user)},
    )
    return finalize_event(ev)


def normalize_plaso(rec: dict[str, Any]) -> Event:
    """Normalize a generic plaso-style super-timeline row."""
    ev = Event(
        event_id="pending",
        timestamp=_parse_ts(rec["timestamp"]),
        event_type=EventType(rec.get("event_type", "other")),
        actor=rec.get("actor", "unknown"),
        action=rec.get("action", "observed"),
        object=rec.get("object", "unknown"),
        source_artifact=rec.get("source", "plaso"),
        source_reliability=SourceReliability(rec.get("reliability", "C")),
        attributes={k: str(v) for k, v in rec.get("attributes", {}).items()},
    )
    return finalize_event(ev)


_DISPATCH = {
    "sysmon": normalize_sysmon,
    "auth": normalize_auth,
    "plaso": normalize_plaso,
}


def normalize(kind: str, rec: dict[str, Any]) -> Event:
    if kind not in _DISPATCH:
        raise ValueError(f"unknown source kind: {kind}")
    return _DISPATCH[kind](rec)


def normalize_batch(records: list[tuple[str, dict[str, Any]]]) -> list[Event]:
    """Normalize a list of (kind, record) pairs, sorted by timestamp."""
    events = [normalize(kind, rec) for kind, rec in records]
    events.sort(key=lambda e: e.timestamp)
    return events
