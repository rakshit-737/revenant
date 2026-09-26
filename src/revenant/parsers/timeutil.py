"""Timestamp parsing tolerant of the formats real DFIR exports use."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

_FRAC = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?\s*(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_ts(value: Any) -> datetime:
    """Parse ISO-ish strings, epoch seconds or datetimes into aware UTC datetimes.

    Accepts ``2020-10-19 04:28:31.089``, ``2020-06-10T02:51:05.723Z``,
    ``2019-03-19 23:35:20.528493+00:00`` and 7-digit .NET fractions.
    Naive values are assumed to be UTC (callers apply clock offsets).
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = _EPOCH + timedelta(seconds=float(value))
    elif isinstance(value, str):
        s = value.strip().replace("T", " ")
        m = _FRAC.match(s)
        if not m:
            raise ValueError(f"unsupported timestamp: {value!r}")
        frac = (m.group("frac") or "0")[:6].ljust(6, "0")
        tz = m.group("tz")
        base = datetime.strptime(m.group("head"), "%Y-%m-%d %H:%M:%S")
        dt = base.replace(microsecond=int(frac))
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            hh, mm = int(tz[1:3]), int(tz[-2:])
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=hh, minutes=mm)))
    else:
        raise ValueError(f"unsupported timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def round_offset(seconds: float, quantum: float = 900.0) -> float:
    """Snap a clock offset to the nearest 15 minutes (time-zone granularity)."""
    return round(seconds / quantum) * quantum
