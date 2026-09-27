"""Real-artefact connectors.

=================  =========================================  ==================
kind               input                                      module
=================  =========================================  ==================
``otrf``           OTRF/Mordor JSON-lines Windows event logs  :mod:`.otrf`
``evtx``           raw ``.evtx`` (python-evtx)                :mod:`.evtx`
``plaso``          psort ``json_line`` or ``l2tcsv``          :mod:`.plaso`
``volatility``     dir of Volatility 3 ``-r json`` outputs    :mod:`.volatility`
``authlog``        Linux auth.log / secure                    :mod:`.authlog`
``auditd``         Linux auditd audit.log (raw records)       :mod:`.auditd`
=================  =========================================  ==================
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Event
from .otrf import LoadStats

KINDS = ("otrf", "evtx", "plaso", "volatility", "authlog", "auditd")


def detect_kind(path: str | Path) -> str:
    p = Path(path)
    if p.is_dir():
        if any(p.glob("*.evtx")):
            return "evtx"
        if (p / "pslist.json").exists() or (p / "pstree.json").exists() or (p / "netscan.json").exists():
            return "volatility"
        return "otrf"
    name = p.name.lower()
    if name.endswith(".evtx"):
        return "evtx"
    if name.endswith(".csv"):
        return "plaso"
    if name.endswith((".jsonl", ".json")):
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.readline()
        if '"data_type"' in head or '"__container_type__"' in head:
            return "plaso"
        return "otrf"
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
    from .auditd import looks_like_audit_log

    if looks_like_audit_log(first):
        return "auditd"
    if "auth" in name or "secure" in name:
        return "authlog"
    raise ValueError(f"cannot detect artefact kind for {p}; pass kind explicitly")


def load_path(path: str | Path, kind: str | None = None, *, stats: LoadStats | None = None,
              **opts: Any) -> list[Event]:
    """Load any supported artefact into normalized, hashed Events."""
    kind = kind or detect_kind(path)
    if kind == "otrf":
        from .otrf import load_otrf

        return load_otrf(path, stats=stats, include_noisy=opts.get("include_noisy", False))
    if kind == "evtx":
        from .evtx import load_evtx

        return load_evtx(path, stats=stats, include_noisy=opts.get("include_noisy", False))
    if kind == "plaso":
        from .plaso import load_plaso

        return load_plaso(path, stats=stats)
    if kind == "volatility":
        from .volatility import load_volatility_dir

        return load_volatility_dir(path, host=opts.get("host", ""), stats=stats)
    if kind == "authlog":
        from .authlog import load_authlog

        return load_authlog(path, year=int(opts.get("year", 2024)),
                            utc_offset_hours=float(opts.get("utc_offset_hours", 0.0)), stats=stats)
    if kind == "auditd":
        from .auditd import load_auditd

        return load_auditd(path, host=opts.get("host", ""), stats=stats)
    raise ValueError(f"unknown artefact kind: {kind}")


__all__ = ["KINDS", "LoadStats", "detect_kind", "load_path"]
