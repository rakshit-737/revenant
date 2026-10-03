"""Real-artefact connectors.

=================  =========================================  ==================
kind               input                                      module
=================  =========================================  ==================
``otrf``           OTRF/Mordor JSON-lines Windows event logs  `.otrf`
``evtx``           raw ``.evtx`` (python-evtx)                `.evtx`
``plaso``          psort ``json_line`` or ``l2tcsv``          `.plaso`
``volatility``     dir of Volatility 3 ``-r json`` outputs    `.volatility`
``authlog``        Linux auth.log / secure                    `.authlog`
``auditd``         Linux auditd audit.log (raw records)       `.auditd`
``atlas``          ATLAS preprocessed Windows/DNS/HTTP log    `.atlas`
=================  =========================================  ==================
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from ..models import Event
    from .otrf import LoadStats

KINDS = ("otrf", "evtx", "plaso", "volatility", "authlog", "auditd", "atlas")


def detect_kind(path: str | Path) -> str:
    """Guess the evidence kind of a file or directory.

    Raises
    ------
    ValueError
        If no supported kind is recognised.
    """
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
    from .atlas import looks_like_atlas
    from .auditd import looks_like_audit_log

    if looks_like_audit_log(first):
        return "auditd"
    if looks_like_atlas(first):
        return "atlas"
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
    if kind == "atlas":
        from .atlas import load_atlas

        return load_atlas(path, host=opts.get("host", ""), stats=stats)
    raise ValueError(f"unknown artefact kind: {kind}")


def __getattr__(name: str) -> Any:
    """Import `LoadStats` on first use, so listing `KINDS` stays cheap."""
    if name == "LoadStats":
        from .otrf import LoadStats

        return LoadStats
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["KINDS", "LoadStats", "detect_kind", "load_path"]
