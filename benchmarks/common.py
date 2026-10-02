"""Shared helpers for the REVENANT benchmarks (dataset discovery + labels).

Datasets live outside the repo (``REVENANT_DATA`` or ``../../datasets/revenant``)
and are fetched by ``scripts/download_data.py``.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DATA = Path(os.environ.get("REVENANT_DATA", ROOT.parent.parent / "datasets" / "revenant"))
RESULTS = ROOT / "results"
OTRF_ATOMIC = DATA / "otrf" / "atomic"
APT29_DIR = DATA / "otrf" / "compound" / "apt29" / "day1" / "apt29_evals_day1_manual"
EVTX_SAMPLES = DATA / "evtx-attack-samples"
COMPOUND = DATA / "otrf" / "compound"


def compound_corpora() -> dict[str, list[tuple[str, Path]]]:
    """Extra GUID-truth corpora (opt-in downloads); each entry is one capture directory."""
    out: dict[str, list[tuple[str, Path]]] = {}
    lsass = sorted(d for c in COMPOUND.glob("LSASS_campaign_*") for d in c.iterdir() if d.is_dir())
    if lsass:
        out["otrf_lsass_campaign"] = [(d.parent.name, d) for d in lsass]
    if (COMPOUND / "Log4Shell").is_dir():
        out["otrf_log4shell"] = [("log4shell", COMPOUND / "Log4Shell")]
    day2 = COMPOUND / "apt29" / "day2" / "apt29_evals_day2_manual"
    if day2.is_dir():
        out["otrf_apt29_day2"] = [("apt29_day2", day2)]
    return out


@dataclass
class AtomicDataset:
    name: str  # archive stem, e.g. empire_shell_net_localgroup_administrators
    tactic_dir: str  # e.g. discovery
    path: Path  # extracted directory
    techniques: list[str] = field(default_factory=list)  # parent ids, e.g. T1069
    sub_techniques: list[str] = field(default_factory=list)  # e.g. T1069.001
    tactics: list[str] = field(default_factory=list)
    title: str = ""
    metadata_id: str = ""


def _labels() -> dict[str, dict]:
    out: dict[str, dict] = {}
    meta_dir = OTRF_ATOMIC / "_metadata"
    for y in sorted(meta_dir.glob("SDWIN-*.yaml")):
        try:
            doc = yaml.safe_load(y.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        techs, subs, tactics = [], [], []
        for m in doc.get("attack_mappings") or []:
            t = str(m.get("technique") or "").strip()
            if not t:
                continue
            techs.append(t)
            st = m.get("sub-technique")
            if st:
                subs.append(f"{t}.{str(st).zfill(3)}")
            tactics += [str(x) for x in (m.get("tactics") or [])]
        for f in doc.get("files") or []:
            if str(f.get("type", "")).lower() != "host":
                continue
            stem = Path(str(f.get("link", ""))).name.split(".")[0]
            out[stem] = {
                "techniques": sorted(set(techs)),
                "sub_techniques": sorted(set(subs)),
                "tactics": sorted(set(tactics)),
                "title": str(doc.get("title", "")).strip(),
                "id": str(doc.get("id", "")),
            }
    return out


def atomic_datasets(labelled_only: bool = False) -> list[AtomicDataset]:
    labels = _labels()
    out: list[AtomicDataset] = []
    seen: set[str] = set()
    base = OTRF_ATOMIC / "windows"
    if not base.exists():
        return out
    for tactic_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        host = tactic_dir / "host"
        if not host.exists():
            continue
        for d in sorted(p for p in host.iterdir() if p.is_dir()):
            if not any(d.rglob("*.json")):
                continue
            lab = labels.get(d.name)
            if labelled_only and not lab:
                continue
            if d.name in seen:  # the same capture is published under two tactics: count it once
                continue
            seen.add(d.name)
            ds = AtomicDataset(d.name, tactic_dir.name, d)
            if lab:
                ds.techniques = lab["techniques"]
                ds.sub_techniques = lab["sub_techniques"]
                ds.tactics = lab["tactics"]
                ds.title = lab["title"]
                ds.metadata_id = lab["id"]
            out.append(ds)
    return out


def environment() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
    }


def write_json(name: str, payload: dict) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    p = RESULTS / name
    p.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"[results] {p.relative_to(ROOT)}")
    return p


def require(path: Path, what: str) -> bool:
    if not path.exists():
        print(f"[skip] {what} not found at {path} -- run scripts/download_data.py", file=sys.stderr)
        return False
    return True


CACHE = DATA / ".cache"


def load_cached(path: Path, key: str):
    """Parse an OTRF capture once; later runs read a pickle (outside the repo).

    Returns ``(events, stats_dict)``. The cache key includes a hash of the
    parser sources so a mapping change never serves stale events.
    """
    import hashlib
    import pickle  # nosec B403 - local cache written by this script only

    from revenant.parsers.otrf import LoadStats, load_otrf

    src = ROOT / "src" / "revenant"
    h = hashlib.sha256()
    deps = ["parsers/otrf.py", "parsers/windows.py", "parsers/timeutil.py", "entities.py", "models.py", "integrity.py"]
    for f in (src / d for d in deps):  # exactly what OTRF parsing depends on
        h.update(f.read_bytes())
    CACHE.mkdir(parents=True, exist_ok=True)
    c = CACHE / f"{key}-{h.hexdigest()[:12]}.pkl"
    if c.exists():
        with c.open("rb") as fh:
            return pickle.load(fh)  # nosec B301
    st = LoadStats()
    events = load_otrf(path, stats=st)
    out = (events, st.as_dict())
    with c.open("wb") as fh:
        pickle.dump(out, fh, protocol=pickle.HIGHEST_PROTOCOL)
    return out
