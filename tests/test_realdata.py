"""Tests against the full downloaded corpora (skipped when data is absent).

Run with ``python -m pytest -m realdata`` after ``python scripts/download_data.py``.
Set ``REVENANT_DATA`` if the datasets are not in ``../../datasets/revenant``.
"""

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("REVENANT_DATA", ROOT.parent.parent / "datasets" / "revenant"))
ATOMIC = DATA / "otrf" / "atomic" / "windows"
APT29 = DATA / "otrf" / "compound" / "apt29" / "day1" / "apt29_evals_day1_manual"
EVTX = DATA / "evtx-attack-samples"

pytestmark = pytest.mark.realdata


def _need(p: Path):
    if not p.exists():
        pytest.skip(f"dataset not downloaded: {p}")


def test_atomic_comsvcs_lsass_dump_story():
    d = ATOMIC / "credential_access" / "host" / "psh_lsass_memory_dump_comsvcs"
    _need(d)
    from revenant.pipeline import analyze_paths

    a = analyze_paths([d])
    top = a.stories[0]
    assert "T1003.001" in top.techniques
    assert a.ledger.verify()


def test_evtx_log_cleared_sample():
    _need(EVTX)
    from revenant.antiforensics import scan
    from revenant.graph import ProvenanceGraph
    from revenant.parsers.evtx import load_evtx

    f = next(EVTX.rglob("DE_1102_security_log_cleared.evtx"))
    events = load_evtx(f)
    g = ProvenanceGraph(backend="memory")
    g.add_events(events)
    assert any(i.indicator == "log_cleared" for i in scan(g))


def test_evtx_timestomp_sample():
    _need(EVTX)
    from revenant.antiforensics import detect_sysmon_timestomp
    from revenant.parsers.evtx import load_evtx

    f = next(EVTX.rglob("sysmon_2_11_evasion_timestomp_MACE.evtx"))
    assert detect_sysmon_timestomp(load_evtx(f))


def test_apt29_day1_end_to_end():
    _need(APT29)
    from revenant.pipeline import analyze_paths

    a = analyze_paths([APT29])
    assert len(a.events) > 100_000
    assert a.corroborations > 100  # Sysmon 1 <-> Security 4688 pairs
    assert len({h for s in a.stories for h in s.hosts}) >= 2  # multi-host intrusion
    techniques = {t.split(".")[0] for s in a.stories[:10] for t in s.techniques}
    assert techniques & {"T1059", "T1003", "T1547", "T1548", "T1055"}
    assert a.ledger.verify()
