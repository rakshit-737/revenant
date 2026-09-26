"""FastAPI service + timeline/graph UI (optional ``[api]`` extra).

Run::

    REVENANT_EVIDENCE_ROOT=D:/evidence uvicorn revenant.api:app --port 8000

Endpoints
---------
``GET  /``                               single-page timeline + causal-graph UI
``GET  /api/health``                     liveness
``GET  /api/scenarios``                  built-in synthetic scenarios
``POST /api/cases/scenario/{name}``      analyse a synthetic scenario
``POST /api/cases/path``                 analyse artefacts under the evidence root
``GET  /api/cases``                      list cases
``GET  /api/cases/{id}``                 stories, events, edges, indicators (JSON)
``GET  /api/cases/{id}/report.md|.html`` court-style report
``GET  /api/cases/{id}/cypher``          Neo4j export
``GET  /api/cases/{id}/custody``         custody ledger + verification

Safety: the service only *reads* evidence, and only below
``REVENANT_EVIDENCE_ROOT`` (default: the current directory); path traversal
outside it is refused. It binds to localhost by default -- lab use only.
"""

from __future__ import annotations

import os
import uuid
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from . import __version__
from .export import to_cypher, to_dict
from .generators import SCENARIOS
from .pipeline import Analysis, analyze_paths, run
from .report import generate_html, generate_report

app = FastAPI(title="REVENANT", version=__version__,
              description="Evidence-graph forensic timeline reconstruction (lab-only).")
CASES: dict[str, dict[str, Any]] = {}
MAX_CASES = 20


class PathRequest(BaseModel):
    path: str
    kind: str | None = None
    include_noisy: bool = False


def evidence_root() -> Path:
    return Path(os.environ.get("REVENANT_EVIDENCE_ROOT", ".")).resolve()


def _safe_path(p: str) -> Path:
    root = evidence_root()
    target = (root / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(403, f"path outside evidence root {root}")
    if not target.exists():
        raise HTTPException(404, "no such artefact")
    return target


def _store(name: str, analysis: Analysis) -> dict[str, Any]:
    cid = uuid.uuid4().hex[:12]
    if len(CASES) >= MAX_CASES:
        CASES.pop(next(iter(CASES)))
    CASES[cid] = {"id": cid, "name": name, "analysis": analysis}
    return {"id": cid, "name": name, "stories": len(analysis.stories), "events": len(analysis.events)}


def _case(cid: str) -> Analysis:
    c = CASES.get(cid)
    if c is None:
        raise HTTPException(404, "unknown case")
    return c["analysis"]


@app.get("/", response_class=HTMLResponse)
def ui() -> str:
    return resources.files("revenant.web").joinpath("index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/scenarios")
def scenarios() -> list[str]:
    return sorted(SCENARIOS)


@app.post("/api/cases/scenario/{name}")
def case_from_scenario(name: str) -> dict[str, Any]:
    if name not in SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    return _store(f"scenario:{name}", run(SCENARIOS[name]()))


@app.post("/api/cases/path")
def case_from_path(req: PathRequest) -> dict[str, Any]:
    target = _safe_path(req.path)
    try:
        analysis = analyze_paths([target], kind=req.kind, include_noisy=req.include_noisy)
    except (ValueError, ImportError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return _store(target.name, analysis)


@app.get("/api/cases")
def list_cases() -> list[dict[str, Any]]:
    return [{"id": c["id"], "name": c["name"], "stories": len(c["analysis"].stories),
             "events": len(c["analysis"].events)} for c in CASES.values()]


@app.get("/api/cases/{cid}")
def get_case(cid: str, top: int = 20) -> dict[str, Any]:
    return to_dict(_case(cid), top=top)


@app.get("/api/cases/{cid}/report.md", response_class=PlainTextResponse)
def report_md(cid: str, top: int = 5) -> str:
    return generate_report(_case(cid), top=top)


@app.get("/api/cases/{cid}/report.html", response_class=HTMLResponse)
def report_html(cid: str, top: int = 5) -> str:
    return generate_html(_case(cid), top=top)


@app.get("/api/cases/{cid}/cypher", response_class=PlainTextResponse)
def cypher(cid: str, top: int = 20) -> str:
    return to_cypher(_case(cid), top=top)


@app.get("/api/cases/{cid}/custody")
def custody(cid: str) -> dict[str, Any]:
    ledger = _case(cid).ledger
    return {"verified": ledger.verify(), "records": [r.model_dump(mode="json") for r in ledger.records[-200:]],
            "total": len(ledger.records)}


def main() -> None:  # pragma: no cover - thin launcher
    import uvicorn

    uvicorn.run(app, host=os.environ.get("REVENANT_HOST", "127.0.0.1"), port=int(os.environ.get("REVENANT_PORT", "8000")))
