"""Custody store, exports, report rendering, API and CLI over real fixtures."""

import json
import sqlite3
from pathlib import Path

import pytest

from revenant.cli import main
from revenant.custody_store import append_ledger, load_ledger, verify_store
from revenant.export import to_cypher, to_dict
from revenant.pipeline import analyze_paths
from revenant.report import generate_html, generate_report, markdown_to_html

FX = Path(__file__).parent / "fixtures"
OTRF = FX / "otrf_psexec_lsa_secrets.jsonl"


@pytest.fixture(scope="module")
def analysis():
    return analyze_paths([OTRF])


# ------------------------------------------------------------------ custody
def test_custody_store_append_verify_and_append_only(tmp_path, analysis):
    db = tmp_path / "custody.sqlite"
    assert append_ledger(analysis.ledger, db) == len(analysis.ledger.records)
    assert append_ledger(analysis.ledger, db) == 0  # idempotent
    assert verify_store(db)
    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("UPDATE custody SET digest='x' WHERE seq=0")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("DELETE FROM custody")
    con.close()
    assert len(load_ledger(db).records) == len(analysis.ledger.records)


def test_custody_store_refuses_divergent_history(tmp_path, analysis):
    db = tmp_path / "custody.sqlite"
    append_ledger(analysis.ledger, db)
    other = analyze_paths([FX / "auth.log"], year=2024).ledger
    with pytest.raises(ValueError, match="diverges"):
        append_ledger(other, db)


def test_custody_store_detects_offline_edit(tmp_path, analysis):
    db = tmp_path / "custody.sqlite"
    append_ledger(analysis.ledger, db)
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER custody_no_update")  # an attacker editing the file directly
    con.execute("UPDATE custody SET artifact='forged' WHERE seq=0")
    con.commit()
    con.close()
    assert not verify_store(db)


# ---------------------------------------------------------- report / export
def test_report_sections_cite_hashes(analysis):
    md = generate_report(analysis)
    for section in ("## Scope and evidence", "## Findings: ranked incident stories", "## Tampering indicators",
                    "## What remains uncertain", "## Chain of custody"):
        assert section in md
    assert "T1569.002" in md and "sha256:" in md and "Ledger head" in md
    assert "Event types present but not interpreted" in md


def test_html_render_escapes():
    html = markdown_to_html("# T\n- a <script>x</script> `c`\n| a | b |\n| --- | --- |\n| 1 | 2 |")
    assert "<script>x" not in html and "&lt;script&gt;" in html
    assert "<table>" in html and "<code>c</code>" in html


def test_generate_html(analysis):
    assert generate_html(analysis).startswith("<!doctype html>")


def test_export_dict_and_cypher(analysis):
    d = to_dict(analysis)
    assert d["summary"]["ledger_ok"] and d["stories"]
    ids = {e["id"] for e in d["events"]}
    assert all(i in ids for s in d["stories"] for i in s["event_ids"])
    json.dumps(d, default=str)
    cy = to_cypher(analysis)
    assert "CREATE CONSTRAINT" in cy and "MERGE (a)-[r:CAUSED" in cy
    assert "\\\\" in cy or "\\" not in cy.replace("\\\\", "")  # windows paths escaped as JSON strings


# ---------------------------------------------------------------------- API
def test_api_end_to_end(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from revenant.api import app

    monkeypatch.setenv("REVENANT_EVIDENCE_ROOT", str(FX))
    c = TestClient(app)
    assert c.get("/api/health").json()["status"] == "ok"
    assert "intrusion" in c.get("/api/scenarios").json()
    assert "vis-timeline" in c.get("/").text
    case = c.post("/api/cases/path", json={"path": OTRF.name}).json()
    body = c.get(f"/api/cases/{case['id']}").json()
    assert body["stories"][0]["techniques"]
    assert "Chain of custody" in c.get(f"/api/cases/{case['id']}/report.md").text
    assert c.get(f"/api/cases/{case['id']}/report.html").text.startswith("<!doctype html>")
    assert "MERGE" in c.get(f"/api/cases/{case['id']}/cypher").text
    assert c.get(f"/api/cases/{case['id']}/custody").json()["verified"] is True
    assert c.post("/api/cases/scenario/intrusion").status_code == 200
    assert any(x["id"] == case["id"] for x in c.get("/api/cases").json())
    # path traversal outside the evidence root is refused
    assert c.post("/api/cases/path", json={"path": "../test_parsers.py"}).status_code == 403
    assert c.post("/api/cases/path", json={"path": "nope.json"}).status_code == 404
    assert c.get("/api/cases/unknown").status_code == 404


# ---------------------------------------------------------------------- CLI
def test_cli_analyze_real_formats_and_ledger(tmp_path, capsys):
    out = tmp_path / "r.json"
    db = tmp_path / "c.sqlite"
    assert main(["analyze", str(OTRF), "--format", "json", "--out", str(out), "--ledger", str(db)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["stories"]
    assert main(["verify", str(db)]) == 0
    assert "intact: True" in capsys.readouterr().out
    assert main(["analyze", str(FX / "plaso.jsonl"), "--format", "cypher", "--out", str(tmp_path / "g.cypher")]) == 0
    assert main(["analyze", str(FX / "volatility"), "--format", "html", "--out", str(tmp_path / "r.html")]) == 0


def test_cli_pdf_is_optional(tmp_path, capsys):
    try:
        import weasyprint  # noqa: F401
    except Exception:
        led = tmp_path / "c.sqlite"
        rc = main(["analyze", str(OTRF), "--out", str(tmp_path / "r.md"), "--pdf", str(tmp_path / "r.pdf"),
                   "--ledger", str(led)])
        assert rc == 2 and "WeasyPrint" in capsys.readouterr().err
        assert led.exists()  # the ledger is written before the optional PDF step
    else:  # pragma: no cover - environment dependent
        assert main(["analyze", str(OTRF), "--out", str(tmp_path / "r.md"), "--pdf", str(tmp_path / "r.pdf")]) == 0
