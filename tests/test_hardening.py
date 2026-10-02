"""Regression tests for the round-4 audit: CLI errors, ledger verification, links, parsers, API guards."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from revenant import cli
from revenant.custody_store import verify_store
from revenant.fsutil import iter_files

FIX = Path(__file__).parent / "fixtures"


def test_verify_missing_ledger_fails_and_creates_nothing(tmp_path, capsys):
    target = tmp_path / "nope.sqlite"
    assert cli.main(["verify", str(target)]) == 2
    assert not target.exists()


def test_verify_detects_truncation_with_anchor_and_dropped_trigger(tmp_path, capsys):
    led = tmp_path / "case.sqlite"
    assert cli.main(["analyze", str(FIX / "plaso.jsonl"), "--ledger", str(led), "--out", str(tmp_path / "r.md")]) == 0
    con = sqlite3.connect(led)
    n, head = con.execute("SELECT COUNT(*), (SELECT record_hash FROM custody ORDER BY seq DESC LIMIT 1) FROM custody").fetchone()
    con.close()
    assert cli.main(["verify", str(led), "--expect-count", str(n), "--expect-head", head]) == 0
    assert verify_store(led, expect_head=head, expect_count=n)
    con = sqlite3.connect(led)
    con.executescript("DROP TRIGGER custody_no_delete; DELETE FROM custody WHERE seq = (SELECT MAX(seq) FROM custody);")
    con.close()
    assert cli.main(["verify", str(led), "--expect-count", str(n)]) == 2  # truncation + missing trigger
    out = capsys.readouterr().out
    assert "trigger" in out and "count" in out
    con = sqlite3.connect(led)
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    con.close()
    assert "custody_no_delete" not in names  # verify must not repair (and hide) the tampering


def test_verify_empty_ledger_fails(tmp_path):
    led = tmp_path / "empty.sqlite"
    from revenant.custody_store import _connect

    _connect(led).close()
    assert cli.main(["verify", str(led)]) == 2


def test_analyze_missing_input_exits_2(tmp_path, capsys):
    assert cli.main(["analyze", str(tmp_path / "capture.evtx")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_analyze_kind_auditd_cli(capsys):
    assert cli.main(["analyze", str(FIX / "auditd_sample.log"), "--kind", "auditd", "--top", "1"]) == 0


def test_undetectable_kind_is_one_line_error(capsys):
    assert cli.main(["analyze", str(FIX / "evtx_1102.xml")]) == 2
    assert "cannot detect" in capsys.readouterr().err


def test_version_flag():
    r = subprocess.run([sys.executable, "-m", "revenant.cli", "--version"], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")})
    assert r.returncode == 0 and "revenant" in r.stdout


def _make_link(link: Path, target: Path) -> bool:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
        return True
    except (OSError, NotImplementedError):
        if os.name == "nt" and target.is_dir():
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
            return r.returncode == 0
        return False


def test_links_inside_evidence_are_not_followed(tmp_path):
    root = tmp_path / "ev"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "in.json").write_text("{}")
    (outside / "secret.json").write_text("{}")
    if not _make_link(root / "mounted", outside):
        pytest.skip("cannot create symlinks/junctions here")
    skipped: list[str] = []
    files = list(iter_files(root, (".json",), skipped))
    assert [f.name for f in files] == ["in.json"]
    assert skipped


def test_oversized_csv_field_and_deep_json_do_not_abort(tmp_path):
    from revenant.parsers.otrf import load_otrf
    from revenant.parsers.plaso import load_plaso

    csv_src = (FIX / "l2t.csv").read_text(encoding="utf-8")
    header = csv_src.splitlines()[0]
    bad = tmp_path / "bad.csv"
    bad.write_text(csv_src.rstrip("\n") + "\n" + header.replace(header, ",".join(["x" * 200_000] * 3)) + "\n",
                   encoding="utf-8")
    good_n = len(load_plaso(FIX / "l2t.csv"))
    assert len(load_plaso(bad)) == good_n
    src = (FIX / "otrf_psexec_lsa_secrets.jsonl").read_text(encoding="utf-8")
    deep = tmp_path / "deep.jsonl"
    deep.write_text(src + "[" * 200_000 + "\n", encoding="utf-8")
    assert len(load_otrf(deep)) == len(load_otrf(FIX / "otrf_psexec_lsa_secrets.jsonl"))


def test_api_guards(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from revenant.api import app

    monkeypatch.setenv("REVENANT_EVIDENCE_ROOT", str(tmp_path))
    c = TestClient(app)
    assert c.get("/api/health", headers={"host": "attacker.example:8000"}).status_code == 400
    assert c.post("/api/cases/scenario/intrusion", headers={"origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/cases/path", content=b"{" + b" " * 70_000 + b"}",
                  headers={"content-type": "application/json"}).status_code == 413
    for bad in ["\\\\127.0.0.1\\share\\x.json", "//host/share", "C:/Windows", "/etc/passwd", "a/../../x"]:
        r = c.post("/api/cases/path", json={"path": bad})
        assert r.status_code == 403, bad
        assert str(tmp_path) not in r.text
