import json

from revenant import pipeline
from revenant.cli import main
from revenant.generators import intrusion_scenario
from revenant.report import generate_report


def test_report_contains_sections_and_hashes():
    a = pipeline.run(intrusion_scenario())
    report = generate_report(a)
    assert "# REVENANT" in report
    assert "What remains uncertain" in report
    assert "Chain of custody" in report
    assert "sha256:" in report


def test_report_every_chain_cites_events():
    a = pipeline.run(intrusion_scenario())
    report = generate_report(a)
    # at least one event id cited
    assert "ev-" in report


def test_cli_scenarios(capsys):
    assert main(["scenarios"]) == 0
    out = capsys.readouterr().out
    assert "intrusion" in out


def test_cli_demo(capsys):
    assert main(["demo", "--scenario", "intrusion"]) == 0
    out = capsys.readouterr().out
    assert "REVENANT" in out


def test_cli_analyze_and_verify(tmp_path, capsys):
    records = [{"kind": k, "record": r} for k, r in intrusion_scenario()]
    f = tmp_path / "recs.json"
    f.write_text(json.dumps(records), encoding="utf-8")
    assert main(["analyze", str(f)]) == 0
    assert main(["verify", str(f)]) == 0
    out = capsys.readouterr().out
    assert "tamper-evident chain intact: True" in out


def test_refused_ledger_append_leaves_no_report(tmp_path, capsys):
    """A report must never cite a ledger head the store did not persist."""
    from pathlib import Path

    fix = str(Path(__file__).parent / "fixtures" / "otrf_psexec_lsa_secrets.jsonl")
    store, first, second = tmp_path / "case.sqlite", tmp_path / "r1.md", tmp_path / "r2.md"
    assert main(["analyze", fix, "--ledger", str(store), "--out", str(first)]) == 0
    assert first.exists()
    head = next(ln for ln in first.read_text(encoding="utf-8").splitlines() if "Ledger head" in ln)
    assert main(["analyze", fix, "--ledger", str(store), "--out", str(second)]) == 2  # another case's history
    assert not second.exists()
    assert "refusing to append" in capsys.readouterr().err
    digest = head.split("`")[1] if "`" in head else head.rsplit(" ", 1)[-1]
    assert main(["verify", str(store), "--expect-head", digest.strip()]) == 0
