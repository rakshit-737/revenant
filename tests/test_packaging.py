"""The calibration table must load (it ships in the wheel as package data)."""

from revenant.rules import MAX_CALIBRATED, load_calibration


def test_calibration_table_loads():
    cal = load_calibration()
    assert len(cal) >= 16
    assert all(0.0 < v <= MAX_CALIBRATED < 1.0 for v in cal.values())


def test_shipped_table_is_the_recorded_atomic_fit():
    """The JSON users get is exactly the table the benchmark run fitted (its SHA-256 is in results/edges.json)."""
    import hashlib
    import json
    from importlib import resources
    from pathlib import Path

    import pytest

    shipped = json.loads(resources.files("revenant.data").joinpath("rule_calibration.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(json.dumps(shipped["rules"], sort_keys=True).encode("utf-8")).hexdigest()
    assert digest == shipped["table_sha256"]
    assert shipped["fitted_on"]["run_id"] and shipped["fitted_on"]["effects"] > 0
    edges = Path(__file__).resolve().parents[1] / "results" / "edges.json"
    if not edges.exists():  # sdist: results/ is not shipped
        pytest.skip("results/edges.json not available")
    assert json.loads(edges.read_text(encoding="utf-8"))["atomic_fit_table"]["sha256"] == digest
