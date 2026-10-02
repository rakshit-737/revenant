"""The calibration table must load (it ships in the wheel as package data)."""

from revenant.rules import MAX_CALIBRATED, load_calibration


def test_calibration_table_loads():
    cal = load_calibration()
    assert len(cal) >= 16
    assert all(0.0 < v <= MAX_CALIBRATED < 1.0 for v in cal.values())
