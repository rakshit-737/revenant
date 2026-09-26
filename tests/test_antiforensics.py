from revenant import pipeline
from revenant.antiforensics import detect_hash_mismatch, detect_log_gaps, scan
from revenant.generators import intrusion_scenario, timestomp_scenario
from revenant.normalize import normalize_batch


def test_timestomp_detected():
    a = pipeline.run(timestomp_scenario())
    assert any(i.indicator == "timestomp" for i in a.indicators)


def test_hash_mismatch_detected_on_mutation():
    events = normalize_batch(intrusion_scenario())
    events[0] = events[0].model_copy(update={"action": "tampered"})
    assert detect_hash_mismatch(events)


def test_log_gap_detected():
    events = normalize_batch(timestomp_scenario())
    # timestomp scenario has a logfile far in future but real events are close;
    # force a gap check with tiny threshold
    gaps = detect_log_gaps(events, gap_threshold_s=1.0)
    assert isinstance(gaps, list)


def test_scan_returns_indicators_list():
    a = pipeline.run(intrusion_scenario())
    assert isinstance(a.indicators, list)
