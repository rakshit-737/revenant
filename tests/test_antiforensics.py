from revenant import pipeline
from revenant.antiforensics import detect_hash_mismatch, detect_log_gaps
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
    """Spec demo 4: a 20+ minute silence is reported as an *unknown* window, not filled in."""
    from datetime import timedelta

    events = normalize_batch(intrusion_scenario())
    events.sort(key=lambda e: e.timestamp)
    shifted = events[:2] + [e.model_copy(update={"timestamp": e.timestamp + timedelta(minutes=25)}) for e in events[2:]]
    gaps = detect_log_gaps(shifted)
    assert len(gaps) == 1 and gaps[0].indicator == "log_gap"
    assert "(unknown)" in gaps[0].detail and gaps[0].event_ids == [shifted[1].event_id, shifted[2].event_id]
    assert not detect_log_gaps(events)


def test_scan_returns_indicators_list():
    a = pipeline.run(intrusion_scenario())
    assert isinstance(a.indicators, list)
