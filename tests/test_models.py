from datetime import datetime, timezone

import pytest

from revenant.models import ConfidenceGrade, Event, EventType, SourceReliability


def _ev(**kw):
    base = dict(
        event_id="x",
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        event_type=EventType.PROCESS_START,
        actor="process:1:a",
        action="spawned",
        object="process:2:b",
        source_artifact="sysmon",
    )
    base.update(kw)
    return Event(**base)


def test_event_rejects_empty_actor():
    with pytest.raises(ValueError):
        _ev(actor="  ")


def test_reliability_weight_ordering():
    assert SourceReliability.A.weight > SourceReliability.C.weight
    assert SourceReliability.C.weight > SourceReliability.E.weight


def test_confidence_grade_bands():
    assert ConfidenceGrade.from_score(0.9) == ConfidenceGrade.CONFIRMED
    assert ConfidenceGrade.from_score(0.7) == ConfidenceGrade.HIGH
    assert ConfidenceGrade.from_score(0.5) == ConfidenceGrade.MEDIUM
    assert ConfidenceGrade.from_score(0.1) == ConfidenceGrade.LOW


def test_canonical_is_deterministic():
    assert _ev().canonical() == _ev().canonical()
