from revenant.integrity import verify_event
from revenant.models import EventType
from revenant.normalize import normalize, normalize_batch


def test_normalize_sysmon_process_start():
    rec = {"EventID": 1, "UtcTime": "2024-01-01T00:00:00Z", "ProcessId": "300",
           "Image": "ps.exe", "ParentProcessId": "200", "ParentImage": "word.exe"}
    e = normalize("sysmon", rec)
    assert e.event_type == EventType.PROCESS_START
    assert e.actor == "process:200:word.exe"
    assert e.object == "process:300:ps.exe"
    assert verify_event(e)


def test_normalize_auth_logon():
    e = normalize("auth", {"time": "2024-01-01T00:00:00Z", "user": "alice", "host": "h",
                           "src_ip": "1.2.3.4"})
    assert e.event_type == EventType.LOGON
    assert e.actor == "user:alice"


def test_normalize_batch_sorted_by_time():
    recs = [
        ("auth", {"time": "2024-01-01T00:01:00Z", "user": "a", "host": "h"}),
        ("auth", {"time": "2024-01-01T00:00:00Z", "user": "b", "host": "h"}),
    ]
    events = normalize_batch(recs)
    assert events[0].timestamp < events[1].timestamp


def test_unknown_kind_raises():
    import pytest
    with pytest.raises(ValueError):
        normalize("nope", {})
