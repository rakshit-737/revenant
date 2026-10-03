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


def _win(eid, channel, minutes, **fields):
    from datetime import datetime, timedelta, timezone

    from revenant.parsers.windows import map_windows_event

    ts = datetime(2022, 7, 8, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)
    return map_windows_event({"Channel": channel, "EventID": eid, "Hostname": "WS1", **fields}, ts)


def test_eventlog_service_state_is_mapped_only_for_the_event_log():
    from revenant.models import EventType

    ev = _win(7036, "System", 0, param1="Windows Event Log", param2="stopped")
    assert ev.event_type == EventType.LOGGING_STATE and ev.attributes["state"] == "stopped"
    assert _win(7036, "System", 0, param1="Windows Update", param2="stopped") is None
    assert _win(7034, "System", 0, param1="EventLog", param2="1").attributes["state"] == "crashed"
    assert _win(1100, "Security", 0).event_type == EventType.LOGGING_STATE
    assert _win(6006, "System", 0).event_type == EventType.SYSTEM_POWER


def test_logging_stopped_outside_boot_or_shutdown():
    from revenant.antiforensics import detect_logging_stopped

    stop = _win(7036, "System", 0, param1="Windows Event Log", param2="stopped")
    crash = _win(7034, "System", 1, param1="Windows Event Log", param2="1")
    restart = _win(7036, "System", 2, param1="Windows Event Log", param2="running")
    found = detect_logging_stopped([stop, crash, restart])
    assert [i.severity for i in found] == ["high", "high", "medium"]
    assert all(i.indicator == "logging_stopped" for i in found)


def test_clean_shutdown_and_boot_are_not_tampering():
    from revenant.antiforensics import detect_logging_stopped

    events = [
        _win(1074, "System", 0),  # shutdown initiated
        _win(1100, "Security", 1),
        _win(7036, "System", 1, param1="Windows Event Log", param2="stopped"),
        _win(6005, "System", 30),  # boot
        _win(7036, "System", 30, param1="Windows Event Log", param2="running"),
    ]
    assert detect_logging_stopped(events) == []
    # the same 1100 with no shutdown nearby is reported
    assert [i.severity for i in detect_logging_stopped([_win(1100, "Security", 1)])] == ["medium"]


def test_werfault_for_the_event_log_host_is_a_crash():
    from revenant.antiforensics import detect_logging_stopped

    wer = _win(1, "Microsoft-Windows-Sysmon/Operational", 0, Image=r"C:\Windows\System32\WerFault.exe",
               ParentCommandLine=r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog",
               ProcessId="3424", ParentProcessId="3004")
    other = _win(1, "Microsoft-Windows-Sysmon/Operational", 0, Image=r"C:\Windows\System32\WerFault.exe",
                 ParentCommandLine=r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule",
                 ProcessId="3425", ParentProcessId="3005")
    assert [i.severity for i in detect_logging_stopped([wer, other])] == ["high"]
