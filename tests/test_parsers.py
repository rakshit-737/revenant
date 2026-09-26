from pathlib import Path

import pytest

from revenant.models import EventType, SourceReliability
from revenant.parsers import LoadStats, detect_kind, load_path
from revenant.parsers.authlog import load_authlog
from revenant.parsers.evtx import xml_to_record
from revenant.parsers.otrf import estimate_clock_offsets, load_otrf, load_raw_rows
from revenant.parsers.plaso import load_plaso
from revenant.parsers.timeutil import parse_ts, round_offset
from revenant.parsers.volatility import load_volatility_dir
from revenant.parsers.windows import map_windows_event

FX = Path(__file__).parent / "fixtures"
OTRF = FX / "otrf_psexec_lsa_secrets.jsonl"


# ------------------------------------------------------------------ timeutil
def test_parse_ts_formats_and_utc():
    assert parse_ts("2020-10-19 04:28:31.089").microsecond == 89000
    assert parse_ts("2020-06-10T02:51:05.723Z").tzinfo is not None
    assert parse_ts("2019-03-19 23:35:20.5284931+02:00").hour == 21  # 7-digit .NET fraction, tz applied
    assert parse_ts(0).year == 1970
    with pytest.raises(ValueError):
        parse_ts("yesterday")


def test_round_offset_snaps_to_quarter_hour():
    assert round_offset(-14398.2) == -14400.0
    assert round_offset(7) == 0.0


# ---------------------------------------------------------------------- OTRF
def test_otrf_real_capture_loads_with_coverage_and_offset():
    st = LoadStats()
    events = load_otrf(OTRF, stats=st)
    assert len(events) == st.mapped > 100
    assert st.bad_rows == 0
    # collector-local TimeCreated is 4 h off Sysmon UtcTime on this capture
    assert st.clock_offsets_s["TimeCreated"] == -14400.0
    kinds = {e.source_artifact for e in events}
    assert {"sysmon", "security"} <= kinds
    assert all(e.integrity_hash and e.event_id.startswith("ev-") for e in events)
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)


def test_otrf_security_and_sysmon_agree_after_offset():
    events = load_otrf(OTRF)
    sysmon = {e.object.split(":")[1]: e for e in events if e.source_artifact == "sysmon"
              and e.event_type == EventType.PROCESS_START}
    sec = [e for e in events if e.source_artifact == "security" and e.event_type == EventType.PROCESS_START]
    matched = [(s, sysmon[s.object.split(":")[1]]) for s in sec if s.object.split(":")[1] in sysmon]
    assert matched
    for s, y in matched:
        assert abs((s.timestamp - y.timestamp).total_seconds()) < 2.0


def test_estimate_clock_offsets_ignores_non_sysmon():
    rows = load_raw_rows(OTRF)
    offsets = estimate_clock_offsets(rows)
    assert "TimeCreated" in offsets


def test_otrf_unreadable_file_is_counted_not_fatal(tmp_path, monkeypatch):
    good = tmp_path / "a.json"
    good.write_text(OTRF.read_text(encoding="utf-8"), encoding="utf-8")
    bad = tmp_path / "b.json"
    bad.write_text("{}", encoding="utf-8")
    import revenant.parsers.otrf as otrf

    real = otrf.iter_json_lines

    def fake(path):
        if Path(path).name == "b.json":
            raise OSError(22, "Operation did not complete successfully because the file contains a virus")
        return real(path)

    monkeypatch.setattr(otrf, "iter_json_lines", fake)
    st = LoadStats()
    events = otrf.load_otrf(tmp_path, stats=st)
    assert events and st.unreadable_files == [str(bad)]


def test_otrf_skips_macos_resource_forks(tmp_path):
    (tmp_path / "__MACOSX").mkdir()
    (tmp_path / "__MACOSX" / "._x.json").write_bytes(b"\x00\x05\x16\x07binary")
    (tmp_path / "x.json").write_text(OTRF.read_text(encoding="utf-8"), encoding="utf-8")
    st = LoadStats()
    load_otrf(tmp_path, stats=st)
    assert st.bad_rows == 0


# ------------------------------------------------------------ windows mapper
def test_windows_mapper_reliability_by_channel():
    from datetime import datetime, timezone

    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    sec = map_windows_event({"Channel": "Security", "EventID": 4624, "TargetUserName": "THESHIRE\\Alice",
                             "TargetLogonId": "0x3e1a2", "LogonType": "10", "Hostname": "WS1.corp"}, ts)
    assert sec.event_type == EventType.LOGON and sec.source_reliability == SourceReliability.A
    assert sec.attributes["user"] == "alice" and sec.attributes["logon_id"] == "0x3e1a2"
    assert sec.attributes["host"] == "ws1"
    assert map_windows_event({"Channel": "Application", "EventID": 1}, ts) is None
    hexpid = map_windows_event({"Channel": "Security", "EventID": 4688, "NewProcessId": "0x10e1",
                                "NewProcessName": "C:\\x.exe", "ProcessId": "0x4"}, ts)
    assert hexpid.object == "process:4321:C:\\x.exe"


def test_windows_mapper_nxlog_processid_alias():
    from datetime import datetime, timezone

    ev = map_windows_event({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 13,
                            "ProcessID": "77", "Image": "C:\\a.exe", "TargetObject": "HKLM\\x"},
                           datetime(2024, 1, 1, tzinfo=timezone.utc))
    assert ev.actor == "process:77:C:\\a.exe"


# ---------------------------------------------------------------------- EVTX
def test_evtx_xml_flattening_and_mapping():
    rec = xml_to_record((FX / "evtx_sysmon1.xml").read_text(encoding="utf-8"))
    assert rec["EventID"] == 1 and rec["Channel"].endswith("Sysmon/Operational")
    assert rec["ProcessId"] == "4321" and rec["EventRecordID"] == "4242"
    ev = map_windows_event(rec, parse_ts(rec["UtcTime"]))
    assert ev.event_type == EventType.PROCESS_START
    assert ev.attributes["object_guid"] == "11111111-2222-3333-4444-555555555555"
    assert "WINWORD" in ev.actor


def test_evtx_userdata_log_cleared():
    rec = xml_to_record((FX / "evtx_1102.xml").read_text(encoding="utf-8"))
    ev = map_windows_event(rec, parse_ts(rec["TimeCreated"]))
    assert ev.event_type == EventType.LOG_CLEARED and ev.actor == "user:alice"


# --------------------------------------------------------------------- plaso
def test_plaso_json_line():
    st = LoadStats()
    events = load_plaso(FX / "plaso.jsonl", stats=st)
    types = {e.event_type for e in events}
    assert {EventType.FILE_WRITE, EventType.EXECUTION, EventType.REGISTRY_SET, EventType.WEB_VISIT} <= types
    assert st.unmapped  # the session container is counted, not ingested
    ntfs = [e for e in events if "ntfs_attribute" in e.attributes]
    assert {e.attributes["ntfs_attribute"] for e in ntfs} == {"$STANDARD_INFORMATION", "$FILE_NAME"}


def test_plaso_l2tcsv():
    events = load_plaso(FX / "l2t.csv")
    assert {e.event_type for e in events} >= {EventType.EXECUTION, EventType.REGISTRY_SET, EventType.WEB_VISIT}


# ---------------------------------------------------------------- volatility
def test_volatility_dir():
    events = load_volatility_dir(FX / "volatility", host="LAB-WS01")
    starts = [e for e in events if e.event_type == EventType.PROCESS_START]
    assert len(starts) == 3 and all(e.source_artifact == "memory" for e in events)
    ps = next(e for e in starts if e.object.startswith("process:4321:"))
    assert "-enc" in ps.attributes["command_line"]
    nets = [e for e in events if e.event_type == EventType.NETWORK_CONNECT]
    assert len(nets) == 1  # listening socket skipped
    assert any(e.event_type == EventType.PROCESS_STOP for e in events)


# ------------------------------------------------------------------ auth.log
def test_authlog():
    st = LoadStats()
    events = load_authlog(FX / "auth.log", year=2024, utc_offset_hours=1.0, stats=st)
    kinds = [e.event_type for e in events]
    assert kinds == [EventType.LOGON_FAILED, EventType.LOGON, EventType.PROCESS_START]
    assert events[1].attributes["src_ip"] == "198.51.100.23"
    assert events[0].timestamp.hour == 9  # 10:10 local at UTC+1
    assert st.unmapped["unmatched_line"] == 1


# ---------------------------------------------------------------- dispatcher
def test_detect_kind_and_load_path():
    assert detect_kind(OTRF) == "otrf"
    assert detect_kind(FX / "plaso.jsonl") == "plaso"
    assert detect_kind(FX / "l2t.csv") == "plaso"
    assert detect_kind(FX / "volatility") == "volatility"
    assert detect_kind(FX / "auth.log") == "authlog"
    assert load_path(FX / "auth.log", year=2024)
    with pytest.raises(ValueError):
        load_path(FX / "auth.log", kind="nope")
