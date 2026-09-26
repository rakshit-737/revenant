"""Engine behaviour on the committed real OTRF fixture + targeted synthetic cases."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from revenant.antiforensics import (
    detect_audit_tamper,
    detect_clock_change,
    detect_record_order,
    detect_si_fn_mismatch,
    detect_sysmon_timestomp,
)
from revenant.attack import score_events
from revenant.fusion import fuse
from revenant.graph import ProvenanceGraph
from revenant.integrity import finalize_event
from revenant.models import Event, EventType, SourceReliability
from revenant.parsers.otrf import load_otrf
from revenant.parsers.plaso import load_plaso
from revenant.pipeline import analyze_events, analyze_paths
from revenant.rules import RuleEngine
from revenant.stories import SYSTEM_ROOTS, story_breakdown, story_root

FX = Path(__file__).parent / "fixtures"
OTRF = FX / "otrf_psexec_lsa_secrets.jsonl"
T0 = datetime(2024, 3, 2, 10, 0, tzinfo=timezone.utc)


def ev(sec, etype, actor, obj, *, source="sysmon", **attrs):
    return finalize_event(Event(
        event_id="pending", timestamp=T0 + timedelta(seconds=sec), event_type=etype, actor=actor,
        action="x", object=obj, source_artifact=source,
        source_reliability=SourceReliability.A if source == "security" else SourceReliability.B,
        attributes={"host": "ws1", **{k: str(v) for k, v in attrs.items()}},
    ))


def _graph(events, use_guids=True):
    g = ProvenanceGraph(backend="memory")
    g.add_events(events)
    fuse(g)
    RuleEngine(use_guids=use_guids).infer(g)
    return g


# --------------------------------------------------------------------- rules
def test_guid_free_inference_agrees_with_sysmon_guids():
    """The benchmark's claim in miniature: host|pid|image rules reproduce GUID lineage."""
    events = load_otrf(OTRF)
    start_by_guid = {e.attributes["object_guid"]: e.event_id for e in events
                     if e.source_artifact == "sysmon" and e.event_type == EventType.PROCESS_START
                     and e.attributes.get("object_guid")}
    truth = {e.event_id: start_by_guid[e.attributes["actor_guid"]] for e in events
             if e.source_artifact == "sysmon" and e.event_type != EventType.PROCESS_STOP
             and e.attributes.get("actor_guid") in start_by_guid
             and start_by_guid[e.attributes["actor_guid"]] != e.event_id}
    assert len(truth) >= 10
    g = _graph(events, use_guids=False)
    pred = {(e.src_event_id, e.dst_event_id) for e in g.edges if e.rule_name.startswith("process_")}
    correct = sum((src, dst) in pred for dst, src in truth.items())
    assert correct / len(truth) >= 0.9


def test_pid_reuse_guard_refuses_dead_parent():
    a = ev(0, EventType.PROCESS_START, "process:1:C:/w/explorer.exe", "process:500:C:/tools/a.exe")
    stop = ev(10, EventType.PROCESS_STOP, "process:500:C:/tools/a.exe", "process:500:C:/tools/a.exe")
    child = ev(20, EventType.PROCESS_START, "process:500:C:/tools/a.exe", "process:600:C:/w/cmd.exe")
    g = _graph([a, stop, child], use_guids=False)
    assert not any(e.dst_event_id == child.event_id and e.rule_name == "process_spawn" for e in g.edges)


def test_nearest_cause_wins_over_older_same_key():
    old = ev(0, EventType.PROCESS_START, "process:1:C:/w/explorer.exe", "process:500:C:/tools/a.exe")
    new = ev(100, EventType.PROCESS_START, "process:1:C:/w/explorer.exe", "process:500:C:/tools/a.exe")
    w = ev(110, EventType.FILE_WRITE, "process:500:C:/tools/a.exe", "file:C:/x.txt")
    g = _graph([old, new, w], use_guids=False)
    srcs = [e.src_event_id for e in g.edges if e.dst_event_id == w.event_id]
    assert srcs == [new.event_id]


def test_image_fallback_when_pid_missing():
    s = ev(0, EventType.PROCESS_START, "process:1:C:/w/svchost.exe", "process:?:C:/o/SDXHelper.exe",
           image="C:/o/SDXHelper.exe")
    r = ev(1, EventType.REGISTRY_SET, "process:?:C:/o/sdxhelper.exe", "registry:HKCU/x")
    g = _graph([s, r], use_guids=False)
    rules = {e.rule_name for e in g.edges if e.dst_event_id == r.event_id}
    assert rules == {"process_image_fallback_registry_set"}


def test_dropped_file_executed_and_logon_session():
    logon = ev(0, EventType.LOGON, "user:alice", "host:ws1", source="security", logon_id="0x3e1a2", user="alice")
    p = ev(5, EventType.PROCESS_START, "process:1:C:/w/explorer.exe", "process:10:C:/u/drop.exe",
           image="C:/u/drop.exe", logon_id="0x3e1a2")
    w = ev(10, EventType.FILE_WRITE, "process:10:C:/u/drop.exe", "file:C:/u/stage2.exe")
    x = ev(20, EventType.PROCESS_START, "process:77:C:/w/unknown.exe", "process:11:C:/u/stage2.exe",
           image="C:/u/stage2.exe")
    g = _graph([logon, p, w, x])
    rules = {(e.src_event_id, e.dst_event_id): e.rule_name for e in g.edges}
    assert rules[(w.event_id, x.event_id)] == "dropped_file_executed"
    assert rules[(logon.event_id, p.event_id)] == "logon_session"


# -------------------------------------------------------------------- fusion
def test_fusion_links_sysmon_and_4688():
    y = ev(0, EventType.PROCESS_START, "process:1:C:/w/cmd.exe", "process:4321:C:/w/reg.exe")
    s = ev(1, EventType.PROCESS_START, "process:1:C:/w/cmd.exe", "process:4321:C:\\W\\REG.EXE", source="security")
    g = ProvenanceGraph(backend="memory")
    g.add_events([y, s])
    assert fuse(g) == 1
    assert g.corroborations[y.event_id] == [s.event_id]  # Sysmon is primary
    assert s.event_id in g.shadowed and g.sources_for(y.event_id) == {"sysmon", "security"}


def test_fusion_respects_tolerance():
    y = ev(0, EventType.PROCESS_START, "process:1:a", "process:4321:C:/w/reg.exe")
    s = ev(30, EventType.PROCESS_START, "process:1:a", "process:4321:C:/w/reg.exe", source="security")
    g = ProvenanceGraph(backend="memory")
    g.add_events([y, s])
    assert fuse(g) == 0


def test_fusion_prefetch_execution_corroborates_start():
    events = load_plaso(FX / "plaso.jsonl")
    ps = ev(0, EventType.PROCESS_START, "process:1:C:/o/winword.exe",
            "process:4321:C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    ps = ps.model_copy(update={"timestamp": next(e.timestamp for e in events
                                                 if e.event_type == EventType.EXECUTION)})
    ps = finalize_event(ps.model_copy(update={"attributes": {"host": "lab-ws01"}}))
    g = ProvenanceGraph(backend="memory")
    g.add_events([*events, ps])
    fuse(g)
    assert "plaso" in g.sources_for(ps.event_id)


# -------------------------------------------------------------------- attack
def test_attack_heuristics_tag_known_patterns():
    enc = ev(0, EventType.PROCESS_START, "process:1:C:/o/WINWORD.EXE", "process:2:C:/w/powershell.exe",
             image="C:/w/powershell.exe", command_line="powershell -nop -w hidden -enc AAA",
             parent_image="C:/o/WINWORD.EXE")
    lsass = ev(1, EventType.PROCESS_ACCESS, "process:2:C:/w/powershell.exe", "process:600:C:/w/lsass.exe",
               target_image="C:\\Windows\\system32\\lsass.exe", granted_access="0x1010")
    benign = ev(2, EventType.PROCESS_START, "process:1:C:/w/services.exe", "process:3:C:/w/svchost.exe",
                image="C:/w/svchost.exe", command_line="svchost.exe -k netsvcs")
    tags = score_events([enc, lsass, benign])
    assert {"T1059.001", "T1059.003"} <= {t[0] for t in tags[enc.event_id].techniques}
    assert tags[lsass.event_id].techniques[0][0] == "T1003.001"
    assert tags[benign.event_id].techniques == []
    assert tags[enc.event_id].suspicion > tags[benign.event_id].suspicion


# ------------------------------------------------------------------- stories
def test_real_capture_top_story_is_the_psexec_attack():
    a = analyze_paths([OTRF])
    top = a.stories[0]
    assert {"T1569.002", "T1003.002"} <= set(top.techniques)
    root = a.graph.get_event(top.root_event_id)
    assert "PsExec" in root.object
    assert top.grade.value in ("HIGH", "CONFIRMED")
    assert top.omitted_events > 0  # routine registry noise was elided, and counted
    assert a.corroborations > 0 and a.ledger.verify()
    assert a.artefacts and len(a.artefacts[0]["sha256"]) == 64


def test_story_root_stops_at_system_process():
    svc = ev(0, EventType.PROCESS_START, "process:4:System", "process:700:C:/w/services.exe",
             image="C:/w/services.exe")
    evil = ev(1, EventType.PROCESS_START, "process:700:C:/w/services.exe", "process:800:C:/w/evil.exe",
              image="C:/w/evil.exe")
    child = ev(2, EventType.PROCESS_START, "process:800:C:/w/evil.exe", "process:900:C:/w/cmd.exe",
               image="C:/w/cmd.exe")
    g = _graph([svc, evil, child])
    assert "services.exe" in SYSTEM_ROOTS
    assert story_root(g, child.event_id) == evil.event_id


def test_log_clear_raises_suspicion_but_not_confidence_penalty():
    clear = ev(0, EventType.LOG_CLEARED, "user:eve", "log:security", source="security")
    a = analyze_events([clear])
    s = a.stories[0]
    assert "T1070.001" in s.techniques and s.tampering_flags
    assert story_breakdown(s, a.graph).penalty == 1.0


# ------------------------------------------------------------ anti-forensics
def test_sysmon_timestomp_backdating_is_high():
    e = ev(0, EventType.FILE_TIME_CHANGE, "process:1:a.exe", "file:C:/x.dll",
           creation_time="2019-01-01 00:00:00.000", previous_creation_time="2024-03-02 10:00:00.000")
    assert detect_sysmon_timestomp([e])[0].severity == "high"


def test_si_fn_mismatch_from_plaso():
    inds = detect_si_fn_mismatch(load_plaso(FX / "plaso.jsonl"))
    assert len(inds) == 1 and "payload.dll" in inds[0].detail


def test_audit_tamper_clock_and_record_order():
    reg = ev(0, EventType.REGISTRY_SET, "process:1:reg.exe",
             "registry:HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Start")
    cmd = ev(1, EventType.PROCESS_START, "process:1:cmd.exe", "process:2:wevtutil.exe",
             command_line="wevtutil cl Security")
    assert len(detect_audit_tamper([reg, cmd])) == 2
    tc = ev(2, EventType.TIME_CHANGE, "process:1:x", "clock",
            previous_time="2024-03-02 10:00:00", new_time="2024-03-01 10:00:00")
    assert detect_clock_change([tc])
    r1 = ev(100, EventType.LOGON, "user:a", "host:ws1", source="security", record_id="10", channel="security")
    r2 = ev(0, EventType.LOGON, "user:a", "host:ws1", source="security", record_id="11", channel="security")
    assert detect_record_order([r1, r2])
