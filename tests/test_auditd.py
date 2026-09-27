from pathlib import Path

from revenant.models import EventType
from revenant.parsers import detect_kind, load_path
from revenant.parsers.auditd import _sockaddr, parse_line
from revenant.pipeline import analyze_paths

FIX = Path(__file__).parent / "fixtures" / "auditd_sample.log"


def test_detect_and_map():
    assert detect_kind(FIX) == "auditd"
    evs = load_path(FIX)
    types = [e.event_type for e in evs]
    assert types.count(EventType.PROCESS_START) == 4
    assert EventType.NETWORK_CONNECT in types and EventType.FILE_DELETE in types
    fetch = next(e for e in evs if e.attributes.get("image") == "/tmp/rv/fetcher")
    assert fetch.actor == "process:2000:/usr/bin/bash"  # parent image recovered from earlier execve
    assert "http://127.0.0.1:8765/data.txt" in fetch.attributes["command_line"]  # hex argv decoded
    loot = next(e for e in evs if e.object == "file:/tmp/rv/loot.txt" and e.event_type == EventType.FILE_WRITE)
    assert loot.actor.endswith("/tmp/rv/fetcher")  # relative path joined with CWD


def test_failed_and_non_inet_calls_skipped():
    assert all(e.attributes.get("pid") != "500" for e in load_path(FIX))
    assert _sockaddr("01002F72756E") is None
    assert _sockaddr("0200223D7F0000010000000000000000") == ("127.0.0.1", 8765)
    assert parse_line("garbage") is None


def test_end_to_end_edges():
    a = analyze_paths([FIX])
    rules = {e.rule_name for e in a.graph.edges}
    assert {"process_spawn", "dropped_file_executed", "process_net_connect"} <= rules
    assert a.stories and a.stories[0].techniques
