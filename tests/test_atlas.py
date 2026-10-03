"""ATLAS preprocessed-log connector, entity mapping and symptom-seeded stories.

The fixture is 26 lines of ATLAS's released S2 test log
(purseclab/ATLAS, Apache-2.0), labels included, so the tests can prove the
ground-truth suffix never reaches REVENANT.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from revenant.models import Event, EventType
from revenant.parsers import detect_kind, load_path
from revenant.parsers.atlas import (
    entity_labels,
    iter_records,
    load_atlas,
    local_addresses,
    records_to_events,
    seed_events,
    split_record,
    strip_label,
    to_datetime,
)
from revenant.pipeline import analyze_events
from revenant.stories import StoryConfig, seeded_story

FIX = Path(__file__).parent / "fixtures" / "atlas_s2_excerpt.txt"
LABEL = re.compile(r"-L[A-Z][+-]")


def _flip(line: str) -> str:
    return re.sub(r"-L([A-Z])([+-])$", lambda m: f"-L{m.group(1)}{'-' if m.group(2) == '+' else '+'}", line)


def test_strip_label_and_fields():
    line = "22323694,,,2064,516,c:/users/aalsahee/payload.exe,,,,,,,,,,,,,,-LA+\n"
    assert strip_label(line).endswith(",")
    r = split_record(line)
    assert r is not None and r["pid"] == "2064" and r["ppid"] == "516"
    assert r["image"] == "c:/users/aalsahee/payload.exe" and r["direction"] == ""
    assert split_record("") is None and split_record("not,a,record") is None


def test_time_has_no_year_but_keeps_order_and_gaps():
    assert to_datetime("86400") == datetime(2018, 1, 1, tzinfo=timezone.utc)
    assert (to_datetime("22323695") - to_datetime("22323694")).total_seconds() == 1


def test_labels_never_reach_events():
    events = load_atlas(FIX, host="s2")
    assert events
    for e in events:
        text = " ".join([e.actor, e.object, *e.attributes.values()])
        assert not LABEL.search(text), text
    # flipping every ground-truth label changes nothing REVENANT sees
    lines = FIX.read_text(encoding="utf-8").splitlines()
    flipped = records_to_events(list(iter_records(_flip(x) for x in lines)), host="s2")
    assert [e.event_id for e in flipped] == [e.event_id for e in events]


def test_mapping_of_record_kinds():
    events = load_atlas(FIX, host="s2")
    types = {e.event_type for e in events}
    assert {EventType.DNS_QUERY, EventType.WEB_VISIT, EventType.NETWORK_CONNECT, EventType.FILE_WRITE,
            EventType.FILE_READ, EventType.PROCESS_START} <= types
    dns = [e for e in events if e.event_type == EventType.DNS_QUERY and e.attributes.get("resolved_ip")]
    assert dns and dns[0].attributes["domain"] == "0xalsaheel.com"
    conns = [e for e in events if e.event_type == EventType.NETWORK_CONNECT and "payload" in e.actor]
    assert conns and all(e.attributes["remote_ip"] == "192.168.223.3" for e in conns)
    # one start per (pid, image basename): the \\device\\ spelling of payload.exe is not a new process
    starts = [e for e in events if e.event_type == EventType.PROCESS_START and "payload.exe" in e.object]
    assert len(starts) == 1


def test_local_address_is_the_busiest_endpoint():
    recs = list(iter_records(FIX.read_text(encoding="utf-8").splitlines()))
    assert local_addresses(recs) == {"192.168.223.128"}


def test_kind_detection_and_dispatch():
    assert detect_kind(FIX) == "atlas"
    events = load_path(FIX, host="s2")
    assert len(events) == len(load_atlas(FIX, host="s2"))


def _ev(et, actor, obj, **attrs):
    return Event(event_id="e", timestamp=datetime(2018, 1, 1, tzinfo=timezone.utc), event_type=et, actor=actor,
                 action="x", object=obj, source_artifact="atlas_security", attributes=attrs)


@pytest.mark.parametrize(("event", "expected"), [
    # a process start names the started process only, never its parent
    (_ev(EventType.PROCESS_START, "process:516:c:/windows/system32/services.exe", "process:2064:c:/users/a/payload.exe"),
     {"payload.exe"}),
    # spaces: ATLAS graph words drop them, log lines keep them
    (_ev(EventType.FILE_WRITE, "process:3236:c:/program files/mozilla firefox/plugin-container.exe",
         "file:c:/users/a/my secret.docx"),
     {"plugin-container.exe", "my secret.docx", "mysecret.docx"}),
    # only the remote end of a connection, never the host's own or a broadcast address
    (_ev(EventType.NETWORK_CONNECT, "process:0:", "ip:192.168.223.3:8080", remote_ip="192.168.223.3"),
     {"192.168.223.3"}),
    (_ev(EventType.NETWORK_CONNECT, "process:4:system", "ip:255.255.255.255:137", remote_ip="255.255.255.255"),
     set()),
    (_ev(EventType.DNS_QUERY, "network:dns", "dns:0xalsaheel.com", domain="0xalsaheel.com",
         resolved_ip="192.168.223.3"), {"0xalsaheel.com", "192.168.223.3"}),
    (_ev(EventType.WEB_VISIT, "browser:firefox", "url:0xalsaheel.com:9999/ripleeszw/x.swf"), {"0xalsaheel.com"}),
    # strings under 4 characters would match nearly every ATLAS line
    (_ev(EventType.FILE_READ, "process:1:a.b", "file:c:/x"), set()),
])
def test_entity_labels(event, expected):
    assert entity_labels(event, {"192.168.223.128"}) == expected


def test_symptom_seeded_story_reaches_the_payload():
    events = load_atlas(FIX, host="s2")
    a = analyze_events(events, chains=False)
    local = {"192.168.223.128"}
    seeds, aliases = seed_events(a.graph.events, "0xalsaheel.com", local)
    assert aliases == ["192.168.223.3"]
    assert len(seeds) >= 5
    rules = {e.rule_name for e in a.graph.edges}
    assert {"dns_resolved_connect", "dropped_file_executed"} <= rules
    story = seeded_story(a.graph, seeds, a.indicators, StoryConfig(), a.tags)
    assert story is not None
    labels = set().union(*(entity_labels(a.graph.get_event(i), local) for i in story.event_ids))
    assert {"0xalsaheel.com", "192.168.223.3", "payload.exe"} <= labels
    assert seeded_story(a.graph, ["ev-unknown"]) is None
