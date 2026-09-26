"""Causal-edge rule engine (indexed, PID-reuse aware).

Rules infer typed edges between events under *temporal* and *entity*
constraints. This is deliberately rule-based, not ML: courts distrust black
boxes, so every edge names the rule that produced it (``CausalEdge.rule_name``).

A rule declares which event types can be a cause (``src_types``) and an
effect (``dst_types``) and how to derive an entity key for each side. For
every effect the engine picks the **nearest preceding** cause with the same
key inside ``max_window_s`` -- one parent, not every historical match. Two
refinements matter on real Windows data (see docs/adr/0002-indexed-rule-engine.md):

* **PID reuse.** Windows recycles PIDs quickly. Keys include host and image
  basename, and a process-keyed rule refuses a cause whose process was seen
  terminating (Sysmon 5 / Security 4689) before the effect happened.
* **Complexity.** v0.1 compared every pair of events (O(n^2)); the index makes
  inference O(n log n), which is what lets it run on full captures.

When Sysmon process GUIDs are present they are the strongest possible entity
key; ``RuleEngine(use_guids=True)`` (the pipeline default) links on them first
and only falls back to host|pid|image for events without GUIDs (Security 4688,
plaso, memory). Benchmarks disable GUIDs and use them as ground truth.
"""

from __future__ import annotations

import bisect
import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from .entities import (
    actor_process_key,
    event_host,
    image_key,
    norm_path,
    norm_pid,
    norm_user,
    object_process_key,
    split_process_ref,
)
from .graph import ProvenanceGraph
from .models import CausalEdge, Event, EventType

KeyFn = Callable[[Event], str | None]

HALF_LIFE_S = 600.0  # temporal tightness: an effect 10 min after its cause scores 0.5


@dataclass
class Rule:
    name: str
    relation: str
    max_window_s: float
    src_types: frozenset[EventType]
    dst_types: frozenset[EventType]
    src_key: KeyFn
    dst_key: KeyFn
    base_confidence: float = 0.6
    fallback: bool = False  # only fire if the effect has no incoming edge yet
    respect_termination: bool = False  # process keys: dead processes cause nothing
    skip_if_guid_linked: bool = False  # defer to a GUID rule when one fired
    tags: set[str] = field(default_factory=set)


# --------------------------------------------------------------------------- #
# key functions
# --------------------------------------------------------------------------- #
def _obj_guid(ev: Event) -> str | None:
    g = ev.attributes.get("object_guid")
    return f"guid:{g}" if g else None


def _act_guid(ev: Event) -> str | None:
    g = ev.attributes.get("actor_guid")
    return f"guid:{g}" if g else None


def _pid_only_actor(ev: Event) -> str | None:
    parts = split_process_ref(ev.actor)
    if not parts or not parts[0]:
        return None
    return f"{event_host(ev)}|{parts[0]}"


def _pid_only_object(ev: Event) -> str | None:
    parts = split_process_ref(ev.object)
    if not parts or not parts[0]:
        return None
    return f"{event_host(ev)}|{parts[0]}"


def _file_written(ev: Event) -> str | None:
    if not ev.object.startswith("file:"):
        return None
    return f"{event_host(ev)}|{norm_path(ev.object[5:])}"


def _image_started(ev: Event) -> str | None:
    img = ev.attributes.get("image") or ev.attributes.get("Image")
    if not img:
        parts = split_process_ref(ev.object)
        img = parts[1] if parts else ""
    return f"{event_host(ev)}|{norm_path(img)}" if img else None


def _actor_image(ev: Event) -> str | None:
    parts = split_process_ref(ev.actor)
    img = parts[1] if parts else ""
    return f"{event_host(ev)}|{norm_path(img)}" if img else None


def _logon_id_src(ev: Event) -> str | None:
    lid = ev.attributes.get("logon_id")
    return f"{event_host(ev)}|{lid}" if lid and lid not in ("0x0", "0x3e7", "0x3e4", "0x3e5") else None


def _logon_id_dst(ev: Event) -> str | None:
    return _logon_id_src(ev)


def _user_src(ev: Event) -> str | None:
    u = norm_user(ev.attributes.get("user"))
    return f"user:{u}" if u else None


def _user_dst(ev: Event) -> str | None:
    u = norm_user(ev.attributes.get("user") or ev.attributes.get("User"))
    return f"user:{u}" if u else None


_T = EventType
_PS = frozenset({_T.PROCESS_START})
PROCESS_ACTIONS: dict[str, tuple[str, frozenset[EventType], float]] = {
    # rule suffix: (relation, effect types, base confidence)
    "file_write": ("wrote", frozenset({_T.FILE_WRITE}), 0.75),
    "file_other": ("touched", frozenset({_T.FILE_READ, _T.FILE_DELETE, _T.FILE_TIME_CHANGE}), 0.7),
    "net_connect": ("connected", frozenset({_T.NETWORK_CONNECT}), 0.7),
    "registry_set": ("persisted", frozenset({_T.REGISTRY_SET}), 0.75),
    "dns_query": ("resolved", frozenset({_T.DNS_QUERY}), 0.65),
    "process_access": ("accessed", frozenset({_T.PROCESS_ACCESS, _T.REMOTE_THREAD}), 0.7),
    "pipe": ("piped", frozenset({_T.PIPE}), 0.6),
}

DAY = 86400.0
HOUR = 3600.0


def guid_rules() -> list[Rule]:
    out = [Rule("guid_process_spawn", "spawned", 30 * DAY, _PS, _PS, _obj_guid, _act_guid, 0.97, tags={"guid"})]
    for suffix, (rel, types, _) in PROCESS_ACTIONS.items():
        out.append(Rule(f"guid_process_{suffix}", rel, 30 * DAY, _PS, types, _obj_guid, _act_guid, 0.95,
                        tags={"guid"}))
    return out


def pid_rules() -> list[Rule]:
    out = [
        Rule("process_spawn", "spawned", DAY, _PS, _PS, object_process_key, actor_process_key, 0.8,
             respect_termination=True, skip_if_guid_linked=True),
    ]
    for suffix, (rel, types, conf) in PROCESS_ACTIONS.items():
        out.append(Rule(f"process_{suffix}", rel, DAY, _PS, types, object_process_key, actor_process_key, conf,
                        respect_termination=True, skip_if_guid_linked=True))
    out.append(Rule("process_script_block", "ran_script", DAY, _PS, frozenset({_T.SCRIPT_BLOCK}),
                    _pid_only_object, _pid_only_actor, 0.55, respect_termination=False))
    # Some exports lose the PID entirely (NXLog drops Sysmon ``ProcessId`` on a
    # share of rows). As a *fallback only* -- the effect has no cause yet --
    # link to the nearest earlier start of the same image on the same host.
    out.append(Rule("process_image_fallback_spawn", "spawned", HOUR, _PS, _PS,
                    _image_started, _actor_image, 0.5, fallback=True))
    for suffix, (rel, types, _conf) in PROCESS_ACTIONS.items():
        out.append(Rule(f"process_image_fallback_{suffix}", rel, HOUR, _PS, types,
                        _image_started, _actor_image, 0.5, fallback=True))
    return out


def cross_entity_rules() -> list[Rule]:
    return [
        # a file written earlier is later executed as a process image (dropper -> payload)
        Rule("dropped_file_executed", "executed", 7 * DAY, frozenset({_T.FILE_WRITE}), _PS,
             _file_written, _image_started, 0.7),
        # a process with no known parent is attributed to the logon session it ran in
        Rule("logon_session", "session_of", DAY, frozenset({_T.LOGON}), _PS,
             _logon_id_src, _logon_id_dst, 0.75, fallback=True),
        Rule("logon_session_user", "session_of", 8 * 3600, frozenset({_T.LOGON}), _PS,
             _user_src, _user_dst, 0.5, fallback=True),
    ]


def default_rules(use_guids: bool = True) -> list[Rule]:
    return (guid_rules() if use_guids else []) + pid_rules() + cross_entity_rules()


# kept for backwards compatibility with v0.1 imports
DEFAULT_RULES: list[Rule] = default_rules(use_guids=True)


def edge_confidence(base: float, delta_s: float) -> float:
    tightness = math.exp(-max(delta_s, 0.0) * math.log(2) / HALF_LIFE_S)
    return round(base * (0.7 + 0.3 * tightness), 4)


def load_calibration() -> dict[str, float]:
    """Per-rule empirical precision measured on OTRF atomic captures.

    Produced by ``benchmarks/bench_edges.py --write-calibration`` (Laplace-
    smoothed accuracy of each rule against Sysmon-GUID ground truth) and
    evaluated on the held-out APT29 capture. Rules without enough evidence
    keep their hand-set, time-decayed confidence.
    """
    import json
    from importlib import resources

    try:
        raw = resources.files("revenant.data").joinpath("rule_calibration.json").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):  # pragma: no cover - packaging edge case
        return {}
    return {k: float(v["confidence"]) for k, v in json.loads(raw)["rules"].items()}


class RuleEngine:
    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        use_guids: bool = True,
        calibration: dict[str, float] | None | str = "default",
    ) -> None:
        self.rules = rules if rules is not None else default_rules(use_guids)
        self.calibration = load_calibration() if calibration == "default" else (calibration or {})

    def confidence(self, rule: Rule, delta_s: float) -> float:
        cal = self.calibration.get(rule.name)
        return round(cal, 4) if cal is not None else edge_confidence(rule.base_confidence, delta_s)

    @staticmethod
    def _termination_index(events: list[Event]) -> dict[str, list[float]]:
        stops: dict[str, list[float]] = defaultdict(list)
        for e in events:
            if e.event_type == EventType.PROCESS_STOP:
                k = actor_process_key(e)
                if k:
                    stops[k].append(e.timestamp.timestamp())
        for v in stops.values():
            v.sort()
        return stops

    def infer(self, graph: ProvenanceGraph) -> list[CausalEdge]:
        """Infer and add causal edges to ``graph``. Returns the new edges."""
        events = [e for e in graph.events if e.event_id not in graph.shadowed]
        stops = self._termination_index(events)
        guid_linked: set[str] = set()
        existing = {(e.src_event_id, e.dst_event_id) for e in graph.edges}
        new_edges: list[CausalEdge] = []
        ordered = [r for r in self.rules if not r.fallback] + [r for r in self.rules if r.fallback]

        for rule in ordered:
            index: dict[str, tuple[list[float], list[Event]]] = {}
            for e in events:
                if e.event_type in rule.src_types:
                    k = rule.src_key(e)
                    if k:
                        ts_list, ev_list = index.setdefault(k, ([], []))
                        ts_list.append(e.timestamp.timestamp())
                        ev_list.append(e)
            if not index:
                continue
            for dst in events:
                if dst.event_type not in rule.dst_types:
                    continue
                if rule.fallback and graph.has_incoming(dst.event_id):
                    continue
                if rule.skip_if_guid_linked and dst.event_id in guid_linked:
                    continue
                k = rule.dst_key(dst)
                if not k or k not in index:
                    continue
                ts_list, ev_list = index[k]
                t_dst = dst.timestamp.timestamp()
                i = bisect.bisect_right(ts_list, t_dst) - 1
                while i >= 0 and ev_list[i].event_id == dst.event_id:
                    i -= 1
                if i < 0:
                    continue
                src = ev_list[i]
                delta = t_dst - ts_list[i]
                if delta > rule.max_window_s:
                    continue
                if rule.respect_termination:
                    s = stops.get(k)
                    if s:
                        j = bisect.bisect_right(s, ts_list[i])
                        if j < len(s) and s[j] < t_dst:
                            continue  # cause had already exited: PID reused
                if (src.event_id, dst.event_id) in existing:
                    continue
                edge = CausalEdge(
                    src_event_id=src.event_id,
                    dst_event_id=dst.event_id,
                    relation=rule.relation,
                    rule_name=rule.name,
                    time_delta_s=max(delta, 0.0),
                    confidence=self.confidence(rule, delta),
                )
                existing.add((src.event_id, dst.event_id))
                graph.add_edge(edge)
                new_edges.append(edge)
                if "guid" in rule.tags:
                    guid_linked.add(dst.event_id)
        return new_edges


__all__ = [
    "DEFAULT_RULES",
    "HALF_LIFE_S",
    "PROCESS_ACTIONS",
    "Rule",
    "RuleEngine",
    "default_rules",
    "edge_confidence",
    "guid_rules",
    "load_calibration",
    "image_key",
    "norm_pid",
    "pid_rules",
]
