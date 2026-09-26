"""Causal-edge rule engine.

Rules infer typed edges between events under *temporal* and *entity*
constraints. This is deliberately rule-based, not ML: courts distrust black
boxes, so every edge names the rule that produced it (see CausalEdge.rule_name).

A rule matches an ordered (src, dst) pair where ``dst`` happens at/after
``src`` within ``max_window_s`` and the entity linkage holds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .graph import ProvenanceGraph
from .models import CausalEdge, Event, EventType


@dataclass
class Rule:
    name: str
    relation: str
    max_window_s: float
    # returns True if src causally links to dst
    predicate: Callable[[Event, Event], bool]
    base_confidence: float = 0.6


def _proc_identity(ev: Event) -> str:
    """The process identity an event refers to via its actor."""
    return ev.actor


def _proc_object(ev: Event) -> str:
    """The process identity an event produced via its object."""
    return ev.object


# --- individual predicates ------------------------------------------------- #
def _spawn(src: Event, dst: Event) -> bool:
    # parent PROCESS_START whose child (object) is the actor of a later start
    return (
        src.event_type == EventType.PROCESS_START
        and dst.event_type == EventType.PROCESS_START
        and _proc_object(src) == dst.actor
    )


def _process_did(action_type: EventType) -> Callable[[Event, Event], bool]:
    def pred(src: Event, dst: Event) -> bool:
        return (
            src.event_type == EventType.PROCESS_START
            and dst.event_type == action_type
            and _proc_object(src) == dst.actor
        )

    return pred


def _logon_session(src: Event, dst: Event) -> bool:
    if src.event_type != EventType.LOGON or dst.event_type != EventType.PROCESS_START:
        return False
    user = src.attributes.get("user")
    return bool(user) and dst.attributes.get("User", dst.attributes.get("user")) == user


DEFAULT_RULES: list[Rule] = [
    Rule("process_spawn", "spawned", 3600, _spawn, 0.8),
    Rule("process_file_write", "wrote", 1800, _process_did(EventType.FILE_WRITE), 0.75),
    Rule("process_net_connect", "connected", 1800, _process_did(EventType.NETWORK_CONNECT), 0.7),
    Rule("process_registry_set", "persisted", 1800, _process_did(EventType.REGISTRY_SET), 0.75),
    Rule("process_dns_query", "resolved", 1800, _process_did(EventType.DNS_QUERY), 0.65),
    Rule("logon_session", "session_of", 7200, _logon_session, 0.6),
]


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else list(DEFAULT_RULES)

    def infer(self, graph: ProvenanceGraph) -> list[CausalEdge]:
        """Infer and add causal edges to ``graph``. Returns the new edges."""
        events = graph.events  # sorted by time
        new_edges: list[CausalEdge] = []
        for i, src in enumerate(events):
            for dst in events[i + 1 :]:
                delta = (dst.timestamp - src.timestamp).total_seconds()
                if delta < 0:
                    continue
                for rule in self.rules:
                    if delta > rule.max_window_s:
                        continue
                    if rule.predicate(src, dst):
                        # temporal tightness sharpens confidence
                        tightness = 1.0 - min(delta / rule.max_window_s, 1.0)
                        conf = round(
                            rule.base_confidence * (0.7 + 0.3 * tightness), 4
                        )
                        edge = CausalEdge(
                            src_event_id=src.event_id,
                            dst_event_id=dst.event_id,
                            relation=rule.relation,
                            rule_name=rule.name,
                            time_delta_s=delta,
                            confidence=conf,
                        )
                        new_edges.append(edge)
                        graph.add_edge(edge)
        return new_edges
