from revenant.generators import intrusion_scenario
from revenant.graph import ProvenanceGraph
from revenant.normalize import normalize_batch
from revenant.rules import RuleEngine


def _graph_from(records):
    events = normalize_batch(records)
    g = ProvenanceGraph()
    g.add_events(events)
    RuleEngine().infer(g)
    return g


def test_graph_add_edge_requires_known_nodes():
    import pytest

    from revenant.models import CausalEdge
    g = ProvenanceGraph()
    with pytest.raises(KeyError):
        g.add_edge(CausalEdge(src_event_id="a", dst_event_id="b", relation="x",
                              rule_name="r", time_delta_s=1.0))


def test_rules_infer_spawn_and_actions():
    g = _graph_from(intrusion_scenario())
    relations = {e.relation for e in g.edges}
    assert "spawned" in relations
    assert "wrote" in relations
    assert "connected" in relations
    assert "persisted" in relations


def test_roots_have_no_incoming():
    g = _graph_from(intrusion_scenario())
    incoming = {e.dst_event_id for e in g.edges}
    for r in g.roots():
        assert r not in incoming


def test_memory_backend_matches_edges():
    events = normalize_batch(intrusion_scenario())
    g = ProvenanceGraph(backend="memory")
    g.add_events(events)
    RuleEngine().infer(g)
    assert g.backend == "memory"
    assert len(g.edges) > 0
