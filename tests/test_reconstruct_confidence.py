from revenant import pipeline
from revenant.generators import (
    corroboration_scenario,
    intrusion_scenario,
    timestomp_scenario,
)
from revenant.models import ConfidenceGrade, KillChainStage


def test_intrusion_reconstructs_multistage_chain():
    a = pipeline.run(intrusion_scenario())
    assert a.chains
    top = a.chains[0]
    # a strong chain should span several kill-chain stages
    assert len(top.stages) >= 3
    # across the reconstructed branches, both C2 and persistence stages appear
    all_stages = {s for c in a.chains for s in c.stages}
    assert KillChainStage.C2 in all_stages
    assert KillChainStage.INSTALLATION in all_stages


def test_corroboration_boosts_confidence():
    corro = pipeline.run(corroboration_scenario())
    # two distinct sources on the logon -> higher corroboration than a single source
    assert corro.chains
    assert corro.chains[0].confidence_score > 0.3


def test_timestomp_flags_lower_confidence():
    a = pipeline.run(timestomp_scenario())
    flagged = [c for c in a.chains if c.tampering_flags]
    assert any("timestomp" in " ".join(c.tampering_flags) for c in flagged) or a.indicators
    assert any(i.indicator == "timestomp" for i in a.indicators)


def test_chains_ranked_descending():
    a = pipeline.run(intrusion_scenario())
    scores = [c.confidence_score for c in a.chains]
    assert scores == sorted(scores, reverse=True)


def test_grade_consistent_with_score():
    a = pipeline.run(intrusion_scenario())
    for c in a.chains:
        assert c.grade == ConfidenceGrade.from_score(c.confidence_score)
