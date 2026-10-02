# REVENANT

**Contribution:** REVENANT recovers *which process caused what* in forensic artefacts that lack
process GUIDs, using named, deterministic causal rules whose per-rule confidences are
calibrated against Sysmon-GUID lineage hidden at inference and tested on held-out corpora;
every narrative claim carries that confidence plus the SHA-256 of its evidence.

[Open the live demo](demo/index.html){ .md-button .md-button--primary }
[Try it in 60 seconds](getting-started.md#try-it-in-60-seconds){ .md-button }
[Evaluation](evaluation.md){ .md-button }

[![REVENANT demo: the real OTRF PsExec capture as a ranked story with timeline, causal graph and evidence hashes](img/demo.png)](demo/index.html)

<div class="grid cards" markdown>

-   **0.910 vs 0.822**

    ---

    Causal-edge F1 with GUIDs hidden on 120 OTRF atomic captures (142k effects), REVENANT vs
    a PID-nearest baseline on the same input. 95% CIs 0.80-0.98 vs 0.54-0.96.

-   **Ablation**

    ---

    Without its image-keyed fallback rules REVENANT scores 0.826: that component carries the
    gain. Four further corpora are easy for every method (F1 about 1.0).

-   **ECE 0.233 → 0.106**

    ---

    Edge-confidence calibration, fitted on APT29 and tested on atomic. Story grades remain
    uncalibrated, hand-set heuristics.

-   **ATLAS reproduced**

    ---

    ATLAS's event-level F1 0.9988 reproduced exactly by re-running the authors' evaluation
    on their released outputs; entity-level 0.913 vs the paper's 0.938.

</div>

!!! warning "Lab-only and defensive"
    REVENANT reads evidence and never changes it. It contains no offensive code. All
    benchmark data is public (see [Datasets](datasets.md)).

!!! note "An honest negative result"
    Under equal reading budgets, REVENANT's stories do **not** reach the labelled ATT&CK
    technique faster than a suspicion-sorted flat list (hit@1 0.28 vs 0.36, p = 0.06). Stories
    add grouping, per-hop explanation and confidence, not faster triage. See
    [Evaluation](evaluation.md).

## What it does

`plaso`/`log2timeline` produces a super-timeline with millions of undifferentiated rows, and
an analyst still has to build the story by hand. REVENANT reads real Windows and Linux
artefacts (Sysmon, Security, PowerShell, raw `.evtx`, plaso, Volatility 3, `auth.log`,
auditd), turns events into nodes and adds typed causal edges ("process spawned process",
"process wrote file", "logon → session", "dropped file executed"). Each edge comes from a
named, deterministic rule with entity and time constraints. The graph is then cut into
**incident stories**, each with two separate scores:

- **suspicion**: how attack-like it is, from ATT&CK heuristics and per-case rarity;
- **confidence**: how well the evidence supports it, from source reliability, cross-artefact
  corroboration, temporal fit and calibrated per-rule edge precision. Tampering reduces it.

The report ends with a **"What remains uncertain"** section listing time windows with no
artefact coverage and event types that were not interpreted, so gaps are not quietly filled.
Every report records an append-only custody ledger whose head hash can be verified later.

## Where next

- [How it works](how-it-works.md): one real capture followed through every stage.
- [Evaluation](evaluation.md): methodology, every result with confidence intervals.
- [Reproduce](reproduce.md): exact commands, expected outputs and runtimes.
- [Getting started](getting-started.md) and the [CLI & API reference](reference.md).
