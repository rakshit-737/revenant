# REVENANT

**Forensic timeline reconstruction for DFIR: causal incident stories from Windows and Linux
artefacts, every claim graded and cited by the SHA-256 of its evidence.**

**Contribution:** REVENANT builds a causal provenance graph from forensic artefacts that lack
process GUIDs using named, deterministic rules whose per-rule confidences are fitted against
Sysmon-GUID lineage hidden at inference, and attaches the rule, its confidence and the hash of
the supporting event to every claim it reports.

[Open the live demo](demo/index.html){ .md-button .md-button--primary }
[Try it in 60 seconds](getting-started.md#try-it-in-60-seconds){ .md-button }
[Evaluation](evaluation.md){ .md-button }

[![REVENANT demo: the real OTRF PsExec capture as a ranked story with timeline, causal graph and evidence hashes](img/demo.png)](demo/index.html)

!!! note "What the evidence shows"
    With GUIDs hidden, REVENANT's causal edges beat a PID-nearest analyst baseline on OTRF
    atomic but are at parity with a careful PID-then-image heuristic; calibration lowers the
    error of its edge confidences without improving their ranking; its stories do not speed up
    triage; and under the ATLAS protocol it scores far below ATLAS's hand-cleaned output. What it
    adds is explainability and custody, not accuracy. The table below is generated from the
    committed result files; each row names the workflow run behind it.

## Headline results

--8<-- "results/headline.md"

ATLAS rows: each multi-host attack is scored from its h2 folder, where the authors' procedure puts both hosts' outputs (its event totals equal the paper's); `M4_h1`'s release has no cleaned predictions, so `evaluate.py` stops there with an error. Event-level paper figures come from Table 4 (Avg row, p. 3016) and Table 5 (p. 3017), not the abstract.

!!! warning "Lab-only and defensive"
    REVENANT reads evidence and never changes it. It contains no offensive code. All
    benchmark data is public (see [Datasets](datasets.md)).

## What it does

`plaso`/`log2timeline` produces a super-timeline with millions of undifferentiated rows, and
an analyst still has to build the story by hand. REVENANT reads real Windows and Linux
artefacts (Sysmon, Security, PowerShell, raw `.evtx`, plaso, Volatility 3, `auth.log`,
auditd, and ATLAS's preprocessed logs), turns events into nodes and adds typed causal edges
("process spawned process", "process wrote file", "logon → session", "dropped file executed").
Each edge comes from a named, deterministic rule with entity and time constraints. The graph is
then cut into **incident stories**, each with two separate scores:

- **suspicion**: how attack-like it is, from ATT&CK heuristics and per-case rarity;
- **confidence**: how well the evidence supports it, from source reliability, cross-artefact
  corroboration, temporal fit and calibrated per-rule edge precision. Tampering reduces it.

The report ends with a **"What remains uncertain"** section listing time windows with no
artefact coverage and event types that were not interpreted, so gaps are not quietly filled.
Every report records an append-only custody ledger whose head hash can be verified later.

## Where next

- [How it works](how-it-works.md): one real capture followed through every stage.
- [Evaluation](evaluation.md): methodology, every result with confidence intervals.
- [ATLAS protocol mapping](atlas-mapping.md): how REVENANT is scored under ATLAS's own harness.
- [Reproduce](reproduce.md): exact commands, expected outputs and runtimes.
- [Getting started](getting-started.md) and the [CLI & API reference](reference.md).
- [Limitations & roadmap](limitations.md).
