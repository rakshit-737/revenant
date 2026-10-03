# ADR 0006: Benchmark methodology (ground truth without hand labels)

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

The spec's research question asks whether rule-based causal inference with
corroboration-based confidence can reconstruct incidents accurately and with
calibrated confidence. Public DFIR corpora rarely ship event-level causal
labels, and hand-labelling thousands of edges is not feasible solo.

## Decision

Use ground truth that already exists in public data, and state each
benchmark's blind spot.

| Benchmark | Ground truth | Blind spot |
| --- | --- | --- |
| B1 causal edges | Sysmon `ProcessGuid`/`ParentProcessGuid`: unique per process instance, so the GUID parent *is* the true cause. REVENANT runs with GUIDs hidden. | Measures process lineage and process→action edges only, not cross-entity edges (dropped-file-executed, logon session). |
| Calibration | The same GUID truth. Per-rule precision is fitted on one corpus and ECE is measured on the other (atomic ↔ APT29). | Calibration is per rule, not per context. |
| B2 story ranking | ATT&CK technique ids from OTRF metadata YAML, written by the dataset authors. | "Found" means an event tagged with the technique by REVENANT's own heuristics, so B2 measures *ranking and grouping*, not detector quality. Every method shares the detector. |
| B3 anti-forensics | EVTX-ATTACK-SAMPLES file names (the author names each file after the technique), with the positive regex fixed before running. | Some "negative" files contain real 1102 events because the author cleared logs before recording; only 10 positives. |
| B3b anti-forensics | OTRF metadata entries mapped to T1562.002 by the dataset authors (6 entries, 17 host captures); negatives map to neither T1562 nor T1070. | The captures were in the development corpus; pre-recording 1102/104 clears and benign Sysmon EID 2 events inflate false positives, so indicator kinds are reported separately. |
| B4 scale | none (timing) | One runner type (GitHub-hosted ubuntu-24.04); 5 end-to-end and 3 per-point repetitions. |
| B5 live auditd | the scripted benign sequence | Truth from auditd pid/ppid is close to what the parser reads: a consistency check, not accuracy. |
| C ATLAS | the authors' released counts, outputs and model | Recomputes ATLAS's numbers, re-runs `model.h5` (TF 2.3) and diffs it against the release; the paper's figures also need a manual cleaning step the release does not script. |
| C2 REVENANT under ATLAS | ATLAS's malicious-entity labels, scored by the authors' `evaluate.py` | Substring matching over-generalises (see docs/atlas-mapping.md); ATLAS's released predictions are hand-cleaned, REVENANT's are not. |

Baselines are chosen to isolate one contribution each:

- **v0.1-style exact-ref join**: a reconstruction of the previous version's idea (one 1 h
  window for every effect type), not the v0.1 engine itself.
- **PID-then-image-nearest**: PID-nearest, plus the nearest earlier start of the same image
  when an effect has no PID. A careful analyst's heuristic, and REVENANT's fallback idea without
  its keys, PID-reuse guard or fusion: it bounds what the engine adds beyond that idea.
- **PID-nearest**: what an analyst gets by filtering a flat timeline by
  host+PID. Since round 4 it runs on the **same fused, de-duplicated events** as REVENANT
  (`*_fused`); on raw events most of its false positives were links to the Security 4688
  twin of the right process, which inflated REVENANT's margin.
- **Ablations** remove one REVENANT component at a time (image in the key, termination
  guard, image-only fallback rules, fusion) to isolate each contribution.
- **flat suspicion-sorted timeline**: the same heuristics with no graph.
  Isolates the value of grouping into stories. Every method gets the same event budget.
- **chronological super-timeline**: plaso/psort, read top to bottom.
- **1102/104 query**: the standard SIEM anti-forensics rule.
- **Sigma-equivalent**: 1102/104, Sysmon EID 2, logging-disable registry keys and 4719, i.e.
  what standard Sigma/Hayabusa rules read.
- **BackTracker-style reachability** (C2): every causal ancestor and descendant of the symptom
  events, unpruned; and **symptom only**.

## Consequences

- All numbers are reproducible from public data with `scripts/download_data.py`
  and the `benchmarks/` scripts. No private data and no hand labels.
- Uncertainty: B1 uses capture-clustered bootstrap CIs (10,000 resamples, seed 7; effects
  inside one capture are correlated) and reports macro F1 beside the micro average, with
  paired capture-level tests (exact sign, Wilcoxon) for every comparison; calibration metrics
  are bootstrapped over captures; B2/B3/B3b use Wilson intervals and exact McNemar tests; B5
  uses Clopper-Pearson; C2 bootstraps over the 10 attacks.
- Provenance: every result file records the workflow run and commit that produced it.
- No published numbers exist for these exact tasks on these corpora, so
  comparisons are against baselines, not against prior papers.
