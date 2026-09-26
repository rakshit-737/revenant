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
| B3 anti-forensics | EVTX-ATTACK-SAMPLES file names (the author names each file after the technique), with the positive regex fixed before running. | Some "negative" files contain real 1102 events because the author cleared logs before recording. |
| B4 scale | none (timing) | Single machine, and other workloads were running concurrently. |

Baselines are chosen to isolate one contribution each:

- **v0.1 exact-ref join**: the previous version of this project.
- **PID-nearest**: what an analyst gets by filtering a flat timeline by
  host+PID. Isolates the value of image keys, the termination guard and
  fallbacks.
- **flat suspicion-sorted timeline**: the same heuristics with no graph.
  Isolates the value of grouping into stories.
- **chronological super-timeline**: plaso/psort, read top to bottom.
- **1102/104 query**: the standard SIEM anti-forensics rule.

## Consequences

- All numbers are reproducible from public data with `scripts/download_data.py`
  and the `benchmarks/` scripts. No private data and no hand labels.
- No published numbers exist for these exact tasks on these corpora, so
  comparisons are against baselines, not against prior papers.
