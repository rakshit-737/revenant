# ADR 0001: Deterministic rules, not ML, produce causal claims

- Status: accepted (v0.1, reaffirmed v0.2)
- Date: 2026-09-26

## Context

A forensic report is tested adversarially. Each causal sentence ("PsExec
spawned `reg.exe`, which saved the SECURITY hive") has to be explained to a
non-technical fact-finder and survive cross-examination. A learned model that
outputs edges would be hard to explain and hard to reproduce, and an expert
would struggle to defend it.

## Decision

- Every causal edge is produced by a **named, deterministic rule** with
  explicit entity keys and a time window (`CausalEdge.rule_name`).
- ML-flavoured signals are limited to *ranking what to look at first*:
  ATT&CK heuristics and per-case rarity (`attack.py`). They never create or
  remove an edge.
- LLMs are out of scope for claims. If one is ever added, it may only draft
  prose over facts that have already been derived, and every sentence must cite
  an event id.

## Consequences

- Rule accuracy can be measured against ground truth (Sysmon GUIDs, see
  ADR 0006) and every error can be traced to one rule.
- Recall is capped by what the rules express. Edges that need semantic
  inference (e.g. "this DLL was loaded because of that registry change") are
  not produced.
- Rule confidences started hand-set. In v0.2 they are calibrated on data
  (ADR 0006), which keeps the explainability and makes the numbers honest.
