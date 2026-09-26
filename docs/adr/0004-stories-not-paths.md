# ADR 0004: Incident stories (causal subtrees), not enumerated paths

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

v0.1 enumerated every simple root-to-leaf path and scored each one. That is
exponential in fan-out: `explorer.exe` on a real workstation has thousands of
descendants. It also produced hundreds of near-duplicate "chains", which is
not how an examiner writes up an incident.

## Decision

1. Each event receives a **suspicion** score from transparent ATT&CK
   heuristics plus per-case parent→child rarity (`attack.py`).
2. Events with suspicion ≥ 0.45 are *seeds*. Each seed walks up its strongest
   incoming edge to the top-most ancestor that is **not** part of the OS
   skeleton (`services.exe`, `svchost.exe`, `explorer.exe`, ...). That ancestor
   is the *story root*, typically the attacker's first foothold process.
3. Seeds that share a root merge into one **story**: the root's causal subtree,
   explored best-first by suspicion and capped at 200 events. Benign leaf
   actions (routine registry writes and similar) are omitted from the
   narrative but **counted** (`omitted_events`).
4. Stories carry two separate numbers:
   - **suspicion**: what it looks like (noisy-OR of the top event suspicions
     plus tactic breadth);
   - **confidence**: how well the evidence supports the causal links
     (reliability, corroboration, temporal fit, calibrated edge strength,
     tamper penalty).

   Ranking uses `suspicion × (0.5 + 0.5 × confidence)`.
5. Only evidence-undermining indicators (timestomp, SI/FN mismatch, hash
   mismatch, clock change, record-order anomalies) lower confidence. A cleared
   log is a *finding*: it raises suspicion (T1070.001) but does not make the
   surviving events less reliable.

The v0.1 path view is still produced for small graphs (≤ 2,000 events), so the
original API and tests keep working.

## Consequences

- Story reconstruction is linear in graph size, and APT29 day 1 is analysed
  in seconds.
- Stories depend on the heuristic vocabulary to seed. A technique with no
  heuristic produces no story. `results/stories.json` reports vocabulary
  coverage explicitly.
- The OS-skeleton list is a judgement call. A process-injection attack whose
  whole chain lives inside `svchost.exe` becomes a story rooted at the injected
  event rather than at a foothold.
