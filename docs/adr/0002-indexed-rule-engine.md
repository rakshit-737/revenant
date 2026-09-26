# ADR 0002: Indexed, nearest-cause rule engine with a PID-reuse guard

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

v0.1 compared every ordered pair of events against every rule (O(n²)) and
linked an effect to **every** earlier cause whose `process:pid:image` string
matched exactly. On real Windows data this broke in three ways:

1. **Scale.** The APT29 day-1 capture has ~128k normalised events, and the pair
   loop's cost is quadratic (see `results/scale.json`).
2. **PID reuse.** Windows recycles PIDs within minutes, so "all earlier
   matches" means false parents.
3. **Spelling.** Sysmon writes `C:\Windows\Explorer.EXE` in one field and
   `C:\windows\explorer.exe` in another, and Security 4688 logs hex PIDs, so
   exact string equality missed most true links.

## Decision

- A rule declares cause types, effect types, a key function for each side and
  a window. The engine indexes causes by key (sorted timestamps) and uses
  `bisect` to pick the **nearest preceding** cause: one parent per rule, not all
  historical matches. Cost is O(n log n).
- Keys are `host|pid|image-basename` (ADR 0003), so spelling differences
  normalise away.
- `respect_termination`: a process-keyed rule refuses a cause whose process was
  seen exiting (Sysmon 5 / Security 4689) before the effect happened.
- Rule tiers, in order: GUID rules (Sysmon `ProcessGuid`, the strongest key),
  then PID rules (which skip effects already GUID-linked), then cross-entity
  rules (dropped file executed, logon session), then **fallbacks**, which fire
  only for effects that still have no cause. A fallback is either the logon
  session by user or the nearest same-image start when the export lost the PID.

## Consequences

- Benchmarks disable the GUID tier and use GUIDs as ground truth (ADR 0006).
- Fallback rules are lower-precision by design, and their calibrated
  confidence says so.
- One cause per rule is a modelling choice. A genuinely ambiguous effect gets
  the most recent candidate, not a probability distribution over candidates.
