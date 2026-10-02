# ADR 0007: Timestamp normalisation across collectors

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

OTRF captures are exported through NXLog and Logstash, so each row carries
several clocks:

- Sysmon `UtcTime`: authoritative UTC, set by the Sysmon driver.
- `EventTime` / `TimeCreated`: when Windows wrote the record, in the
  **collector's local time**, sometimes with a misleading `Z` suffix, and
  whole seconds only.
- `@timestamp`: when **Logstash ingested** the row, which lags real time on the
  APT29 capture (we observed lags of up to tens of seconds during development;
  that run's log was not kept, so treat the figure as anecdotal).

The first v0.2 benchmark run preferred `@timestamp` for non-Sysmon rows. Security
4688 records then landed after their Sysmon twins, fusion failed to merge them,
and the orphaned 4688 became the "nearest cause" of later events, which visibly
depressed APT29 edge F1 (the exact figure from that development run was not
committed and is not reported here).

## Decision

- Sysmon rows use `UtcTime`.
- Other rows use the first of `TimeCreated`, `EventTime`, `@timestamp`
  (ingest time is the last resort), shifted by a **per-field offset**
  estimated as the median of `field - UtcTime` over Sysmon rows and snapped to
  15 minutes (time-zone granularity).
- auth.log carries no year or zone, so both are explicit parameters, never
  guesses. `.evtx` `SystemTime` is already UTC.
- Clock *manipulation* is a separate question, handled by anti-forensics
  (4616 jumps, record-number order vs time order).

## Consequences

- After the fix, APT29 edge F1 is 1.000 (see `results/edges.json`).
- The offsets used are reported in every analysis (`load_stats.clock_offsets_s`).
- Captures without any Sysmon rows cannot be offset-corrected automatically.
  Their times are taken as UTC, which the report states under "What remains
  uncertain".
