# REVENANT

**Forensic timeline reconstruction for DFIR.** REVENANT reads real Windows and Linux
artefacts (Sysmon, Security, PowerShell, raw `.evtx`, plaso, Volatility 3, `auth.log`),
joins them into a temporal provenance graph, and outputs ranked **incident stories**
graded by confidence. Every claim cites the SHA-256 of the event that supports it, and the
stories are recorded in an append-only custody ledger.

!!! warning "Lab-only and defensive"
    REVENANT reads evidence and never changes it. It contains no offensive code. All
    benchmark data is public (see [Datasets](datasets.md)).

## Why

`plaso`/`log2timeline` produces a super-timeline with millions of undifferentiated rows, and
an analyst still has to build the story by hand. REVENANT turns events into nodes and adds
typed causal edges ("process spawned process", "process wrote file", "logon → session",
"dropped file executed"). Each edge comes from a named, deterministic rule with entity and
time constraints. The graph is then cut into **incident stories**, and each story gets two
separate scores:

- **suspicion** — how attack-like it is, from ATT&CK heuristics and per-case rarity;
- **confidence** — how well the evidence supports it, from source reliability, cross-artefact
  corroboration, temporal fit and calibrated rule precision. Tampering indicators reduce it.

The report ends with a **"What remains uncertain"** section that lists time windows with no
artefact coverage and event types that were not interpreted — so gaps are not quietly filled.

## Highlights

- Real-artefact connectors: OTRF/Mordor JSON, raw `.evtx`, plaso `json_line`/`l2tcsv`,
  Volatility 3 JSON, Linux `auth.log`.
- Indexed causal rule engine (near-linear scaling; see [Benchmarks](benchmarks.md)).
- Corroboration-based, cross-corpus-calibrated confidence (ECE 0.035 / 0.013).
- Anti-forensics indicators: timestomp, `$SI`/`$FN` mismatch, log clearing, audit-policy
  tampering, clock jumps.
- Court-style report (Markdown / HTML / PDF) with cited hashes and an uncertainty section.
- Append-only SQLite custody ledger with offline hash-chain verification.

## Quick links

- [Getting started](getting-started.md)
- [Architecture](architecture.md)
- [Benchmarks & results](benchmarks.md)
- [CLI & API reference](reference.md)
- [Live demo](demo/index.html)
