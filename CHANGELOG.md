# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-26

Moves the project from synthetic scenarios to real public DFIR data.

### Added
- **Real-artefact connectors** (`revenant.parsers`): OTRF/Mordor JSON lines,
  raw `.evtx` (python-evtx + defusedxml), plaso `json_line` and `l2tcsv`,
  Volatility 3 JSON (`pslist`/`pstree`/`netscan`/`cmdline`), Linux auth.log.
  Coverage covers 20 Sysmon and 23 Security/System/PowerShell event ids, NTFS
  `$SI`/`$FN`, prefetch/amcache and browser history. Unmapped records and
  unreadable files are counted and reported.
- **Per-capture clock-offset estimation** for collector-local time fields
  (ADR 0007).
- **Cross-artefact fusion**: Sysmon 1 ↔ Security 4688, Sysmon 5 ↔ 4689,
  logons, network connections, memory `pslist`, prefetch execution.
  Corroboration feeds confidence.
- **Indexed rule engine** (O(n log n)): nearest-cause selection, host/PID/image
  keys, PID-reuse guard, GUID tier, dropped-file-executed, logon-session and
  image-only fallback rules (ADR 0002).
- **Rule calibration**: per-rule precision fitted on OTRF atomic against Sysmon
  GUID ground truth and shipped as `revenant/data/rule_calibration.json`.
- **ATT&CK tagging**: 55 transparent heuristics plus per-case rarity, combined
  into event suspicion.
- **Incident stories** replacing path enumeration on real data, with separate
  suspicion and confidence, omitted-event accounting and "unknown" windows
  (ADR 0004).
- **Anti-forensics**: Sysmon EID 2 timestomp (back-dating flagged high), plaso
  `$SI`/`$FN` mismatch, 1102/104 log clearing, audit-policy and logging
  registry/command tampering, 4616 clock jumps, record-number vs time order.
- **Court-style report**: scope with artefact SHA-256s, method, findings with
  cited hashes, tampering, "What remains uncertain", custody head hash. Output
  as Markdown, HTML, or PDF (optional WeasyPrint).
- **Append-only SQLite custody store** with UPDATE/DELETE triggers and offline
  hash-chain verification (ADR 0005).
- **Exports**: JSON, Cypher script, optional live Neo4j push.
- **FastAPI service and single-page UI** (vis-timeline + vis-network, SRI-pinned),
  confined to an evidence root.
- **CLI**: `analyze` on real artefacts, `--format md|html|json|cypher`,
  `--ledger`, `--pdf`, `verify` on SQLite stores, `serve`.
- **Benchmarks** on OTRF atomic, OTRF APT29 day 1 and EVTX-ATTACK-SAMPLES,
  with a checksum-pinned downloader, results JSON and figures (ADR 0006).
- Tests for parsers, engine, API, custody and CLI on a real OTRF fixture, plus
  `realdata`-marked tests against the full corpora.

### Changed
- `pipeline.run()` keeps the v0.1 API but now runs fusion, ATT&CK scoring and
  stories as well as the path view.
- Event types extended (logon failures, process access, remote threads, WMI,
  services, tasks, script blocks, log clearing, audit and time changes,
  execution, web visits).

### Fixed
- Non-Sysmon rows were timed by Logstash ingest time (`@timestamp`, lagging up
  to 45 s), which broke fusion. `EventTime` is now preferred.
- ISO timestamps with an offset but no fractional seconds (Volatility 3 JSON)
  failed to parse.
- macOS `__MACOSX/._*` resource forks inside OTRF archives were read as bad rows.
- `record_order` compared event times. Sysmon reports network connections
  late, so benign captures raised clock-rollback alerts. It now compares
  channel write times (`logged_at`).
- The downloader tolerates AV-quarantined captures and persists first-seen hashes.

## [0.1.0] - 2026-06

- Initial MVP on synthetic scenarios: normalizer, hash-chained custody
  ledger, networkx provenance graph, pairwise causal rules, path-chain
  reconstruction, confidence scoring, demonstrative anti-forensics, Markdown
  report, CLI, CI.
