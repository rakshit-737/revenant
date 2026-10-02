# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-02

Republishes the wheel, sdist and GHCR image with the calibration table (v1.0.0 lacked it).

### Added
- Linux auditd connector (execve/open/unlink/connect to events) and a CI job that captures a
  benign scripted sequence with auditd on the runner and asserts the reconstructed chain.
- OTRF compound captures (APT29 day 1/2, LSASS, Log4Shell) and an ATLAS downloader, every
  archive pinned by SHA-256 with fail-closed verification; Sentinel-format captures readable.
- Five-corpus B1 with ablations, equal-input baselines and CIs; equal-budget B2; B3 in Actions.
- ATLAS reproduction workflow: paper numbers recomputed from released outputs and the
  authors' `evaluate.py` re-run.
- Anti-forensics: PowerShell script-block/module logging disables are flagged.
- Generated docs demo on a real OTRF case; How it works, Evaluation and Reproduce pages.
- `revenant --version`, `--kind auditd`; package/docker/quickstart CI jobs, SHA-pinned actions.

### Changed
- Public functions and methods now carry docstrings; ruff `D102`/`D103` enforce this in CI.
- B1 corpora with fewer than 10 scorable captures report `n/a` instead of a degenerate
  cluster-bootstrap CI (`results/stats.json`, `results/RESULTS.md`).
- ATLAS row wording: event-level numbers are recomputed from released outputs, not reproduced
  by re-running the model. Scoring REVENANT on ATLAS/ATLASv2 is deferred; reasons are in the
  README Limitations.

### Fixed
- **Packaging:** the wheel, sdist and Docker image now ship `rule_calibration.json`; v1.0.0
  artefacts silently ran with hand-set edge confidences. A missing table now raises instead
  of falling back. The sdist carries the test fixtures; `setuptools>=77`.
- **Custody verification:** `revenant verify` opens the store read-only, never creates or
  repairs it, fails on a missing or empty ledger and on dropped append-only triggers, and
  accepts external anchors (`--expect-head`, `--expect-count`) that detect truncation. The
  ledger is written before the optional PDF.
- **Evidence confinement:** symlinks and NTFS junctions inside evidence are never followed
  (and are recorded in the ledger); API paths are validated lexically before any filesystem
  access (no UNC/SMB lookups); TrustedHost and Origin checks against DNS rebinding; 64 KiB
  body cap; `serve` refuses non-loopback addresses without `--allow-remote`.
- **Parser robustness:** an oversized CSV field or a deeply nested JSON line becomes one bad
  row instead of aborting the case.
- Office-spawned PowerShell is tagged T1059.001 (was T1059.003).
- CLI: `--kind auditd`, `--host`, `--version`, help for every option, one-line errors with
  the extra to install, exit 2 for missing inputs.

### Added
- **Linux auditd connector** and a **live-auditd CI job** that captures a benign scripted
  sequence on the runner and asserts its reconstruction (a consistency check).
- **More data:** OTRF APT29 day 2, the 7-capture LSASS-dump campaign and Log4Shell (Microsoft
  Sentinel exports are now parsed); the ATLAS release downloader. Every archive is pinned by
  SHA-256 and verification fails closed.
- **Evaluation:** equal-input baselines, an ablation grid, per-capture rows,
  capture-clustered bootstrap CIs, macro F1, Brier/AUROC, Wilson intervals and McNemar
  tests; `bench-extended` and `atlas-repro` workflows; ATLAS reproduction (`results/atlas_repro.json`).
- Docs: landing page, How it works, Evaluation and Reproduce pages; the demo is generated
  by `scripts/build_demo.py` and defaults to the real OTRF capture.
- CI: wheel/sdist/Docker smoke jobs, README Quickstart run verbatim, Python 3.14, strict
  bandit/pip-audit/gitleaks, SHA-pinned actions, least-privilege permissions, dependabot,
  issue/PR templates, CODEOWNERS, CITATION.cff.
- Anti-forensics: PowerShell script-block/module-logging disables are flagged.

### Changed (published numbers; several are worse)
- B1 baselines now see the same fused events as REVENANT, and the corpus runs on GitHub
  Actions with every capture readable: OTRF atomic F1 0.910 vs PID-nearest 0.822 (was 0.955
  vs 0.898 on the AV-reduced local corpus). The ablation shows the gain comes from the
  image-keyed fallback rules.
- B2 now gives every method the same reading budget: stories are slightly **worse** than a
  suspicion-sorted flat list (hit@1 0.28 vs 0.36, p = 0.06); the earlier "stories help"
  claim is withdrawn.
- Calibration fitted on APT29 and tested on atomic: ECE 0.106 (was 0.035); hand-set
  confidences were under-, not over-confident. Calibrated constants are capped at 0.99.
- B3: recall 0.60, precision 0.20 (was 0.50 / 0.17).

## [1.0.0] - 2026-09-26

First stable release. No engine behaviour changes from 0.2.0; this release adds the
documentation site, container image and release automation.

### Added
- **Documentation site** (MkDocs Material) published to GitHub Pages via
  `.github/workflows/docs.yml` (`mkdocs build --strict`): Home, Getting started,
  Architecture, Datasets, Benchmarks, CLI & API reference (mkdocstrings), Threat model,
  Security, ADRs, Changelog, Limitations/Roadmap.
- **Static, server-less demo** under `/demo/` — the timeline + causal-graph UI over
  pre-computed synthetic scenarios (no API needed).
- **`Dockerfile`** (slim, non-root, multi-stage) and a **release workflow**
  (`.github/workflows/release.yml`): on a `v*` tag it builds the wheel/sdist, pushes the
  image to `ghcr.io/rakshit-737/revenant`, and creates a GitHub Release with notes from
  this changelog and the distributions attached.

### Changed
- `pyproject` uses the SPDX `license = "MIT"` form.

## [0.2.0] - 2026-09-26

Moves the project from synthetic scenarios to real public DFIR data.

### Added
- **Real-artefact connectors** (`revenant.parsers`): OTRF/Mordor JSON lines,
  raw `.evtx` (python-evtx + defusedxml), plaso `json_line` and `l2tcsv`,
  Volatility 3 JSON (`pslist`/`pstree`/`netscan`/`cmdline`), Linux auth.log.
  Covers 21 Sysmon and 23 Security/System/PowerShell event ids, NTFS
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
