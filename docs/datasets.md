# Datasets

All data is public and downloaded by `scripts/download_data.py` into
`$REVENANT_DATA` (default `../../datasets/revenant`, outside the repository).
Every file is pinned to a commit and verified against `data/manifest.json`
(SHA-256 + size). Nothing from these corpora is committed here except one
field-trimmed OTRF capture used as a test fixture (MIT, attribution below).

| Corpus | What | Size used | Licence | Citation |
| --- | --- | --- | --- | --- |
| OTRF Security-Datasets: atomic Windows host captures | ~120 single-technique captures (Sysmon, Security, System, PowerShell) as JSON lines, with ATT&CK metadata YAML | 121 archives ≤ 8 MB compressed (~2 GB extracted) | MIT | Rodriguez, R. and Rodriguez, J., *Security Datasets*, Open Threat Research Forge, https://github.com/OTRF/Security-Datasets (commit `d9d40ef`) |
| OTRF APT29 ATT&CK Evaluations, day 1 (manual) | Multi-host emulation of APT29 (MITRE ATT&CK Evaluations round 2) | 1 archive, ~128k normalised events | MIT | same repository, `datasets/compound/apt29/day1` |
| EVTX-ATTACK-SAMPLES | ~280 raw `.evtx` files, each recording one technique | 1 archive (commit zip) | GPL-3.0 (used only as input data; nothing redistributed) | Bousseaden, S., https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (commit `4ceed2f`) |

Total download is well under 1 GB compressed.

## Practical notes

- **Endpoint antivirus.** Several captures contain attack-tool strings (e.g.
  Mimikatz command lines inside log text). On the author's machine Windows
  Defender blocked 2 archives and a few extracted JSON files. REVENANT treats
  these as *unreadable artefacts*: the downloader lists them, the loader counts
  them (`LoadStats.unreadable_files`), and the report states that their contents
  are absent. Do **not** disable AV to work around this. The files are logs, not
  binaries, and the analysis stays valid on what is readable.
- **macOS archive junk.** Some OTRF archives contain `__MACOSX/._*.json`
  resource forks. The loader skips them.
- **Clock fields.** See ADR 0007. The collector-local offset is estimated per
  capture and reported.
- **Parsed-event cache.** Benchmarks cache parsed events as pickles under
  `$REVENANT_DATA/.cache`, keyed by a hash of the parser sources. It is safe to
  delete.

## Test fixture attribution

`tests/fixtures/otrf_psexec_lsa_secrets.jsonl` is derived from OTRF
Security-Datasets `cmd_psexec_lsa_secrets_dump` (MIT licence, © Open Threat
Research Forge), with fields not read by REVENANT removed
(`scripts/make_fixtures.py`). All other fixtures are hand-written and synthetic.
