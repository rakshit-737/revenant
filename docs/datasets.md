# Datasets

All data is public and downloaded by `scripts/download_data.py` into
`$REVENANT_DATA` (default `../../datasets/revenant`, outside the repository).
Every file is pinned to a commit and verified against `data/manifest.json`
(SHA-256 + size). Nothing from these corpora is committed here except two small test fixtures
(a field-trimmed OTRF capture, MIT, and a 26-line ATLAS excerpt, Apache-2.0; attribution below).

| Corpus | What | Size used | Licence | Citation |
| --- | --- | --- | --- | --- |
| OTRF Security-Datasets: atomic Windows host captures | ~120 single-technique captures (Sysmon, Security, System, PowerShell) as JSON lines, with ATT&CK metadata YAML | 121 archives ≤ 8 MB compressed (~2 GB extracted) | MIT | Rodriguez, R. and Rodriguez, J., *Security Datasets*, Open Threat Research Forge, https://github.com/OTRF/Security-Datasets (commit `d9d40ef`) |
| OTRF APT29 ATT&CK Evaluations, day 1 (manual) | Multi-host emulation of APT29 (MITRE ATT&CK Evaluations round 2) | 1 archive, ~128k normalised events | MIT | same repository, `datasets/compound/apt29/day1` |
| OTRF compound: APT29 day 2, LSASS-dump campaign (7), Log4Shell | Opt-in (`--only otrf-apt29-day2 otrf-lsass otrf-log4shell`); host logs only, no memory dumps or pcaps | 43 MB + 21 MB + 38 KB compressed (~64 MB); day 2 is 1.7 GB of JSON (run it on a runner) | MIT | same repository, `datasets/compound/` |
| ATLAS release | Raw Windows security / DNS / Firefox logs and the authors' experiment outputs for 10 attacks (`scripts/download_atlas.py`) | 21 files, ~0.85 GB | Apache-2.0 | Alsaheel et al., *ATLAS: A Sequence-based Learning Approach for Attack Investigation*, USENIX Security 2021, https://github.com/purseclab/ATLAS (commit `e46096d`) |
| EVTX-ATTACK-SAMPLES | ~280 raw `.evtx` files, each recording one technique | 1 archive (commit zip) | GPL-3.0 (used only as input data; nothing redistributed) | Bousseaden, S., https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (commit `4ceed2f`) |

The default download is about 86 MB compressed. The corpus benchmarks run on GitHub
Actions (`bench-extended`), which also recovers the captures antivirus blocks locally: on
the runner the atomic corpus is 120 unique captures (one capture is published under two
tactics and is counted once), of which 102 contain effects with GUID ground truth; 107 carry
ATT&CK labels for B2.

## Practical notes

- **Endpoint antivirus.** Several captures contain attack-tool strings (e.g.
  Mimikatz command lines inside log text). On the author's machine Windows
  Defender blocked 2 archives and the JSON of 18 Empire captures, which silently shrank the
  local atomic corpus; the published numbers therefore come from the runner. REVENANT treats
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
(`scripts/make_fixtures.py`). `tests/fixtures/atlas_s2_excerpt.txt` is 26 unmodified
lines of the ATLAS release's S2 test log (`paper_experiments/S2.zip`,
`output/testing_preprocessed_logs_S2-CVE-2015-3105_windows`; Apache-2.0, © the ATLAS
authors), kept with their ground-truth suffixes so a test can prove REVENANT strips them.
All other fixtures are hand-written and synthetic.
