# Reproduce

Everything here uses public data and pinned versions. The corpus-scale benchmarks are
designed to run on a GitHub Actions `ubuntu-24.04` runner (4 vCPU, 16 GB): no endpoint
antivirus interferes there and the 1.7 GB APT29 day-2 JSON fits in memory.

## Environment

- Python 3.10-3.14 (CI tests all five; benchmarks were run on 3.12).
- `pip install -e ".[bench,evtx]"` for benchmarks, `".[dev,evtx,api]"` for tests,
  `".[docs]"` for this site.
- RAM: about 3 GB for OTRF atomic locally; APT29 day 2 needs a runner.

## 1. Tests and the committed fixture (2 minutes, no download)

```bash
python -m pytest -q
revenant analyze tests/fixtures/otrf_psexec_lsa_secrets.jsonl --top 1
```

Expected: all tests pass (real-data tests skip without data) and the report's first story
is `story-a65f65fb66 - suspicion 0.87, confidence CONFIRMED (0.86)`.

## 2. Data

```bash
python scripts/download_data.py                       # OTRF atomic + metadata, APT29 day 1, EVTX samples: ~100 MB compressed
python scripts/download_data.py --only otrf-lsass --only otrf-log4shell --only otrf-apt29-day2   # opt-in, 66 MB compressed
python scripts/download_atlas.py                      # ATLAS release, ~0.85 GB (better on a runner)
```

Every archive is verified against `data/manifest.json` / `data/atlas_manifest.json`
(SHA-256, plus the git blob SHA-1 of the pinned upstream commit). Unpinned entries are
refused unless `--pin` is passed; mismatching files are deleted.

## 3. Corpus benchmarks

On GitHub: **Actions → bench-extended → Run workflow**. It downloads the data, refuses any
file that starts with an `MZ` header, runs B1 (five corpora, ablations), B2 and B3 and
uploads the JSON. Locally:

```bash
cd benchmarks
python bench_edges.py --extra          # B1 + calibration + ablations
python bench_stories.py                # B2
python bench_antiforensics.py          # B3 (python-evtx is slow on Windows)
python bench_scale.py                  # B4
python make_figures.py                 # results/*.png, RESULTS.md, stats.json
```

| Step | Runner time (last run) | Key lines to expect |
|---|---|---|
| B1, main corpora (atomic, APT29 day 1, LSASS, Log4Shell) | ~2 min | `otrf_atomic 498123 events 142175 evaluable` · `revenant P=0.910 R=0.910 F1=0.910` · `pid_nearest_fused P=0.942 R=0.729 F1=0.822` · `revenant_no_fallback ... F1=0.826` |
| B1, APT29 day 2 | ~2 min | `otrf_apt29_day2 380790 events 166252 evaluable` · all methods except v0.1 at F1 1.000 |
| B2 | ~25 s | 107 captures · REVENANT hit@1 0.280, flat 0.364, McNemar p 0.0636 |
| B3 | ~2 min | REVENANT TP 6 FP 24 FN 4; baseline TP 3 FP 23 FN 7 |
| Calibration | (inside B1) | `fit_otrf_apt29_day1_test_otrf_atomic ECE 0.1055` |

B4 is a single laptop run (108 s analysis of pre-parsed APT29 day 1); expect different
absolute times on other hardware, and a rule-engine log-log slope near 1.

To compare with the committed numbers, run `make_figures.py` and `git diff results/`.

## 4. ATLAS reproduction

On GitHub: **Actions → atlas-repro → Run workflow** (about 10 minutes plus the optional
`evaluate.py` re-runs). Expected:

```text
entity macro (recomputed): {'precision': 0.9106, 'recall': 0.9729, 'f1': 0.9376} paper: {... identical ...}
entity micro (recomputed): {'precision': 0.904, 'recall': 0.9715, 'f1': 0.9365}
evaluate.py re-run on released outputs: {'n_attacks': 10, 'entity_macro': {... 'f1': 0.9132}, 'event_macro': {... 'f1': 0.9988}}
```

The `evaluate.py` step takes about 20 minutes (one Python 3.7 container per experiment,
no network).

## 5. Live auditd capture

Runs in CI (`live-auditd` job). It needs root and auditd, so it is meant for an ephemeral
runner only: `bash ci/live/capture_auditd.sh live-out && python ci/live/check_live.py live-out`.
